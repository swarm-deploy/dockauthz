// Package authz implements Docker's request and response authorization callbacks.
package authz

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/identity"
	"github.com/swarm-deploy/dockauthz/internal/operation"
	"github.com/swarm-deploy/dockauthz/internal/policy"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

type client struct {
	name        string
	permissions map[string]map[string]config.Permission
}
type Plugin struct {
	unidentified string
	clients      map[string]client
	token        *dockerapi.Token
	policy       *policy.Evaluator
	observer     *telemetry.Observer
	logger       *slog.Logger
}

var _ authorization.Plugin = (*Plugin)(nil)

// New validates the administrative policy before constructing the plugin.
func New(
	cfg *config.Config,
	token *dockerapi.Token,
	evaluator *policy.Evaluator,
	observer *telemetry.Observer,
	logger *slog.Logger,
) (*Plugin, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Plugin{
		unidentified: cfg.Authentication.Unidentified,
		clients:      make(map[string]client),
		token:        token,
		policy:       evaluator,
		observer:     observer,
		logger:       logger,
	}
	for name, c := range cfg.Clients {
		p.clients[c.Identity.Certificate.CommonName] = client{name: name, permissions: c.Permissions}
	}
	return p, nil
}

// AuthZReq is the official helper interface; the HTTP adapter supplies context
// through Authorize when the daemon's outer request has trace headers.
func (p *Plugin) AuthZReq(req authorization.Request) authorization.Response {
	return p.Authorize(context.Background(), req)
}

// AuthZRes deliberately permits responses without reevaluating mutated state.
func (p *Plugin) AuthZRes(authorization.Request) authorization.Response {
	return authorization.Response{Allow: true}
}

// Authorize evaluates only authenticated Docker request data, never OTel baggage.
func (p *Plugin) Authorize(ctx context.Context, req authorization.Request) authorization.Response {
	// Docker commonly carries the original trace context in RequestHeaders.
	// The outer AuthZ HTTP context, when present, takes precedence.
	if !hasSpanContext(ctx) {
		headers := make(http.Header)
		for k, v := range req.RequestHeaders {
			headers.Add(k, v)
		}
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(headers))
	}
	start := time.Now()
	ctx, span := p.observer.Start(ctx, "dockauthz.authorize")
	defer span.End()
	name, cn, method := "unknown", "", "unknown"
	op := operation.Operation{Resource: operation.ResourceUnknown, Action: operation.ActionUnknown}
	result := policy.Result{Reason: "authorization denied"}
	internal := false
	defer func() {
		// Early grants still receive normalized audit/metric dimensions when
		// possible. Resolution here cannot change the already made decision.
		if op.Resource == operation.ResourceUnknown {
			if resolved, err := operation.Resolve(req.RequestMethod, req.RequestURI); err == nil {
				op = resolved
			}
		}
		decision := "deny"
		if result.Allow {
			decision = "allow"
		}
		span.SetAttributes(
			attribute.String("dockauthz.client", name),
			attribute.String("dockauthz.identity.auth_method", method),
			attribute.String("dockauthz.resource", string(op.Resource)),
			attribute.String("dockauthz.action", string(op.Action)),
			attribute.String("dockauthz.decision", decision),
			attribute.String("dockauthz.reason", result.Reason),
		)
		p.observer.Decision(ctx, decision, name, string(op.Resource), string(op.Action), start)
		if result.ErrorType != "" {
			p.observer.Error(ctx, result.ErrorType)
		}
		if internal {
			p.observer.Internal(ctx, decision)
		}
		p.logger.InfoContext(
			ctx,
			"authorization decision",
			"client", name,
			"identity", cn,
			"resource", op.Resource,
			"resource_id", op.ID,
			"action", op.Action,
			"decision", decision,
			"reason", result.Reason,
		)
	}()
	respond := func() authorization.Response { return authorization.Response{Allow: result.Allow, Msg: result.Reason} }
	if present, valid := p.token.Check(req.RequestHeaders); present {
		internal = true
		name = "internal"
		method = "internal"
		resolved, err := operation.Resolve(req.RequestMethod, req.RequestURI)
		if err == nil {
			op = resolved
		}
		if valid && err == nil && op.Action == operation.ActionInspect && len(op.Query) == 0 {
			result = policy.Result{Allow: true, Reason: "internal inspect"}
		} else {
			result = policy.Result{Reason: "invalid internal request", ErrorType: "internal"}
		}
		return respond()
	}
	var err error
	cn, err = identity.CommonName(req)
	if err != nil {
		result = policy.Result{Reason: err.Error(), ErrorType: "policy"}
		return respond()
	}
	if cn == "" {
		name = "unidentified"
		method = "none"
		result = policy.Result{Allow: p.unidentified == "allow", Reason: "unidentified policy"}
		return respond()
	}
	method = "TLS"
	c, found := p.clients[cn]
	if !found {
		result = policy.Result{Reason: "unknown authenticated client"}
		return respond()
	}
	name = c.name
	if permission, ok := c.permissions["*"]["*"]; ok && permission.Unconditional() {
		result = policy.Result{Allow: true, Reason: "full administrator"}
		return respond()
	}
	op, err = operation.Resolve(req.RequestMethod, req.RequestURI)
	if err != nil {
		op = operation.Operation{Resource: operation.ResourceUnknown, Action: operation.ActionUnknown}
		result = policy.Result{Reason: "unknown or invalid Docker operation", ErrorType: "resolver"}
		return respond()
	}
	var matching []config.Permission
	for _, resource := range []string{string(op.Resource), "*"} {
		for _, action := range []string{string(op.Action), "*"} {
			if permission, ok := c.permissions[resource][action]; ok {
				matching = append(matching, permission)
			}
		}
	}
	result = p.policy.Evaluate(ctx, matching, op, req.RequestBody, req.RequestHeaders)
	return respond()
}
