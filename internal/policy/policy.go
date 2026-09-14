// Package policy evaluates each permission as a complete, independent grant.
package policy

import (
	"context"
	"strconv"
	"strings"

	"github.com/moby/moby/api/types/swarm"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/mutation"
	"github.com/swarm-deploy/dockauthz/internal/operation"
	"github.com/swarm-deploy/dockauthz/internal/specjson"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
)

type Result struct {
	// Allow is true only if one complete permission succeeded.
	Allow bool
	// Reason is a constant or redacted diagnostic safe for audit logs.
	Reason string
	// ErrorType is a bounded telemetry error category, or empty.
	ErrorType string
}

type Evaluator struct {
	reader   dockerapi.Reader
	observer *telemetry.Observer
}

// New wires the required read-only state client and observer.
func New(reader dockerapi.Reader, observer *telemetry.Observer) *Evaluator {
	return &Evaluator{reader: reader, observer: observer}
}

// Evaluate never merges constraints from separate matching permissions.
func (e *Evaluator) Evaluate(ctx context.Context, permissions []config.Permission, op operation.Operation, body []byte, headers map[string]string) Result {
	ctx, span := e.observer.Start(ctx, "dockauthz.policy.evaluate")
	defer span.End()
	result := Result{Reason: "no matching permission"}
	for _, p := range permissions {
		result = e.permission(ctx, p, op, body, headers)
		if result.Allow {
			return result
		}
	}
	return result
}

func (e *Evaluator) permission(ctx context.Context, p config.Permission, op operation.Operation, body []byte, headers map[string]string) Result {
	if p.Unconditional() {
		return Result{Allow: true, Reason: "permission granted"}
	}
	if op.Resource == "service" && op.Action == "update" && !safeUpdate(op, p, headers) {
		return Result{Reason: "unsafe or unsupported service update options", ErrorType: "policy"}
	}
	var state dockerapi.Snapshot
	if p.Selector != nil || p.Mutation != nil {
		var err error
		state, err = e.reader.Inspect(ctx, op)
		if err != nil {
			return Result{Reason: "cannot inspect current Docker resource", ErrorType: "docker_lookup"}
		}
		// Names and abbreviated IDs can resolve to a different object between
		// authorization and execution. State-bound policies require full IDs.
		if state.ID != op.ID {
			return Result{Reason: "state constraints require a canonical resource ID", ErrorType: "policy"}
		}
		if op.Resource == "service" && op.Action == "update" {
			version, err := strconv.ParseUint(op.Query.Get("version"), 10, 64)
			if err != nil || version != state.Version {
				return Result{Reason: "service version does not match inspected state", ErrorType: "policy"}
			}
		}
	}
	if p.Selector != nil && !matches(state.Labels, p.Selector.Labels) {
		return Result{Reason: "existing resource labels do not match selector"}
	}
	if p.Request != nil {
		var labels map[string]string
		switch op.Resource {
		case "service":
			var spec swarm.ServiceSpec
			if err := specjson.Decode(body, &spec); err != nil {
				return Result{Reason: err.Error(), ErrorType: "policy"}
			}
			labels = spec.Labels
		case "secret":
			var spec swarm.SecretSpec
			if err := specjson.Decode(body, &spec); err != nil {
				return Result{Reason: err.Error(), ErrorType: "policy"}
			}
			labels = spec.Labels
		default:
			return Result{Reason: "unsupported request constraint", ErrorType: "policy"}
		}
		if !matches(labels, p.Request.Labels) {
			return Result{Reason: "request labels do not match constraint"}
		}
	}
	if p.Mutation != nil {
		if state.ServiceSpec == nil {
			return Result{Reason: "missing current service spec", ErrorType: "mutation"}
		}
		_, span := e.observer.Start(ctx, "dockauthz.mutation.validate", attribute.StringSlice("dockauthz.mutation.allowed_fields", p.Mutation.Only))
		err := mutation.Validate(*state.ServiceSpec, body, p.Mutation.Only)
		span.End()
		if err != nil {
			return Result{Reason: err.Error(), ErrorType: "mutation"}
		}
	}
	return Result{Allow: true, Reason: "permission constraints satisfied"}
}

func matches(actual, required map[string]string) bool {
	for key, value := range required {
		got, ok := actual[key]
		if !ok || got != value {
			return false
		}
	}
	return true
}

func safeUpdate(op operation.Operation, p config.Permission, headers map[string]string) bool {
	versions := op.Query["version"]
	if len(versions) != 1 || versions[0] == "" {
		return false
	}
	for _, c := range versions[0] {
		if c < '0' || c > '9' {
			return false
		}
	}
	for key, values := range op.Query {
		if key == "version" {
			continue
		}
		if key != "registryAuthFrom" || len(values) != 1 || values[0] != "spec" {
			return false
		}
	}
	if p.Mutation != nil {
		imageAllowed := false
		for _, field := range p.Mutation.Only {
			if field == "container.image" {
				imageAllowed = true
			}
		}
		if !imageAllowed {
			for key := range headers {
				if strings.EqualFold(key, "X-Registry-Auth") {
					return false
				}
			}
		}
	}
	return true
}
