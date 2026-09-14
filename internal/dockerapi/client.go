// Package dockerapi provides bounded, recursion-safe Docker state inspection.
package dockerapi

//go:generate go run go.uber.org/mock/mockgen -source=client.go -destination=mocks.go -package=dockerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/moby/moby/api/types/swarm"
	"github.com/swarm-deploy/dockauthz/internal/operation"
	"github.com/swarm-deploy/dockauthz/internal/specjson"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

const LookupTimeout = 5 * time.Second
const maxResponseSize = 8 << 20

const (
	maxIdleConns     = 16
	idleConnTimeout  = 30 * time.Second
	forbiddenRedirect = "docker redirects forbidden"
)

type Snapshot struct {
	// ID is the resolved, canonical Docker resource ID.
	ID string
	// Version is Docker's optimistic concurrency index.
	Version uint64
	// Labels belongs to the existing resource's spec.
	Labels map[string]string
	// ServiceSpec is populated for services only.
	ServiceSpec *swarm.ServiceSpec
}

type Reader interface {
	// Inspect loads one current resource or returns a redacted failure.
	Inspect(ctx context.Context, op operation.Operation) (Snapshot, error)
}

type Client struct {
	http     *http.Client
	token    *Token
	observer *telemetry.Observer
}

// New creates a separate Unix-socket client. No Docker environment variables,
// API negotiation or redirects can widen its limited inspect capability.
func New(socket string, token *Token, observer *telemetry.Observer) *Client {
	dialer := net.Dialer{Timeout: LookupTimeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConns,
		IdleConnTimeout:       idleConnTimeout,
		ResponseHeaderTimeout: LookupTimeout,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   LookupTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New(forbiddenRedirect)
		},
	}
	return &Client{http: httpClient, token: token, observer: observer}
}

// Close releases idle state-lookup connections during shutdown.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// Inspect retrieves the same API representation used by the external operation.
func (c *Client) Inspect(ctx context.Context, op operation.Operation) (snapshot Snapshot, err error) {
	start := time.Now()
	ctx, span := c.observer.Start(
		ctx,
		"dockauthz.docker.inspect",
		attribute.String("dockauthz.resource", string(op.Resource)),
	)
	defer span.End()
	defer func() { c.observer.Lookup(ctx, string(op.Resource), start, err) }()
	path := "/" + string(op.Resource) + "s/" + op.ID
	if op.Version != "" {
		path = "/v" + op.Version + path
	}
	resolved, err := operation.Resolve("GET", path)
	if err != nil || resolved.Action != operation.ActionInspect {
		return Snapshot{}, errors.New("invalid inspect operation")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return Snapshot{}, errors.New("cannot construct Docker inspect")
	}
	req.Header.Set(InternalHeader, c.token.value)
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))
	response, err := c.http.Do(req)
	if err != nil {
		return Snapshot{}, errors.New("docker inspect unavailable or timed out")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, errors.New("docker inspect failed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil || len(body) > maxResponseSize {
		return Snapshot{}, errors.New("invalid Docker inspect response size")
	}
	// Metadata may evolve independently. The entire ServiceSpec is decoded
	// strictly below, including unknown nested fields on newer daemons.
	var envelope struct {
		// ID is Docker's canonical resource identifier.
		ID string `json:"ID"`
		// Version is the optimistic concurrency index.
		Version swarm.Version `json:"Version"`
		// Spec retains unknown fields until strict typed decoding.
		Spec json.RawMessage `json:"Spec"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.ID == "" {
		return Snapshot{}, errors.New("invalid Docker inspect response")
	}
	snapshot = Snapshot{ID: envelope.ID, Version: envelope.Version.Index}
	switch op.Resource {
	case operation.ResourceService:
		var spec swarm.ServiceSpec
		if decodeErr := specjson.Decode(envelope.Spec, &spec); decodeErr != nil {
			return Snapshot{}, decodeErr
		}
		snapshot.Labels = spec.Labels
		snapshot.ServiceSpec = &spec
	case operation.ResourceSecret:
		var spec swarm.SecretSpec
		if decodeErr := specjson.Decode(envelope.Spec, &spec); decodeErr != nil {
			return Snapshot{}, decodeErr
		}
		snapshot.Labels = spec.Labels
	case operation.ResourceNode:
		var spec swarm.NodeSpec
		if decodeErr := specjson.Decode(envelope.Spec, &spec); decodeErr != nil {
			return Snapshot{}, decodeErr
		}
		snapshot.Labels = spec.Labels
	case operation.ResourceTask:
		// Task labels belong to Annotations on the task, not TaskSpec.
		var task swarm.Task
		if decodeErr := specjson.Decode(body, &task); decodeErr != nil {
			return Snapshot{}, decodeErr
		}
		snapshot.Labels = task.Labels
	case operation.ResourceUnknown:
		return Snapshot{}, errors.New("unsupported inspect resource")
	default:
		return Snapshot{}, errors.New("unsupported inspect resource")
	}
	return snapshot, nil
}
