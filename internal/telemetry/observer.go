// Package telemetry provides observability independently of authorization results.
package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

type Observer struct {
	tracer         trace.Tracer
	decisions      metric.Int64Counter
	errors         metric.Int64Counter
	duration       metric.Float64Histogram
	lookupDuration metric.Float64Histogram
	lookups        metric.Int64Counter
	internal       metric.Int64Counter
}

// NewObserver binds only constant, valid instrument names to supplied providers.
func NewObserver(tp trace.TracerProvider, mp metric.MeterProvider) *Observer {
	m := mp.Meter("github.com/swarm-deploy/dockauthz")
	d, _ := m.Int64Counter("dockauthz_authorization_decisions_total")
	e, _ := m.Int64Counter("dockauthz_authorization_errors_total")
	t, _ := m.Float64Histogram("dockauthz_authorization_duration_seconds", metric.WithUnit("s"))
	ld, _ := m.Float64Histogram("dockauthz_docker_lookup_duration_seconds", metric.WithUnit("s"))
	l, _ := m.Int64Counter("dockauthz_docker_lookups_total")
	i, _ := m.Int64Counter("dockauthz_internal_requests_total")
	return &Observer{tracer: tp.Tracer("github.com/swarm-deploy/dockauthz"), decisions: d, errors: e, duration: t, lookupDuration: ld, lookups: l, internal: i}
}

// Start creates a span; callers provide only constant operation names.
func (o *Observer) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return o.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// Decision records bounded dimensions, never paths, bodies or resource IDs.
func (o *Observer) Decision(ctx context.Context, decision, client, resource, action string, start time.Time) {
	attrs := []attribute.KeyValue{attribute.String("decision", decision), attribute.String("resource", resource), attribute.String("action", action)}
	o.duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	attrs = append(attrs, attribute.String("client", client))
	o.decisions.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// Error records a fixed error category without sensitive error messages.
func (o *Observer) Error(ctx context.Context, category string) {
	o.errors.Add(ctx, 1, metric.WithAttributes(attribute.String("type", category)))
}

// Lookup records one completed Docker inspect, successful or failed.
func (o *Observer) Lookup(ctx context.Context, resource string, start time.Time, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	o.lookupDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.String("resource", resource)))
	o.lookups.Add(ctx, 1, metric.WithAttributes(attribute.String("resource", resource), attribute.String("result", result)))
}

// Internal records only the allow/deny result of token-bearing requests.
func (o *Observer) Internal(ctx context.Context, decision string) {
	o.internal.Add(ctx, 1, metric.WithAttributes(attribute.String("decision", decision)))
}
