package authz

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

func hasSpanContext(ctx context.Context) bool { return trace.SpanContextFromContext(ctx).IsValid() }
