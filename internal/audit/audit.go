// Package audit correlates safe structured decision records with tracing.
package audit

import (
	"context"
	"go.opentelemetry.io/otel/trace"
	"io"
	"log/slog"
)

type handler struct{ next slog.Handler }

// NewLogger creates a JSON logger with automatic trace/span correlation.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(&handler{next: slog.NewJSONHandler(w, nil)})
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}
func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	sc := trace.SpanContextFromContext(ctx)
	if sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.next.Handle(ctx, r)
}
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &handler{next: h.next.WithAttrs(attrs)}
}
func (h *handler) WithGroup(name string) slog.Handler { return &handler{next: h.next.WithGroup(name)} }
