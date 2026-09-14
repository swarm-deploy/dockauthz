package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/swarm-deploy/dockauthz/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	mg "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	mh "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	tg "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	th "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	mnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tnoop "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type Runtime struct {
	// Observer instruments the plugin even when exporters are disabled.
	Observer *Observer
	traces   *sdktrace.TracerProvider
	metrics  *sdkmetric.MeterProvider
}

const (
	otelErrorLogInterval = 60
	exportTimeout        = 3 * time.Second
)

// Setup validates syntax locally. Exporters connect asynchronously; collector
// failures neither block startup nor change decisions. Global setup runs once.
func Setup(ctx context.Context, cfg *config.Telemetry, version string) (*Runtime, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	var last atomic.Int64
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		now := time.Now().Unix()
		previous := last.Load()
		if now-previous >= otelErrorLogInterval && last.CompareAndSwap(previous, now) {
			// Exporter errors may contain headers, endpoints or response bodies.
			slog.ErrorContext(context.Background(), "telemetry export failed", "type", "telemetry")
		}
	}))
	r := &Runtime{}
	var tp trace.TracerProvider = tnoop.NewTracerProvider()
	var mp metric.MeterProvider = mnoop.NewMeterProvider()
	if cfg != nil {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		attrs := []attribute.KeyValue{
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", version),
		}
		for k, v := range cfg.Resource {
			attrs = append(attrs, attribute.String(k, v))
		}
		res := resource.NewSchemaless(attrs...)
		if cfg.Traces.Enabled {
			exporter, err := traceExporter(ctx, cfg.OTLP)
			if err != nil {
				otel.Handle(errors.New("trace exporter initialization failed"))
			} else {
				r.traces = sdktrace.NewTracerProvider(
					sdktrace.WithResource(res),
					sdktrace.WithSampler(sdktrace.ParentBased(
						sdktrace.TraceIDRatioBased(*cfg.Traces.SampleRatio),
					)),
					sdktrace.WithBatcher(exporter, sdktrace.WithExportTimeout(exportTimeout)),
				)
				tp = r.traces
			}
		}
		if cfg.Metrics.Enabled {
			exporter, err := metricExporter(ctx, cfg.OTLP)
			if err != nil {
				otel.Handle(errors.New("metric exporter initialization failed"))
			} else {
				interval, _ := time.ParseDuration(cfg.Metrics.ExportInterval)
				r.metrics = sdkmetric.NewMeterProvider(
					sdkmetric.WithResource(res),
					sdkmetric.WithReader(sdkmetric.NewPeriodicReader(
						exporter,
						sdkmetric.WithInterval(interval),
						sdkmetric.WithTimeout(exportTimeout),
					)),
				)
				mp = r.metrics
			}
		}
	}
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	r.Observer = NewObserver(tp, mp)
	return r, nil
}

func traceExporter(ctx context.Context, c config.OTLP) (sdktrace.SpanExporter, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.Protocol == "grpc" {
		opts := []tg.Option{
			tg.WithEndpoint(c.Endpoint),
			tg.WithHeaders(c.Headers),
			tg.WithTimeout(exportTimeout),
			tg.WithTLSCredentials(credentials.NewTLS(tlsConfig)),
		}
		if c.Insecure {
			opts = append(opts, tg.WithTLSCredentials(insecure.NewCredentials()))
		}
		return tg.New(ctx, opts...)
	}
	scheme := "https://"
	if c.Insecure {
		scheme = "http://"
	}
	opts := []th.Option{
		th.WithEndpointURL(scheme + c.Endpoint + "/v1/traces"),
		th.WithHeaders(c.Headers),
		th.WithTimeout(exportTimeout),
	}
	if !c.Insecure {
		opts = append(opts, th.WithTLSClientConfig(tlsConfig))
	}
	return th.New(ctx, opts...)
}

func metricExporter(ctx context.Context, c config.OTLP) (sdkmetric.Exporter, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.Protocol == "grpc" {
		opts := []mg.Option{
			mg.WithEndpoint(c.Endpoint),
			mg.WithHeaders(c.Headers),
			mg.WithTimeout(exportTimeout),
			mg.WithTLSCredentials(credentials.NewTLS(tlsConfig)),
		}
		if c.Insecure {
			opts = append(opts, mg.WithTLSCredentials(insecure.NewCredentials()))
		}
		return mg.New(ctx, opts...)
	}
	scheme := "https://"
	if c.Insecure {
		scheme = "http://"
	}
	opts := []mh.Option{
		mh.WithEndpointURL(scheme + c.Endpoint + "/v1/metrics"),
		mh.WithHeaders(c.Headers),
		mh.WithTimeout(exportTimeout),
	}
	if !c.Insecure {
		opts = append(opts, mh.WithTLSClientConfig(tlsConfig))
	}
	return mh.New(ctx, opts...)
}

// Shutdown flushes both providers with the caller's bounded context.
func (r *Runtime) Shutdown(ctx context.Context) error {
	var errs []error
	if r.traces != nil {
		if err := r.traces.Shutdown(ctx); err != nil {
			errs = append(errs, errors.New("trace shutdown failed"))
		}
	}
	if r.metrics != nil {
		if err := r.metrics.Shutdown(ctx); err != nil {
			errs = append(errs, errors.New("metric shutdown failed"))
		}
	}
	return errors.Join(errs...)
}
