package telemetry_test

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/moby/moby/api/types/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swarm-deploy/dockauthz/internal/audit"
	"github.com/swarm-deploy/dockauthz/internal/authz"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/policy"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	collectormetric "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func plugin(t *testing.T, o *telemetry.Observer, logger *slog.Logger) (*authz.Plugin, *dockerapi.MockReader) {
	t.Helper()
	cfg, err := config.Load("../../examples/config.yaml")
	require.NoError(t, err)
	reader := dockerapi.NewMockReader(gomock.NewController(t))
	token, err := dockerapi.NewToken()
	require.NoError(t, err)
	p, err := authz.New(cfg, token, policy.New(reader, o), o, logger)
	require.NoError(t, err)
	return p, reader
}
func request(method, uri, body string) authorization.Request {
	return authorization.Request{UserAuthNMethod: "TLS", RequestPeerCertificates: []*authorization.PeerCertificate{{Subject: pkix.Name{CommonName: "cloud-secrets"}}}, RequestMethod: method, RequestURI: uri, RequestBody: []byte(body)}
}

func TestSpansMetricsAndAudit(t *testing.T) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer tp.Shutdown(context.Background())
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	o := telemetry.NewObserver(tp, mp)
	var logs bytes.Buffer
	p, lookup := plugin(t, o, audit.NewLogger(&logs))
	const body = `{"TaskTemplate":{"ContainerSpec":{"Image":"app","Secrets":[{"SecretID":"sensitive-resource-id"}],"Env":["secret-value","-----BEGIN PRIVATE KEY-----"]}}}`
	var spec swarm.ServiceSpec
	require.NoError(t, json.Unmarshal([]byte(body), &spec))
	lookup.EXPECT().Inspect(gomock.Any(), gomock.Any()).Return(dockerapi.Snapshot{ID: "sensitive-resource-id", Version: 42, ServiceSpec: &spec}, nil)
	req := request("POST", "/services/sensitive-resource-id/update?version=42", body)
	req.RequestHeaders = map[string]string{"traceparent": "00-12345678901234567890123456789012-1234567890123456-01", "baggage": "admin=true,secret=never-export"}
	assert.True(t, p.AuthZReq(req).Allow)
	assert.False(t, p.AuthZReq(request("POST", "/secrets/create", `{"Data":"c2VjcmV0"}`)).Allow)
	spans := recorder.Ended()
	require.NotEmpty(t, spans)
	var root sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == "dockauthz.authorize" && s.Parent().IsRemote() {
			root = s
		}
	}
	require.NotNil(t, root)
	assert.Equal(t, "12345678901234567890123456789012", root.SpanContext().TraceID().String())
	assert.Contains(t, logs.String(), `"trace_id":"12345678901234567890123456789012"`)
	assert.Contains(t, logs.String(), `"span_id":`)
	for _, s := range spans {
		for _, a := range s.Attributes() {
			for _, sensitive := range []string{body, "secret-value", "PRIVATE KEY", "c2VjcmV0", "never-export"} {
				assert.NotContains(t, a.Value.Emit(), sensitive)
			}
		}
	}
	for _, sensitive := range []string{body, "secret-value", "PRIVATE KEY", "c2VjcmV0", "never-export"} {
		assert.NotContains(t, logs.String(), sensitive)
	}
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	decisions := map[string]int64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "dockauthz_authorization_decisions_total" {
				sum := m.Data.(metricdata.Sum[int64])
				for _, point := range sum.DataPoints {
					v, _ := point.Attributes.Value("decision")
					decisions[v.AsString()] += point.Value
					for _, attr := range point.Attributes.ToSlice() {
						assert.NotContains(t, attr.Value.Emit(), "sensitive-resource-id")
						assert.NotContains(t, attr.Value.Emit(), "/services/")
					}
				}
			}
		}
	}
	assert.Equal(t, int64(1), decisions["allow"])
	assert.Equal(t, int64(1), decisions["deny"])
}

func TestOTLPTransports(t *testing.T) {
	for _, protocol := range []string{"grpc", "http"} {
		t.Run(protocol, func(t *testing.T) {
			traces := make(chan *collectortrace.ExportTraceServiceRequest, 8)
			metrics := make(chan *collectormetric.ExportMetricsServiceRequest, 8)
			var endpoint string
			if protocol == "http" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "tenant", r.Header.Get("x-tenant-id"))
					body, err := io.ReadAll(r.Body)
					assert.NoError(t, err)
					w.Header().Set("Content-Type", "application/x-protobuf")
					switch r.URL.Path {
					case "/v1/traces":
						var req collectortrace.ExportTraceServiceRequest
						assert.NoError(t, proto.Unmarshal(body, &req))
						traces <- &req
					case "/v1/metrics":
						var req collectormetric.ExportMetricsServiceRequest
						assert.NoError(t, proto.Unmarshal(body, &req))
						metrics <- &req
					default:
						t.Errorf("unexpected OTLP path: %s", r.URL.Path)
					}
				}))
				defer server.Close()
				endpoint = strings.TrimPrefix(server.URL, "http://")
			} else {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				server := grpc.NewServer()
				// These are real OTLP protocol endpoints, registered without test
				// substitutes for authorization or exporter interfaces.
				server.RegisterService(&grpc.ServiceDesc{ServiceName: "opentelemetry.proto.collector.trace.v1.TraceService", HandlerType: (*collectortrace.TraceServiceServer)(nil), Methods: []grpc.MethodDesc{{MethodName: "Export", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					var req collectortrace.ExportTraceServiceRequest
					if err := decode(&req); err != nil {
						return nil, err
					}
					md, _ := metadata.FromIncomingContext(ctx)
					assert.Equal(t, []string{"tenant"}, md.Get("x-tenant-id"))
					traces <- &req
					return &collectortrace.ExportTraceServiceResponse{}, nil
				}}}}, nil)
				server.RegisterService(&grpc.ServiceDesc{ServiceName: "opentelemetry.proto.collector.metrics.v1.MetricsService", HandlerType: (*collectormetric.MetricsServiceServer)(nil), Methods: []grpc.MethodDesc{{MethodName: "Export", Handler: func(_ any, _ context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					var req collectormetric.ExportMetricsServiceRequest
					if err := decode(&req); err != nil {
						return nil, err
					}
					metrics <- &req
					return &collectormetric.ExportMetricsServiceResponse{}, nil
				}}}}, nil)
				go server.Serve(listener)
				defer server.Stop()
				endpoint = listener.Addr().String()
			}
			cfg := &config.Telemetry{OTLP: config.OTLP{Endpoint: endpoint, Protocol: protocol, Insecure: true, Headers: map[string]string{"x-tenant-id": "tenant"}}, Resource: map[string]string{"environment": "test"}, Traces: config.Traces{Enabled: true}, Metrics: config.Metrics{Enabled: true}}
			rt, err := telemetry.Setup(context.Background(), cfg, "test-version")
			require.NoError(t, err)
			p, _ := plugin(t, rt.Observer, audit.NewLogger(io.Discard))
			assert.True(t, p.AuthZReq(request("GET", "/services", "")).Allow)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, rt.Shutdown(ctx))
			select {
			case req := <-traces:
				require.NotEmpty(t, req.ResourceSpans)
				assert.Contains(t, req.String(), "dockauthz.authorize")
				assert.Contains(t, req.String(), "test-version")
				assert.Contains(t, req.String(), "environment")
			case <-ctx.Done():
				t.Fatal("no OTLP traces received")
			}
			select {
			case req := <-metrics:
				require.NotEmpty(t, req.ResourceMetrics)
				assert.Contains(t, req.String(), "dockauthz_authorization_decisions_total")
			case <-ctx.Done():
				t.Fatal("no OTLP metrics received")
			}
		})
	}
}

func TestDisabledOrUnavailableTelemetry(t *testing.T) {
	for _, protocol := range []string{"omitted", "grpc", "http"} {
		t.Run(protocol, func(t *testing.T) {
			var cfg *config.Telemetry
			if protocol != "omitted" {
				cfg = &config.Telemetry{OTLP: config.OTLP{Endpoint: "127.0.0.1:1", Protocol: protocol, Insecure: true}, Traces: config.Traces{Enabled: true}, Metrics: config.Metrics{Enabled: true}}
			}
			start := time.Now()
			rt, err := telemetry.Setup(context.Background(), cfg, "test")
			require.NoError(t, err)
			assert.Less(t, time.Since(start), time.Second)
			p, _ := plugin(t, rt.Observer, audit.NewLogger(io.Discard))
			assert.True(t, p.AuthZReq(request("GET", "/services", "")).Allow)
			assert.False(t, p.AuthZReq(request("GET", "/containers/json", "")).Allow)
			if protocol == "omitted" {
				_, s := rt.Observer.Start(context.Background(), "test")
				assert.False(t, s.IsRecording())
				s.End()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_ = rt.Shutdown(ctx)
			assert.True(t, p.AuthZReq(request("GET", "/services", "")).Allow)
		})
	}
}

func TestExporterFailureRedaction(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "sensitive-collector-response", http.StatusInternalServerError)
	}))
	defer server.Close()
	logs, err := os.CreateTemp(t.TempDir(), "audit-*.json")
	require.NoError(t, err)
	defer logs.Close()
	previous := slog.Default()
	slog.SetDefault(audit.NewLogger(logs))
	defer slog.SetDefault(previous)
	cfg := &config.Telemetry{OTLP: config.OTLP{Endpoint: strings.TrimPrefix(server.URL, "http://"), Protocol: "http", Insecure: true, Headers: map[string]string{"authorization": "sensitive-otlp-header"}}, Traces: config.Traces{Enabled: true}}
	rt, err := telemetry.Setup(context.Background(), cfg, "test")
	require.NoError(t, err)
	p, _ := plugin(t, rt.Observer, audit.NewLogger(io.Discard))
	assert.True(t, p.AuthZReq(request("GET", "/services", "")).Allow)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = rt.Shutdown(ctx)
	assert.Positive(t, requests.Load(), "the collector must actually reject an export")
	assert.True(t, p.AuthZReq(request("GET", "/services", "")).Allow)
	assert.False(t, p.AuthZReq(request("POST", "/secrets/create", "bad")).Allow)
	// SDK failures are rate limited and stripped of provider-controlled strings.
	otel.Handle(io.ErrUnexpectedEOF)
	otel.Handle(io.EOF)
	data, err := os.ReadFile(logs.Name())
	require.NoError(t, err)
	assert.NotContains(t, string(data), "sensitive-collector-response")
	assert.NotContains(t, string(data), "sensitive-otlp-header")
	assert.Equal(t, 1, strings.Count(string(data), "telemetry export failed"))
}

func TestLookupMetricDimensions(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	tp := sdktrace.NewTracerProvider()
	defer tp.Shutdown(context.Background())
	o := telemetry.NewObserver(tp, mp)
	o.Lookup(context.Background(), "service", time.Now(), nil)
	o.Lookup(context.Background(), "secret", time.Now(), io.EOF)
	o.Internal(context.Background(), "deny")
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	names := map[string]bool{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			names[m.Name] = true
		}
	}
	assert.True(t, names["dockauthz_docker_lookups_total"])
	assert.True(t, names["dockauthz_docker_lookup_duration_seconds"])
	assert.True(t, names["dockauthz_internal_requests_total"])
}
