package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/moby/moby/api/types/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swarm-deploy/dockauthz/internal/audit"
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
)

func TestRecursiveInspectAndTelemetry(t *testing.T) {
	// A short path also works under macOS's small sockaddr_un limit.
	dir, err := os.MkdirTemp("/tmp", "dockauthz-")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer tp.Shutdown(context.Background())
	mr := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(mr))
	defer mp.Shutdown(context.Background())
	observer := telemetry.NewObserver(tp, mp)
	token, err := dockerapi.NewToken()
	require.NoError(t, err)
	client := dockerapi.New(socket, token, observer)
	defer client.Close()
	cfg, err := config.Load("../../examples/config.yaml")
	require.NoError(t, err)
	var logs bytes.Buffer
	p, err := New(cfg, token, policy.New(client, observer), observer, audit.NewLogger(&logs))
	require.NoError(t, err)
	seenToken := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1.53/services/abc", r.URL.Path)
		value := r.Header.Get(dockerapi.InternalHeader)
		seenToken <- value
		assert.NotEmpty(t, r.Header.Get("traceparent"))
		internal := authorization.Request{RequestMethod: r.Method, RequestURI: r.URL.RequestURI(), RequestHeaders: map[string]string{dockerapi.InternalHeader: value, "traceparent": r.Header.Get("traceparent")}}
		assert.True(t, p.AuthZReq(internal).Allow)
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			internal.RequestMethod = method
			assert.False(t, p.AuthZReq(internal).Allow)
		}
		internal.RequestMethod = "GET"
		internal.RequestURI = "/services"
		assert.False(t, p.AuthZReq(internal).Allow)
		internal.RequestURI = "/services/abc?unexpected=1"
		assert.False(t, p.AuthZReq(internal).Allow)
		var spec swarm.ServiceSpec
		assert.NoError(t, json.Unmarshal([]byte(currentSpec), &spec))
		_ = json.NewEncoder(w).Encode(swarm.Service{ID: "abc", Meta: swarm.Meta{Version: swarm.Version{Index: 42}}, Spec: spec})
	})}
	go server.Serve(listener)
	defer server.Close()
	assert.True(t, p.AuthZReq(authenticated("cloud-secrets", "POST", "/v1.53/services/abc/update?version=42", currentSpec)).Allow)
	select {
	case value := <-seenToken:
		assert.NotEmpty(t, value)
		assert.NotContains(t, logs.String(), value)
		for _, s := range recorder.Ended() {
			for _, a := range s.Attributes() {
				assert.NotContains(t, a.Value.Emit(), value)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("internal inspect was not sent")
	}
	spans := recorder.Ended()
	byID := map[string]sdktrace.ReadOnlySpan{}
	var inspect sdktrace.ReadOnlySpan
	for _, s := range spans {
		byID[s.SpanContext().SpanID().String()] = s
		if s.Name() == "dockauthz.docker.inspect" {
			inspect = s
		}
	}
	require.NotNil(t, inspect)
	parent := byID[inspect.Parent().SpanID().String()]
	require.NotNil(t, parent)
	assert.Equal(t, "dockauthz.policy.evaluate", parent.Name())
	authorize := byID[parent.Parent().SpanID().String()]
	require.NotNil(t, authorize)
	assert.Equal(t, "dockauthz.authorize", authorize.Name())
	assert.Equal(t, authorize.SpanContext().TraceID(), inspect.SpanContext().TraceID())
	var rm metricdata.ResourceMetrics
	require.NoError(t, mr.Collect(context.Background(), &rm))
	var lookups int64
	for _, scope := range rm.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name == "dockauthz_docker_lookups_total" {
				for _, point := range metric.Data.(metricdata.Sum[int64]).DataPoints {
					lookups += point.Value
				}
			}
		}
	}
	assert.Equal(t, int64(1), lookups)
}
