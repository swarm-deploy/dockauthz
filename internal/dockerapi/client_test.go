package dockerapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swarm-deploy/dockauthz/internal/operation"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	mnoop "go.opentelemetry.io/otel/metric/noop"
	tnoop "go.opentelemetry.io/otel/trace/noop"
)

func TestToken(t *testing.T) {
	token, err := NewToken()
	require.NoError(t, err)
	assert.Len(t, token.value, 64)
	other, err := NewToken()
	require.NoError(t, err)
	assert.NotEqual(t, token.value, other.value)
	for _, tc := range []struct {
		name           string
		headers        map[string]string
		present, valid bool
	}{
		{"absent", nil, false, false},
		{"valid", map[string]string{InternalHeader: token.value}, true, true},
		{"lowercase", map[string]string{"x-dockauthz-internal-token": token.value}, true, true},
		{"invalid", map[string]string{InternalHeader: other.value}, true, false},
		{"empty", map[string]string{InternalHeader: ""}, true, false},
		{"duplicate", map[string]string{InternalHeader: token.value, "x-dockauthz-internal-token": token.value}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, valid := token.Check(tc.headers)
			assert.Equal(t, tc.present, present)
			assert.Equal(t, tc.valid, valid)
		})
	}
}

func TestInspect(t *testing.T) {
	for _, tc := range []struct {
		name, resource, body string
		status               int
		bad                  bool
	}{
		{"service", "service", `{"ID":"abc","Version":{"Index":42},"Spec":{"Name":"app","TaskTemplate":{"ContainerSpec":{"Image":"app:v1"}}}}`, 200, false},
		{"secret", "secret", `{"ID":"abc","Spec":{"Name":"key","Labels":{"managed":"true"}}}`, 200, false},
		{"node", "node", `{"ID":"abc","Spec":{"Labels":{"managed":"true"},"Role":"worker"}}`, 200, false},
		{"task", "task", `{"ID":"abc","Labels":{"managed":"true"},"Spec":{}}`, 200, false},
		{"not found", "service", `not found`, 404, true},
		{"malformed", "service", `{`, 200, true},
		{"missing ID", "service", `{"Spec":{}}`, 200, true},
		{"unknown spec field", "service", `{"ID":"abc","Spec":{"NewSecuritySetting":true}}`, 200, true},
		{"unknown nested field", "service", `{"ID":"abc","Spec":{"TaskTemplate":{"ContainerSpec":{"Unknown":true}}}}`, 200, true},
		{"trailing JSON", "service", `{"ID":"abc","Spec":{}} {}`, 200, true},
		{"redirect", "service", ``, 302, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := NewToken()
			require.NoError(t, err)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1.53/"+tc.resource+"s/abc", r.URL.Path)
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, token.value, r.Header.Get(InternalHeader))
				if tc.status == 302 {
					w.Header().Set("Location", "http://not-docker/")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			observer := telemetry.NewObserver(tnoop.NewTracerProvider(), mnoop.NewMeterProvider())
			client := New("/unused.sock", token, observer)
			defer client.Close()
			// Exercise real HTTP; substitute only the local network address.
			client.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			state, err := client.Inspect(context.Background(), operation.Operation{Resource: operation.Resource(tc.resource), ID: "abc", Version: "1.53"})
			if tc.bad {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "abc", state.ID)
				if tc.resource == "service" {
					require.NotNil(t, state.ServiceSpec)
					assert.Equal(t, uint64(42), state.Version)
				}
			}
		})
	}
}

func TestInspectCancellation(t *testing.T) {
	token, err := NewToken()
	require.NoError(t, err)
	client := New("/not-present.sock", token, telemetry.NewObserver(tnoop.NewTracerProvider(), mnoop.NewMeterProvider()))
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = client.Inspect(ctx, operation.Operation{Resource: operation.ResourceService, ID: "abc"})
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}
