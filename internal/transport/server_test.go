package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swarm-deploy/dockauthz/internal/audit"
	"github.com/swarm-deploy/dockauthz/internal/authz"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/policy"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"go.opentelemetry.io/otel"
	mnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/mock/gomock"
)

func TestHTTPEnvelope(t *testing.T) {
	cfg, err := config.Parse(strings.NewReader("authentication: {unidentified: allow}\nclients: {admin: {identity: {certificate: {commonName: admin}}, permissions: {'*': {'*': {}}}}}"))
	require.NoError(t, err)
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer tp.Shutdown(context.Background())
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	o := telemetry.NewObserver(tp, mnoop.NewMeterProvider())
	token, err := dockerapi.NewToken()
	require.NoError(t, err)
	p, err := authz.New(cfg, token, policy.New(dockerapi.NewMockReader(gomock.NewController(t)), o), o, audit.NewLogger(io.Discard))
	require.NoError(t, err)
	server := New(p)
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	valid, err := json.Marshal(authorization.Request{UserAuthNMethod: "TLS", RequestMethod: "POST", RequestURI: "/arbitrary", RequestPeerCertificates: []*authorization.PeerCertificate{(*authorization.PeerCertificate)(cert)}})
	require.NoError(t, err)
	for _, tc := range []struct {
		name, path, body string
		allow            bool
	}{
		{"valid leaf", "/AuthZPlugin.AuthZReq", string(valid), true},
		{"local unidentified", "/AuthZPlugin.AuthZReq", `{"RequestMethod":"GET","RequestUri":"/services"}`, true},
		{"malformed JSON", "/AuthZPlugin.AuthZReq", "{", false},
		{"null", "/AuthZPlugin.AuthZReq", "null", false},
		{"empty", "/AuthZPlugin.AuthZReq", "{}", false},
		{"unknown envelope field", "/AuthZPlugin.AuthZReq", `{"RequestMethod":"GET","RequestUri":"/services","Unknown":true}`, false},
		{"trailing document", "/AuthZPlugin.AuthZReq", string(valid) + " {}", false},
		{"invalid PEM", "/AuthZPlugin.AuthZReq", `{"RequestMethod":"GET","RequestUri":"/services","RequestPeerCertificates":["YmFk"]}`, false},
		{"null PEM", "/AuthZPlugin.AuthZReq", `{"RequestMethod":"GET","RequestUri":"/services","RequestPeerCertificates":[null]}`, false},
		{"oversized envelope", "/AuthZPlugin.AuthZReq", `{"RequestMethod":"GET","RequestUri":"/services","RequestBody":"` + strings.Repeat("A", maxEnvelopeSize) + `"}`, false},
		{"response unconditional", "/AuthZPlugin.AuthZRes", "{}", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
			r.Header.Set("traceparent", "00-11223344556677889900112233445566-1122334455667788-01")
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			var res authorization.Response
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &res))
			assert.Equal(t, tc.allow, res.Allow)
		})
	}
	spans := recorder.Ended()
	require.NotEmpty(t, spans)
	assert.Equal(t, "11223344556677889900112233445566", spans[0].SpanContext().TraceID().String())
	assert.True(t, spans[0].Parent().IsRemote())
}
