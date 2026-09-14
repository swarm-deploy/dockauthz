// Package transport preserves HTTP context around the official Docker helper.
package transport

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/docker/go-plugins-helpers/sdk"
	"github.com/swarm-deploy/dockauthz/internal/authz"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

const maxEnvelopeSize = 16 << 20

type Server struct {
	plugin *authz.Plugin
	ready  chan *http.Server
}

// New wires an immutable authorization plugin into the HTTP protocol adapter.
func New(plugin *authz.Plugin) *Server {
	return &Server{plugin: plugin, ready: make(chan *http.Server, 1)}
}

// ServeHTTP bounds and validates the envelope before invoking authorization.
// The helper's default callbacks discard HTTP context and continue after decode
// errors; this adapter retains the official interface with strict decoding.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/dockauthz.ready" && r.Method == http.MethodGet {
		if server, ok := r.Context().Value(http.ServerContextKey).(*http.Server); ok {
			select {
			case s.ready <- server:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	deny := func() {
		_ = json.NewEncoder(w).Encode(authorization.Response{Allow: false, Msg: "invalid authorization envelope"})
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/"+authorization.AuthZApiRequest && r.URL.Path != "/"+authorization.AuthZApiResponse) {
		w.WriteHeader(http.StatusNotFound)
		deny()
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEnvelopeSize)
	// Decode certificate wrappers separately: the upstream helper dereferences
	// an unchecked PEM block when it receives malformed certificate data.
	var wire *struct {
		// Request carries the official Docker AuthZ envelope fields.
		authorization.Request
		// Peer avoids the helper's unchecked certificate unmarshaler.
		Peer []json.RawMessage `json:"RequestPeerCertificates"`
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || wire == nil || d.Decode(new(any)) != io.EOF || len(wire.Peer) > 16 {
		deny()
		return
	}
	if r.URL.Path == "/"+authorization.AuthZApiRequest && (wire.RequestMethod == "" || wire.RequestURI == "") {
		deny()
		return
	}
	for _, raw := range wire.Peer {
		var certPEM []byte
		if json.Unmarshal(raw, &certPEM) != nil {
			deny()
			return
		}
		block, rest := pem.Decode(certPEM)
		if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
			deny()
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			deny()
			return
		}
		wire.Request.RequestPeerCertificates = append(wire.Request.RequestPeerCertificates, (*authorization.PeerCertificate)(cert))
	}
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	var response authorization.Response
	if r.URL.Path == "/"+authorization.AuthZApiRequest {
		response = s.plugin.Authorize(ctx, wire.Request)
	} else {
		response = s.plugin.AuthZRes(wire.Request)
	}
	_ = json.NewEncoder(w).Encode(response)
}

// ServeUnix uses the official helper's socket setup. A local readiness request
// obtains the helper's http.Server so shutdown closes its listener and drains
// active requests before telemetry is flushed. The socket is root-only group 0.
func (s *Server) ServeUnix(ctx context.Context, socket string) error {
	h := authorization.NewHandler(s.plugin)
	// Replace only HTTP dispatch, preserving helper activation and ServeUnix.
	h.Handler = sdk.NewHandler(`{"Implements":["authz"]}`)
	h.HandleFunc("/", s.ServeHTTP)
	done := make(chan error, 1)
	go func() { done <- h.ServeUnix(socket, 0) }()
	dialer := net.Dialer{Timeout: time.Second}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}}
	defer client.CloseIdleConnections()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	var server *http.Server
	for server == nil {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return errors.New("plugin socket startup timed out")
		case <-tick.C:
			resp, err := client.Get("http://plugin/dockauthz.ready")
			if err == nil {
				_ = resp.Body.Close()
			}
		case server = <-s.ready:
		}
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return errors.New("plugin shutdown timed out")
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
