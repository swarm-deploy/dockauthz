package identity

import (
	"crypto/x509/pkix"
	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCommonName(t *testing.T) {
	leaf := &authorization.PeerCertificate{Subject: pkix.Name{CommonName: "client"}}
	ca := &authorization.PeerCertificate{Subject: pkix.Name{CommonName: "ca"}}
	cases := []struct {
		name string
		req  authorization.Request
		cn   string
		bad  bool
	}{
		{"TLS leaf", authorization.Request{UserAuthNMethod: "TLS", RequestPeerCertificates: []*authorization.PeerCertificate{leaf, ca}}, "client", false},
		{"no identity", authorization.Request{}, "", false},
		{"spoofed header", authorization.Request{RequestHeaders: map[string]string{"User": "client", "X-User": "client"}}, "", false},
		{"user only", authorization.Request{User: "client"}, "", true},
		{"TLS no certificate", authorization.Request{UserAuthNMethod: "TLS", User: "client"}, "", true},
		{"certificate no TLS", authorization.Request{RequestPeerCertificates: []*authorization.PeerCertificate{leaf}}, "", true},
		{"nil leaf", authorization.Request{UserAuthNMethod: "TLS", RequestPeerCertificates: []*authorization.PeerCertificate{nil, leaf}}, "", true},
		{"empty CN", authorization.Request{UserAuthNMethod: "TLS", RequestPeerCertificates: []*authorization.PeerCertificate{{}}}, "", true},
		{"contradictory user", authorization.Request{UserAuthNMethod: "TLS", User: "other", RequestPeerCertificates: []*authorization.PeerCertificate{leaf}}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cn, err := CommonName(tc.req)
			assert.Equal(t, tc.cn, cn)
			assert.Equal(t, tc.bad, err != nil)
		})
	}
}
