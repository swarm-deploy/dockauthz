// Package identity consumes authentication performed by Docker, never headers.
package identity

import (
	"errors"

	"github.com/docker/go-plugins-helpers/authorization"
)

// CommonName returns an authenticated leaf CN. Empty means no authentication.
// Incomplete or contradictory authentication context must never become anonymous.
func CommonName(req authorization.Request) (string, error) {
	if req.UserAuthNMethod == "" && req.User == "" && len(req.RequestPeerCertificates) == 0 {
		return "", nil
	}
	if req.UserAuthNMethod != "TLS" || len(req.RequestPeerCertificates) == 0 || req.RequestPeerCertificates[0] == nil {
		return "", errors.New("invalid authentication context")
	}
	cn := req.RequestPeerCertificates[0].Subject.CommonName
	if cn == "" || (req.User != "" && req.User != cn) {
		return "", errors.New("ambiguous authenticated identity")
	}
	return cn, nil
}
