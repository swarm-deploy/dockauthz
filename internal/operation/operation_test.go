package operation

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := []struct{ method, path, resource, action, id string }{
		{"GET", "/services", "service", "list", ""},
		{"GET", "/services/abc", "service", "inspect", "abc"},
		{"POST", "/services/create", "service", "create", ""},
		{"POST", "/services/abc/update?version=42", "service", "update", "abc"},
		{"DELETE", "/services/abc", "service", "delete", "abc"},
		{"GET", "/secrets", "secret", "list", ""},
		{"GET", "/secrets/abc", "secret", "inspect", "abc"},
		{"POST", "/secrets/create", "secret", "create", ""},
		{"DELETE", "/secrets/abc", "secret", "delete", "abc"},
		{"GET", "/tasks", "task", "list", ""},
		{"GET", "/tasks/abc", "task", "inspect", "abc"},
		{"GET", "/nodes", "node", "list", ""},
		{"GET", "/nodes/abc", "node", "inspect", "abc"},
	}
	for _, prefix := range []string{"", "/v1.53"} {
		for _, tc := range cases {
			t.Run(tc.method+prefix+tc.path, func(t *testing.T) {
				op, err := Resolve(tc.method, prefix+tc.path)
				require.NoError(t, err)
				assert.Equal(t, tc.resource, op.Resource)
				assert.Equal(t, tc.action, op.Action)
				assert.Equal(t, tc.id, op.ID)
				if prefix != "" {
					assert.Equal(t, "1.53", op.Version)
				}
			})
		}
	}
}

func TestRejectAmbiguousOperations(t *testing.T) {
	for _, uri := range []string{"", "services", "http://docker/services", "//docker/services", "/services/", "/services//abc", "/services/../secrets", "/services/%61bc", "/services/a%2Fb", "/services/a%252fb", "/services/abc/extra", "/v1.x/services", "/v1.53/v1.53/services", "/services#fragment", "/services?broken=%", "/services?x=1;y=2", "/services/abc\\update", "/containers/json", "/services/."} {
		t.Run(uri, func(t *testing.T) { _, err := Resolve("GET", uri); require.Error(t, err) })
	}
	for _, method := range []string{"get", "HEAD", "PUT", "PATCH", "POST"} {
		t.Run(method, func(t *testing.T) { _, err := Resolve(method, "/services"); require.Error(t, err) })
	}
}
