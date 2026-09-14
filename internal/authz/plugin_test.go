package authz

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/moby/moby/api/types/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/swarm-deploy/dockauthz/internal/audit"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/policy"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	mnoop "go.opentelemetry.io/otel/metric/noop"
	tnoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"
)

const currentSpec = `{"Name":"app","TaskTemplate":{"ContainerSpec":{"Image":"app:v1","Command":["serve"],"Env":["KEY=value"],"Secrets":[{"SecretID":"old"}]}},"Mode":{"Replicated":{"Replicas":2}}}`

func fixture(t *testing.T) (*Plugin, *dockerapi.MockReader, *bytes.Buffer) {
	t.Helper()
	cfg, err := config.Load("../../examples/config.yaml")
	require.NoError(t, err)
	return fixtureConfig(t, cfg)
}
func fixtureConfig(t *testing.T, cfg *config.Config) (*Plugin, *dockerapi.MockReader, *bytes.Buffer) {
	t.Helper()
	reader := dockerapi.NewMockReader(gomock.NewController(t))
	observer := telemetry.NewObserver(tnoop.NewTracerProvider(), mnoop.NewMeterProvider())
	token, err := dockerapi.NewToken()
	require.NoError(t, err)
	var log bytes.Buffer
	p, err := New(cfg, token, policy.New(reader, observer), observer, audit.NewLogger(&log))
	require.NoError(t, err)
	return p, reader, &log
}
func authenticated(cn, method, path, body string) authorization.Request {
	return authorization.Request{UserAuthNMethod: "TLS", User: cn, RequestPeerCertificates: []*authorization.PeerCertificate{{Subject: pkix.Name{CommonName: cn}}}, RequestMethod: method, RequestURI: path, RequestBody: []byte(body)}
}
func serviceState(t *testing.T) dockerapi.Snapshot {
	t.Helper()
	var spec swarm.ServiceSpec
	require.NoError(t, json.Unmarshal([]byte(currentSpec), &spec))
	return dockerapi.Snapshot{ID: "abc", Version: 42, ServiceSpec: &spec, Labels: spec.Labels}
}

func TestCloudSecrets(t *testing.T) {
	secrets := strings.Replace(currentSpec, `"old"`, `"new"`, 1)
	cases := []struct {
		name, method, path, body string
		lookup, allow            bool
		managed                  bool
	}{
		{"list services", "GET", "/v1.53/services", "", false, true, false},
		{"inspect service", "GET", "/services/abc", "", false, true, false},
		{"list secrets", "GET", "/secrets", "", false, true, false},
		{"inspect secret", "GET", "/secrets/abc", "", false, true, false},
		{"create managed", "POST", "/secrets/create", `{"Name":"new","Data":"c2VjcmV0","Labels":{"org.cloud-secrets.managed":"true","extra":"yes"}}`, false, true, false},
		{"create unmanaged", "POST", "/secrets/create", `{"Name":"new","Data":"c2VjcmV0"}`, false, false, false},
		{"missing body", "POST", "/secrets/create", "", false, false, false},
		{"bad JSON", "POST", "/secrets/create", "{", false, false, false},
		{"delete managed", "DELETE", "/secrets/abc", "", true, true, true},
		{"delete unmanaged", "DELETE", "/secrets/abc", "", true, false, false},
		{"secrets update", "POST", "/services/abc/update?version=42", secrets, true, true, false},
		{"image update", "POST", "/services/abc/update?version=42", strings.Replace(currentSpec, "app:v1", "app:v2", 1), true, false, false},
		{"command update", "POST", "/services/abc/update?version=42", strings.Replace(currentSpec, "serve", "shell", 1), true, false, false},
		{"env update", "POST", "/services/abc/update?version=42", strings.Replace(currentSpec, "KEY=value", "KEY=changed", 1), true, false, false},
		{"mount update", "POST", "/services/abc/update?version=42", strings.Replace(currentSpec, `"Image"`, `"Mounts":[{"Source":"/","Target":"/host","Type":"bind"}],"Image"`, 1), true, false, false},
		{"secrets and image", "POST", "/services/abc/update?version=42", strings.Replace(secrets, "app:v1", "app:v2", 1), true, false, false},
		{"secrets and replicas", "POST", "/services/abc/update?version=42", strings.Replace(secrets, `"Replicas":2`, `"Replicas":3`, 1), true, false, false},
		{"missing update body", "POST", "/services/abc/update?version=42", "", true, false, false},
		{"stale version", "POST", "/services/abc/update?version=41", secrets, true, false, false},
		{"missing version", "POST", "/services/abc/update", secrets, false, false, false},
		{"repeated version", "POST", "/services/abc/update?version=42&version=42", secrets, false, false, false},
		{"rollback bypass", "POST", "/services/abc/update?version=42&rollback=previous", secrets, false, false, false},
		{"registry previous bypass", "POST", "/services/abc/update?version=42&registryAuthFrom=previous-spec", secrets, false, false, false},
		{"unknown option", "POST", "/services/abc/update?version=42&futureOption=true", secrets, false, false, false},
		{"unknown operation", "GET", "/containers/json", "", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, reader, log := fixture(t)
			if tc.lookup {
				snapshot := serviceState(t)
				if strings.Contains(tc.path, "secrets/") {
					snapshot = dockerapi.Snapshot{ID: "abc", Labels: map[string]string{}}
					if tc.managed {
						snapshot.Labels["org.cloud-secrets.managed"] = "true"
					}
				}
				reader.EXPECT().Inspect(gomock.Any(), gomock.Any()).Return(snapshot, nil)
			}
			res := p.AuthZReq(authenticated("cloud-secrets", tc.method, tc.path, tc.body))
			assert.Equal(t, tc.allow, res.Allow, res.Msg)
			assert.NotContains(t, log.String(), "c2VjcmV0")
			assert.NotContains(t, log.String(), "KEY=value")
		})
	}
}

func TestCIAndAutoscaler(t *testing.T) {
	for _, tc := range []struct {
		name, cn, body string
		allow          bool
	}{
		{"CI image", "github-ci", strings.Replace(currentSpec, "app:v1", "app:v2", 1), true},
		{"CI image and secrets", "github-ci", strings.Replace(strings.Replace(currentSpec, "app:v1", "app:v2", 1), `"old"`, `"new"`, 1), false},
		{"autoscaler replicas", "autoscaler", strings.Replace(currentSpec, `"Replicas":2`, `"Replicas":3`, 1), true},
		{"autoscaler replicas and image", "autoscaler", strings.Replace(strings.Replace(currentSpec, `"Replicas":2`, `"Replicas":3`, 1), "app:v1", "app:v2", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, reader, _ := fixture(t)
			reader.EXPECT().Inspect(gomock.Any(), gomock.Any()).Return(serviceState(t), nil)
			assert.Equal(t, tc.allow, p.AuthZReq(authenticated(tc.cn, "POST", "/services/abc/update?version=42", tc.body)).Allow)
		})
	}
}

func TestIdentityAndWildcards(t *testing.T) {
	for _, tc := range []struct {
		name, cn, method, path, unidentified string
		permissions                          map[string]map[string]config.Permission
		allow                                bool
	}{
		{"unknown TLS", "stranger", "GET", "/services", "allow", nil, false},
		{"unidentified allowed", "", "POST", "/anything", "allow", nil, true},
		{"unidentified denied", "", "GET", "/services", "deny", nil, false},
		{"full admin", "docker-admin", "POST", "/grpc", "deny", nil, true},
		{"service wildcard", "cloud-secrets", "DELETE", "/services/abc", "deny", map[string]map[string]config.Permission{"service": {"*": {}}}, true},
		{"service wildcard unknown endpoint", "cloud-secrets", "POST", "/services/abc/unsupported", "deny", map[string]map[string]config.Permission{"service": {"*": {}}}, false},
		{"resource wildcard list", "cloud-secrets", "GET", "/nodes", "deny", map[string]map[string]config.Permission{"*": {"list": {}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load("../../examples/config.yaml")
			require.NoError(t, err)
			cfg.Authentication.Unidentified = tc.unidentified
			if tc.permissions != nil {
				c := cfg.Clients["cloud-secrets"]
				c.Permissions = tc.permissions
				cfg.Clients["cloud-secrets"] = c
			}
			p, _, _ := fixtureConfig(t, cfg)
			req := authenticated(tc.cn, tc.method, tc.path, "")
			if tc.cn == "" {
				req.UserAuthNMethod = ""
				req.RequestPeerCertificates = nil
			}
			assert.Equal(t, tc.allow, p.AuthZReq(req).Allow)
		})
	}
}

func TestFailClosedAndResponse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state dockerapi.Snapshot
		err   error
	}{
		{"lookup failure", dockerapi.Snapshot{}, errors.New("secret-value-never-log")},
		{"name race", dockerapi.Snapshot{ID: "different", Version: 42}, nil},
		{"missing spec", dockerapi.Snapshot{ID: "abc", Version: 42}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, reader, log := fixture(t)
			reader.EXPECT().Inspect(gomock.Any(), gomock.Any()).Return(tc.state, tc.err)
			assert.False(t, p.AuthZReq(authenticated("cloud-secrets", "POST", "/services/abc/update?version=42", currentSpec)).Allow)
			assert.NotContains(t, log.String(), "secret-value-never-log")
		})
	}
	p, _, log := fixture(t)
	req := authenticated("docker-admin", "POST", "/services/create", "")
	req.RequestHeaders = map[string]string{dockerapi.InternalHeader: "invalid-token-never-log"}
	assert.False(t, p.AuthZReq(req).Allow)
	assert.NotContains(t, log.String(), "invalid-token-never-log")
	assert.True(t, p.AuthZRes(req).Allow)
	req = authenticated("cloud-secrets", "POST", "/services/abc/update?version=42", currentSpec)
	req.RequestHeaders = map[string]string{"X-Registry-Auth": "registry-secret"}
	assert.False(t, p.AuthZReq(req).Allow)
}

func TestPermissionsCannotCombineMutationSubsets(t *testing.T) {
	cfg, err := config.Load("../../examples/config.yaml")
	require.NoError(t, err)
	c := cfg.Clients["cloud-secrets"]
	c.Permissions["*"] = map[string]config.Permission{"update": {Mutation: &config.Mutation{Only: []string{"container.image"}}}}
	cfg.Clients["cloud-secrets"] = c
	p, reader, _ := fixtureConfig(t, cfg)
	reader.EXPECT().Inspect(gomock.Any(), gomock.Any()).Return(serviceState(t), nil).Times(2)
	body := strings.Replace(strings.Replace(currentSpec, "app:v1", "app:v2", 1), `"old"`, `"new"`, 1)
	assert.False(t, p.AuthZReq(authenticated("cloud-secrets", "POST", "/services/abc/update?version=42", body)).Allow)
}
