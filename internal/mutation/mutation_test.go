package mutation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const original = `{"Name":"app","Labels":{"team":"infra"},"TaskTemplate":{"ContainerSpec":{"Image":"image:v1","Command":["serve"],"Env":["MODE=prod"],"Secrets":[{"SecretID":"old","SecretName":"secret","File":{"Name":"token","UID":"0","GID":"0","Mode":256}}]},"ForceUpdate":0},"Mode":{"Replicated":{"Replicas":2}}}`

func TestMutation(t *testing.T) {
	var current swarm.ServiceSpec
	require.NoError(t, json.Unmarshal([]byte(original), &current))
	cases := []struct {
		name, from, to string
		allowed        []string
		allow          bool
	}{
		{"unchanged", "", "", []string{"container.secrets"}, true},
		{"secrets", "\"old\"", "\"new\"", []string{"container.secrets"}, true},
		{"image forbidden", "image:v1", "image:v2", []string{"container.secrets"}, false},
		{"command", "serve", "shell", []string{"container.secrets"}, false},
		{"env", "MODE=prod", "MODE=dev", []string{"container.secrets"}, false},
		{"mount", `"Image":"image:v1"`, `"Mounts":[{"Type":"bind","Source":"/","Target":"/host"}],"Image":"image:v1"`, []string{"container.secrets"}, false},
		{"replicas forbidden", `"Replicas":2`, `"Replicas":3`, []string{"container.secrets"}, false},
		{"force update", `"ForceUpdate":0`, `"ForceUpdate":1`, []string{"container.secrets"}, false},
		{"label", "infra", "other", []string{"container.secrets"}, false},
		{"name", `"app"`, `"other"`, []string{"container.secrets"}, false},
		{"nil empty mounts", `"Image":"image:v1"`, `"Mounts":[],"Image":"image:v1"`, []string{"container.secrets"}, false},
		{"nil empty labels", `"Image":"image:v1"`, `"Labels":{},"Image":"image:v1"`, []string{"container.secrets"}, false},
		{"CI image", "image:v1", "image:v2", []string{"container.image"}, true},
		{"CI secrets", "\"old\"", "\"new\"", []string{"container.image"}, false},
		{"autoscaler", `"Replicas":2`, `"Replicas":3`, []string{"replicas"}, true},
		{"autoscaler image", "image:v1", "image:v2", []string{"replicas"}, false},
		{"unknown root", `"Name":"app"`, `"UnknownDockerField":true,"Name":"app"`, []string{"container.secrets"}, false},
		{"unknown nested", `"Image":"image:v1"`, `"FuturePrivilege":true,"Image":"image:v1"`, []string{"container.secrets"}, false},
		{"unknown inside allowed subtree", `"SecretID":"old"`, `"FutureSecretField":true,"SecretID":"old"`, []string{"container.secrets"}, false},
		{"mode change", `"Replicated":{"Replicas":2}`, `"Global":{}`, []string{"replicas"}, false},
		{"mode ambiguity", `"Replicated":{"Replicas":2}`, `"Replicated":{"Replicas":3},"Global":{}`, []string{"replicas"}, false},
		{"empty allowed", "", "", nil, false},
		{"unsupported semantic field", "", "", []string{"container.env"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := original
			if tc.from != "" {
				body = strings.Replace(body, tc.from, tc.to, 1)
			}
			err := Validate(current, []byte(body), tc.allowed)
			assert.Equal(t, tc.allow, err == nil)
			var unchanged swarm.ServiceSpec
			require.NoError(t, json.Unmarshal([]byte(original), &unchanged))
			assert.Equal(t, unchanged, current, "validation must not mutate current state")
		})
	}
}

func TestMultipleChanges(t *testing.T) {
	var current swarm.ServiceSpec
	require.NoError(t, json.Unmarshal([]byte(original), &current))
	for _, tc := range []struct {
		name    string
		allowed []string
		allow   bool
	}{
		{"secrets only", []string{"container.secrets"}, false},
		{"image only", []string{"container.image"}, false},
		{"both explicit", []string{"container.secrets", "container.image"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.ReplaceAll(strings.ReplaceAll(original, "image:v1", "image:v2"), `"old"`, `"new"`)
			assert.Equal(t, tc.allow, Validate(current, []byte(body), tc.allowed) == nil)
		})
	}
	for _, body := range []string{"", "null", "[]", "{} {}", original + " true", strings.Replace(original, `"Replicas":2`, `"Replicas":2.5`, 1), strings.Replace(original, `"Replicas":2`, `"Replicas":18446744073709551616`, 1)} {
		t.Run(body[:min(30, len(body))], func(t *testing.T) { require.Error(t, Validate(current, []byte(body), []string{"container.secrets"})) })
	}
}

func TestTypedComparisonPreservesEmptyCollections(t *testing.T) {
	a := swarm.ServiceSpec{TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{}}}
	b := swarm.ServiceSpec{TaskTemplate: swarm.TaskSpec{ContainerSpec: &swarm.ContainerSpec{Mounts: nil}}}
	assert.True(t, equalSpec(a, b))
	b.TaskTemplate.ContainerSpec.Env = []string{}
	assert.False(t, equalSpec(a, b))
}
