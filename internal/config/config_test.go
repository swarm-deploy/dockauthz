package config

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	const base = "authentication: {unidentified: deny}\nclients: {}\n"
	cases := []struct {
		name, input string
		valid       bool
	}{
		{"minimal", base, true},
		{"missing unidentified", "authentication: {}", false},
		{"invalid unidentified", "authentication: {unidentified: maybe}", false},
		{"unknown root", base + "version: 1\n", false},
		{"unknown nested", "authentication: {unidentified: deny, typo: true}", false},
		{"multiple docs", base + "---\n" + base, false},
		{"trailing empty doc", base + "---\n", false},
		{"anchor", "authentication: &auth {unidentified: deny}", false},
		{"alias", "authentication: &auth {unidentified: deny}\nclients: *auth", false},
		{"custom tag", "authentication: !custom {unidentified: deny}", false},
		{"explicit builtin tag", "authentication: {unidentified: !!str deny}", false},
		{"oversize", base + strings.Repeat(" ", MaxSize), false},
		{"duplicates", "authentication: {unidentified: deny, unidentified: allow}", false},
		{"null permission", "authentication: {unidentified: deny}\nclients: {one: {identity: {certificate: {commonName: one}}, permissions: {service: {update: null}}}}", false},
		{"duplicate CN", "authentication: {unidentified: deny}\nclients: {one: {identity: {certificate: {commonName: same}}}, two: {identity: {certificate: {commonName: same}}}}", false},
		{"reserved client", "authentication: {unidentified: deny}\nclients: {unknown: {identity: {certificate: {commonName: same}}}}", false},
		{"missing CN", "authentication: {unidentified: deny}\nclients: {one: {}}", false},
		{"bad protocol", base + "telemetry: {otlp: {protocol: udp}}", false},
		{"traces missing endpoint", base + "telemetry: {traces: {enabled: true}}", false},
		{"metrics missing endpoint", base + "telemetry: {metrics: {enabled: true}}", false},
		{"missing protocol", base + "telemetry: {traces: {enabled: true}, otlp: {endpoint: 'localhost:4317'}}", false},
		{"ratio high", base + "telemetry: {traces: {sampleRatio: 1.1}}", false},
		{"ratio negative", base + "telemetry: {traces: {sampleRatio: -0.1}}", false},
		{"ratio nan", base + "telemetry: {traces: {sampleRatio: .nan}}", false},
		{"ratio zero", base + "telemetry: {traces: {sampleRatio: 0}}", true},
		{"string ratio", base + "telemetry: {traces: {sampleRatio: '0.5'}}", false},
		{"string boolean", base + "telemetry: {traces: {enabled: 'true'}}", false},
		{"numeric service name", base + "telemetry: {serviceName: 123}", false},
		{"interval invalid", base + "telemetry: {metrics: {exportInterval: banana}}", false},
		{"interval zero", base + "telemetry: {metrics: {exportInterval: 0s}}", false},
		{"interval negative", base + "telemetry: {metrics: {exportInterval: -1s}}", false},
		{"resource override", base + "telemetry: {resource: {service.name: other}}", false},
		{"endpoint URL", base + "telemetry: {otlp: {endpoint: 'https://localhost:4317'}}", false},
		{"invalid endpoint port", base + "telemetry: {otlp: {endpoint: 'localhost:0'}}", false},
		{"grpc", base + "telemetry: {traces: {enabled: true}, otlp: {endpoint: 'localhost:4317', protocol: grpc}}", true},
		{"http", base + "telemetry: {metrics: {enabled: true}, otlp: {endpoint: 'localhost:4318', protocol: http}}", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(strings.NewReader(tc.input))
			if tc.valid {
				require.NoError(t, err)
				require.NotNil(t, cfg)
			} else {
				require.Error(t, err)
				assert.Nil(t, cfg)
			}
		})
	}
}

func TestPermissionValidation(t *testing.T) {
	cases := []struct {
		name, permissions string
		valid             bool
	}{
		{"full admin", `{"*": {"*": {}}}`, true},
		{"resource wildcard", `{"*": {list: {}, inspect: {}}}`, true},
		{"action wildcard", `{service: {"*": {}}}`, true},
		{"constrained wildcard action", `{service: {"*": {mutation: {only: [container.image]}}}}`, false},
		{"unknown resource", `{container: {list: {}}}`, false},
		{"unknown action", `{service: {start: {}}}`, false},
		{"unsupported pair", `{node: {update: {}}}`, false},
		{"unknown mutation", `{service: {update: {mutation: {only: [container.env]}}}}`, false},
		{"empty mutation", `{service: {update: {mutation: {only: []}}}}`, false},
		{"duplicate mutation", `{service: {update: {mutation: {only: [replicas, replicas]}}}}`, false},
		{"wrong mutation action", `{service: {create: {mutation: {only: [replicas]}}}}`, false},
		{"selector on list", `{secret: {list: {selector: {labels: {managed: "true"}}}}}`, false},
		{"request on delete", `{secret: {delete: {request: {labels: {managed: "true"}}}}}`, false},
		{"empty selector", `{secret: {delete: {selector: {}}}}`, false},
		{"boolean label", `{secret: {delete: {selector: {labels: {managed: true}}}}}`, false},
		{"constrained resource wildcard", `{"*": {create: {request: {labels: {managed: "true"}}}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader("authentication: {unidentified: deny}\nclients:\n  one:\n    identity: {certificate: {commonName: cert}}\n    permissions: " + tc.permissions))
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestExampleAndDefaults(t *testing.T) {
	f, err := os.Open("../../examples/config.yaml")
	require.NoError(t, err)
	defer f.Close()
	cfg, err := Parse(f)
	require.NoError(t, err)
	assert.Len(t, cfg.Clients, 5)
	cfg, err = Parse(strings.NewReader("authentication: {unidentified: deny}\ntelemetry: {}"))
	require.NoError(t, err)
	assert.Equal(t, "dockauthz", cfg.Telemetry.ServiceName)
	assert.Equal(t, 1.0, *cfg.Telemetry.Traces.SampleRatio)
	assert.Equal(t, "30s", cfg.Telemetry.Metrics.ExportInterval)
}
