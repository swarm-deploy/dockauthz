// Package config loads a single, bounded, strict administrative policy document.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/swarm-deploy/dockauthz/internal/operation"
	"gopkg.in/yaml.v3"
)

const MaxSize = 1 << 20
const DefaultPath = "/etc/dockauthz/config.yaml"

type Config struct {
	// Authentication defines the mandatory unauthenticated-request policy.
	Authentication Authentication `yaml:"authentication"`
	// Telemetry optionally enables OTLP export.
	Telemetry *Telemetry `yaml:"telemetry"`
	// Clients maps administrative names to identities and independent permissions.
	Clients map[string]Client `yaml:"clients"`
}
type Authentication struct {
	// Unidentified must explicitly be allow or deny.
	Unidentified string `yaml:"unidentified"`
}
type Client struct {
	// Identity names the Docker-authenticated certificate identity.
	Identity Identity `yaml:"identity"`
	// Permissions is indexed by resource, then action.
	Permissions map[string]map[string]Permission `yaml:"permissions"`
}
type Identity struct {
	// Certificate matches the leaf certificate supplied by Docker.
	Certificate Certificate `yaml:"certificate"`
}
type Certificate struct {
	// CommonName is unique across configured clients.
	CommonName string `yaml:"commonName"`
}
type Permission struct {
	// Selector requires labels on the existing resource.
	Selector *Labels `yaml:"selector"`
	// Request requires labels on the submitted resource spec.
	Request *Labels `yaml:"request"`
	// Mutation limits service updates to named semantic subtrees.
	Mutation *Mutation `yaml:"mutation"`
}
type Labels struct {
	// Labels contains required exact key/value pairs; extra labels are allowed.
	Labels map[string]string `yaml:"labels"`
}
type Mutation struct {
	// Only is a nonempty list of supported semantic fields.
	Only []string `yaml:"only"`
}
type Telemetry struct {
	// ServiceName defaults to dockauthz.
	ServiceName string `yaml:"serviceName"`
	// Resource adds bounded, administratively configured resource attributes.
	Resource map[string]string `yaml:"resource"`
	// OTLP configures the exporter transport.
	OTLP OTLP `yaml:"otlp"`
	// Traces configures batch trace export.
	Traces Traces `yaml:"traces"`
	// Metrics configures periodic metric export.
	Metrics Metrics `yaml:"metrics"`
}
type OTLP struct {
	// Endpoint is an explicit host:port, without a URL scheme or path.
	Endpoint string `yaml:"endpoint"`
	// Protocol is grpc or http; required when either signal is enabled.
	Protocol string `yaml:"protocol"`
	// Insecure uses plaintext transport; false verifies TLS with system roots.
	Insecure bool `yaml:"insecure"`
	// Headers are read from the mounted config and must never be logged.
	Headers map[string]string `yaml:"headers"`
}
type Traces struct {
	// Enabled creates an OTLP trace exporter when true.
	Enabled bool `yaml:"enabled"`
	// SampleRatio is in [0,1], defaulting to 1 when omitted.
	SampleRatio *float64 `yaml:"sampleRatio"`
}
type Metrics struct {
	// Enabled creates an OTLP metric exporter when true.
	Enabled bool `yaml:"enabled"`
	// ExportInterval is a positive Go duration, defaulting to 30s.
	ExportInterval string `yaml:"exportInterval"`
}

// Unconditional reports whether this permission has no constraints.
func (p Permission) Unconditional() bool {
	return p.Selector == nil && p.Request == nil && p.Mutation == nil
}

// Load opens a local file once; policy is never reloaded implicitly.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open config file")
	}
	defer f.Close()
	return Parse(f)
}

// Parse enforces the byte limit before any YAML processing.
func Parse(r io.Reader) (*Config, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
	if err != nil || len(data) > MaxSize {
		return nil, errors.New("cannot read config or config exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err = d.Decode(&node); err != nil {
		return nil, errors.New("invalid YAML configuration")
	}
	if err = validateNode(&node); err != nil {
		return nil, err
	}
	if err = validateScalarTypes(&node, ""); err != nil {
		return nil, err
	}
	if d.Decode(new(yaml.Node)) != io.EOF {
		return nil, errors.New("exactly one YAML document is required")
	}
	d = yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	var cfg Config
	if err = d.Decode(&cfg); err != nil {
		return nil, errors.New("invalid configuration schema (unknown, duplicate or mistyped field)")
	}
	if err = cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateNode(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode || n.Style&yaml.TaggedStyle != 0 {
		return errors.New("YAML anchors, aliases and explicit tags are forbidden")
	}
	if n.Tag == "!!null" {
		return errors.New("null configuration values are forbidden; use explicit mappings")
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Tag != "!!str" {
				return errors.New("configuration keys must be strings")
			}
		}
	}
	for _, child := range n.Content {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}

// yaml.v3 otherwise coerces some booleans and numbers into string fields.
// Require the documented scalar types, including quoted string label values.
func validateScalarTypes(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if err := validateScalarTypes(child, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			childPath := n.Content[i].Value
			if path != "" {
				childPath = path + "." + childPath
			}
			if err := validateScalarTypes(n.Content[i+1], childPath); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		expected := "!!str"
		switch path {
		case "telemetry.otlp.insecure", "telemetry.traces.enabled", "telemetry.metrics.enabled":
			expected = "!!bool"
		case "telemetry.traces.sampleRatio":
			if n.Tag == "!!float" || n.Tag == "!!int" {
				return nil
			}
			expected = "!!float"
		}
		if n.Tag != expected {
			return errors.New("configuration scalar has the wrong YAML type")
		}
	}
	return nil
}

// Validate also applies only the documented, non-authorization telemetry defaults.
func (c *Config) Validate() error {
	if c.Authentication.Unidentified != "allow" && c.Authentication.Unidentified != "deny" {
		return errors.New("authentication.unidentified must explicitly be allow or deny")
	}
	cns := make(map[string]bool)
	for name, client := range c.Clients {
		cn := client.Identity.Certificate.CommonName
		if strings.TrimSpace(name) == "" || strings.TrimSpace(cn) == "" || cns[cn] {
			return errors.New("client names and certificate CNs must be nonempty; certificate CNs must be unique")
		}
		if name == "unknown" || name == "unidentified" || name == "internal" {
			return errors.New("client name is reserved for audit attribution")
		}
		cns[cn] = true
		for resource, actions := range client.Permissions {
			if resource != "*" && !operation.Supports(operation.Resource(resource), operation.ActionInspect) {
				return errors.New("unsupported permission resource")
			}
			for action, permission := range actions {
				if action == "*" {
					if !permission.Unconditional() {
						return errors.New("wildcard actions cannot have constraints")
					}
					continue
				}
				resources := []string{resource}
				if resource == "*" {
					resources = nil
					for _, candidate := range []string{"service", "secret", "task", "node"} {
						if operation.Supports(operation.Resource(candidate), operation.Action(action)) {
							resources = append(resources, candidate)
						}
					}
				}
				if len(resources) == 0 {
					return errors.New("unsupported permission action")
				}
				for _, actual := range resources {
					if !operation.Supports(operation.Resource(actual), operation.Action(action)) {
						return errors.New("unsupported permission action for resource")
					}
					if permission.Selector != nil && action != "inspect" && action != "update" && action != "delete" {
						return errors.New("selector requires an existing individual resource")
					}
					if permission.Request != nil && action != "create" && action != "update" {
						return errors.New("request requires create or update")
					}
					if permission.Mutation != nil && (actual != "service" || action != "update") {
						return errors.New("mutation is supported only for service.update")
					}
				}
				for _, labels := range []*Labels{permission.Selector, permission.Request} {
					if labels != nil && len(labels.Labels) == 0 {
						return errors.New("label constraints must be nonempty")
					}
				}
				if permission.Mutation != nil {
					if len(permission.Mutation.Only) == 0 {
						return errors.New("mutation.only must be nonempty")
					}
					seen := make(map[string]bool)
					for _, field := range permission.Mutation.Only {
						if (field != "container.secrets" && field != "container.image" && field != "replicas") || seen[field] {
							return errors.New("unsupported or duplicate mutation field")
						}
						seen[field] = true
					}
				}
			}
		}
	}
	if c.Telemetry != nil {
		return c.Telemetry.Validate()
	}
	return nil
}

// Validate rejects transport mistakes without trying to contact the collector.
func (t *Telemetry) Validate() error {
	if t.ServiceName == "" {
		t.ServiceName = "dockauthz"
	}
	if _, exists := t.Resource["service.name"]; exists {
		return errors.New("telemetry.resource cannot override service.name")
	}
	if _, exists := t.Resource["service.version"]; exists {
		return errors.New("telemetry.resource cannot override service.version")
	}
	if t.Traces.SampleRatio == nil {
		ratio := 1.0
		t.Traces.SampleRatio = &ratio
	}
	if math.IsNaN(*t.Traces.SampleRatio) || math.IsInf(*t.Traces.SampleRatio, 0) || *t.Traces.SampleRatio < 0 || *t.Traces.SampleRatio > 1 {
		return errors.New("telemetry sampleRatio must be between 0 and 1")
	}
	if t.Metrics.ExportInterval == "" {
		t.Metrics.ExportInterval = "30s"
	}
	interval, err := time.ParseDuration(t.Metrics.ExportInterval)
	if err != nil || interval <= 0 {
		return errors.New("telemetry exportInterval must be a positive duration")
	}
	if t.OTLP.Protocol != "" && t.OTLP.Protocol != "grpc" && t.OTLP.Protocol != "http" {
		return errors.New("telemetry protocol must be grpc or http")
	}
	if t.Traces.Enabled || t.Metrics.Enabled {
		if t.OTLP.Endpoint == "" || t.OTLP.Protocol == "" {
			return errors.New("enabled telemetry requires explicit OTLP endpoint and protocol")
		}
	}
	if t.OTLP.Endpoint != "" {
		host, port, err := net.SplitHostPort(t.OTLP.Endpoint)
		n, parseErr := strconv.Atoi(port)
		if err != nil || parseErr != nil || host == "" || n < 1 || n > 65535 || strings.ContainsAny(host, "/@?# \r\n\t") {
			return errors.New("telemetry endpoint must be host:port")
		}
	}
	for key, value := range t.OTLP.Headers {
		if key == "" || strings.ToLower(key) != key {
			return errors.New("OTLP header names must be lowercase")
		}
		for _, c := range key {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-_.", c) {
				return errors.New("invalid OTLP header name")
			}
		}
		for _, c := range value {
			if c < 32 || c > 126 {
				return fmt.Errorf("invalid OTLP header value")
			}
		}
	}
	return nil
}
