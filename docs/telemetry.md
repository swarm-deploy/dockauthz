# OpenTelemetry

Telemetry is optional. Omit the `telemetry` section to create no OTLP exporters; authorization and JSON audit logging continue normally. Requires Docker Engine >= 29.3.1 for the AuthZ security boundary, independently of telemetry.

## Enable OTLP

OTLP/gRPC:

```yaml
telemetry:
  serviceName: dockauthz
  resource:
    environment: production
    cluster: swarm-prod
  otlp:
    endpoint: infra-otel-collector:4317
    protocol: grpc
    insecure: true
    headers:
      x-tenant-id: docker-infra
  traces:
    enabled: true
    sampleRatio: 1.0
  metrics:
    enabled: true
    exportInterval: 15s
```

OTLP/HTTP (protobuf) uses the same schema:

```yaml
telemetry:
  otlp:
    endpoint: collector.example.com:4318
    protocol: http
    insecure: false
  traces:
    enabled: true
    sampleRatio: 0.1
  metrics:
    enabled: true
```

`endpoint` is always an explicit `host:port` (IPv6: `[address]:port`), without scheme or path. There is no default endpoint. HTTP exporters use `/v1/traces` and `/v1/metrics`. `protocol` is mandatory whenever traces or metrics are enabled. Defaults: `serviceName=dockauthz`, trace sampling ratio `1.0`, metric interval `30s`; signals default to disabled.

`insecure: true` means **plaintext**, not TLS with skipped verification. The default false enables TLS >= 1.2, verifies the collector hostname and uses system trust roots. The managed rootfs includes a trust bundle; build with `CA_BUNDLE=/path/to/company-roots.pem` for an internal CA. Exporters use the official OpenTelemetry Go SDK; see [the upstream exporter documentation](https://opentelemetry.io/docs/languages/go/exporters/).

Custom `headers` apply to both signals. Names must be lowercase; values must be printable ASCII. Store authentication headers in the mounted root-owned config file, never command-line arguments or logs. Header values are never placed in attributes or diagnostics.

Trace sampling is parent-based: the configured ratio applies to root spans; a valid parent sampling decision is honored. Sampling and baggage never affect authorization. Configure collector retention/access policies for audit metadata.

## Resources and propagation

Every exported resource includes `service.name` (the configured service name) and `service.version` (build version, default `dev`). Build with `make VERSION=v0.1.0` to set the version. Custom `resource` values are string attributes; `service.name` and `service.version` cannot be overridden through that map. Set a stable `service.instance.id` there if your deployment supplies one.

The global propagator combines W3C TraceContext and Baggage. A valid `traceparent` on the incoming AuthZ HTTP envelope is extracted. If none exists, the original Docker request's forwarded headers may supply context. The internal state client injects trace context into Docker inspect headers, linking the recursive AuthZ callback to the same trace. Baggage is never read by policy evaluation and is not automatically copied into telemetry attributes.

## Spans and logs

Span names are fixed:

```text
dockauthz.authorize
  └─ dockauthz.policy.evaluate
       ├─ dockauthz.docker.inspect
       │    └─ dockauthz.authorize (internal callback, when propagation is preserved)
       └─ dockauthz.mutation.validate
```

Span names contain no client names, resource IDs or paths. Authorization attributes are `dockauthz.client`, `dockauthz.identity.auth_method`, `dockauthz.resource`, `dockauthz.action`, `dockauthz.decision` and `dockauthz.reason`. Mutation spans contain `dockauthz.mutation.allowed_fields`, using only public names such as `container.image`; field values are excluded. The implementation deliberately does not claim an exhaustive changed-field list on failed mutations.

JSON audit records contain `client`, `identity`, `resource`, `resource_id`, `action`, `decision`, `reason`. A valid active span adds `trace_id` and `span_id`. Unknown identities use `client=unknown`; their certificate CN is audit metadata, never a metric dimension. No OpenTelemetry Logs SDK is required.

## Metrics

| Instrument | Type | Attributes |
| --- | --- | --- |
| `dockauthz_authorization_decisions_total` | Counter | `decision`, `resource`, `action`, `client` |
| `dockauthz_authorization_errors_total` | Counter | `type=config\|resolver\|docker_lookup\|policy\|mutation\|internal` |
| `dockauthz_authorization_duration_seconds` | Histogram, seconds | `decision`, `resource`, `action` |
| `dockauthz_docker_lookup_duration_seconds` | Histogram, seconds | `resource` |
| `dockauthz_docker_lookups_total` | Counter | `resource`, `result=success\|error` |
| `dockauthz_internal_requests_total` | Counter | `decision` |

Decision values are `allow`/`deny`; unresolved resources/actions are `unknown`. Client labels are limited to configured names and `unidentified`, `unknown`, `internal`. No metric includes resource IDs, certificate identities or raw paths. Invalid configuration fails before exporters start, so its diagnostic is a startup log rather than a guaranteed exported `type=config` metric.

## Failure and shutdown behavior

Syntactically invalid telemetry configuration prevents startup. A valid configuration with an unavailable collector starts normally. Trace export uses a bounded, nonblocking batch queue; metric export is periodic. Exporter calls never run synchronously on the authorization path. Queue saturation can drop spans. Exporter failures are reported through a redacted, rate-limited JSON error, at most once per minute per process. Setup failure of an exporter disables that signal and emits the same safe diagnostic; it cannot change a policy result.

On SIGTERM/SIGINT, the helper's HTTP server stops accepting connections and drains active requests with a ten-second bound. The process then shuts down both telemetry providers with an eight-second total deadline. Export calls have a three-second timeout. Collector outages or shutdown export errors cannot turn ALLOW into DENY or DENY into ALLOW, and cannot block shutdown indefinitely.

The packaged plugin requests bridge networking for outbound collector connections, without host networking or extra Linux capabilities. Use a collector address reachable and resolvable from that network. A Swarm service name such as `infra-otel-collector` in an example is not automatically resolvable in a managed plugin's bridge network; use published collector ports and infrastructure DNS/routable addresses. Build the plugin with `Network.Type=none` when no network export is needed.

## Collector example

Save as `collector.yaml` on your collector host:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch: {}

exporters:
  debug:
    verbosity: basic

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
```

Run a reviewed/pinned `otel/opentelemetry-collector` image with this file mounted at `/etc/otelcol/config.yaml`, publish 4317/4318 on the intended management address, and point dockauthz to that address with `insecure: true` for this plaintext example. For production, configure receiver TLS and use `insecure: false`. Replace the debug exporter with your telemetry backend. Protect collector ports with network access controls.

## Security

**Never put secrets, certificate private material, request bodies or internal authorization tokens into OpenTelemetry attributes, logs or metrics.** This also applies to custom resource attributes you configure yourself.

The implementation never exports request/response bodies, `SecretSpec.Data`, environment values, registry credentials, private keys, full certificate DER, internal token values or OTLP authentication headers. Diagnostics from Docker, JSON parsing and exporters are redacted so a remote error cannot echo those values into logs. Trace/span correlation and telemetry are observability only; authorization depends solely on Docker's authentication context, operation, resource state and configured permissions.
