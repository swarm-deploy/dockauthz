# Configuration

```yaml
authentication:
  unidentified: allow

telemetry:
  serviceName: dockauthz
  resource:
    environment: production
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

clients:
  admin:
    identity:
      certificate:
        commonName: docker-admin
    permissions:
      "*":
        "*": {}

  cloud-secrets:
    identity:
      certificate:
        commonName: cloud-secrets
    permissions:
      service:
        list: {}
        inspect: {}
        update:
          mutation:
            only: [container.secrets]
      secret:
        list: {}
        inspect: {}
        create:
          request:
            labels:
              org.cloud-secrets.managed: "true"
        delete:
          selector:
            labels:
              org.cloud-secrets.managed: "true"

  ci:
    identity:
      certificate:
        commonName: github-ci
    permissions:
      service:
        list: {}
        inspect: {}
        update:
          mutation:
            only: [container.image]

  autoscaler:
    identity:
      certificate:
        commonName: autoscaler
    permissions:
      service:
        list: {}
        inspect: {}
        update:
          mutation:
            only: [replicas]

  monitoring:
    identity:
      certificate:
        commonName: monitoring
    permissions:
      service:
        list: {}
        inspect: {}
      node:
        list: {}
        inspect: {}
      task:
        list: {}
        inspect: {}
```

Requires **Docker Engine >= 29.3.1**. The configuration is read once from `/etc/dockauthz/config.yaml`; override with `dockauthz --config /path/to/config.yaml`. Keep the file root-owned and writable only by root. It can contain sensitive OTLP headers and should usually be mode 0600.

## File format and schema

One local YAML mapping, maximum **1 MiB** before parsing. Only `authentication`, `telemetry`, `clients` are accepted at the root. Unknown fields, duplicate properties, mistyped values, null values, anchors, aliases, explicit tags and multiple documents are errors. String-valued fields require strings: quote label values such as `"true"` and `"123"`. No `version` field, includes, environment interpolation, templating, remote loading, policy editing API or hot reload exists. `${NAME}` in a string is literal text. Any configuration error prevents startup with a nonzero exit status.

| Field | Type and behavior |
| --- | --- |
| `authentication.unidentified` | Required string, exactly `allow` or `deny`; no default |
| `clients` | Mapping from logical names to clients; empty/omitted grants no authenticated clients access |
| `clients.<name>.identity.certificate.commonName` | Required nonempty string, unique across clients |
| `clients.<name>.permissions` | Resource → action → constraint mapping; empty/omitted grants nothing |
| `permissions.<resource>.<action>.selector.labels` | Nonempty string-to-string map matched against the existing resource |
| `permissions.<resource>.<action>.request.labels` | Nonempty string-to-string map matched against the submitted spec |
| `permissions.service.update.mutation.only` | Nonempty sequence of supported semantic field strings, no duplicates |
| `telemetry` | Optional mapping; omission creates no OTLP exporters |
| `telemetry.serviceName` | String; default `dockauthz` |
| `telemetry.resource` | String-to-string attributes; cannot override `service.name` or `service.version` |
| `telemetry.otlp.endpoint` | Explicit `host:port`, no scheme/path; required when a signal is enabled |
| `telemetry.otlp.protocol` | `grpc` or `http`; required when a signal is enabled |
| `telemetry.otlp.insecure` | Boolean; default false (verified TLS); true selects plaintext |
| `telemetry.otlp.headers` | String-to-string map; lowercase names, printable ASCII values; never logged |
| `telemetry.traces.enabled` | Boolean; default false |
| `telemetry.traces.sampleRatio` | Finite number in `[0,1]`; default 1.0, including explicit support for zero |
| `telemetry.metrics.enabled` | Boolean; default false |
| `telemetry.metrics.exportInterval` | Positive Go duration string, e.g. `15s`; default `30s` |

Client names `unidentified`, `unknown` and `internal` are reserved for audit attribution. There are no roles, subjects, explicit deny rules or implicit authorization grants.

## Authentication

Docker performs mTLS authentication. dockauthz requires TLS authentication context and reads the **leaf** certificate's common name from `RequestPeerCertificates[0]`. The logical client key need not equal the CN. HTTP headers do not establish identity; contradictory `User`/certificate data, certificates without TLS context, or TLS context without a leaf certificate are denied.

`unidentified != unknown authenticated client`:

| Request identity | Result |
| --- | --- |
| No authentication context, certificate or user | Apply `authentication.unidentified` |
| TLS leaf matching a configured CN | Evaluate that client's permissions |
| Authenticated but unknown CN | DENY, including when `unidentified: allow` |
| Incomplete/ambiguous authentication context | DENY |

`unidentified: allow` is useful for ordinary local Docker CLI requests over the Unix socket. It is an explicit grant for **all** requests without authenticated identity, so do not expose an unauthenticated daemon TCP port. `deny` requires clients to use authenticated identities. Internal token requests are evaluated first and never fall back to this setting.

## Resources and actions

| Resource | Actions |
| --- | --- |
| `service` | `list`, `inspect`, `create`, `update`, `delete` |
| `secret` | `list`, `inspect`, `create`, `delete` |
| `task` | `list`, `inspect` |
| `node` | `list`, `inspect` |

The resolver handles both `/v1.53/services/abc/update?version=42` and `/services/abc/update?version=42`, matching exact HTTP methods and route shapes. Encoded path components, repeated/trailing slashes, dot segments, fragments and malformed query syntax are rejected. The state client requests the same API version as the caller; no daemon negotiation happens on the authorization path.

List permission permits the whole list. `selector` cannot filter list results and is rejected on `list` and `create`. `request` is valid on `create` and `update` only. `mutation` is valid on `service.update` only. A rejected or unavailable resource lookup denies the constrained permission.

## Labels: selector and request

`selector.labels` checks existing-resource labels through an internal inspect. It is supported on individual inspect operations, service updates, and service/secret deletes. Task selectors inspect the task's own labels. State-bound requests must identify the **full canonical Docker resource ID**, not a name or abbreviated ID.

`request.labels` checks the incoming service/secret spec. For example, the full configuration allows creating a secret only if its submitted `SecretSpec.Labels` includes `org.cloud-secrets.managed: "true"`. Missing bodies, invalid JSON, unexpected fields and missing labels deny the request. Secret `Data` is decoded but never logged or exported.

All specified labels must exist with exactly matching values. Extra labels are allowed. An absent label never matches a required empty string. Nonempty constraint maps are required to avoid an accidental empty selector.

Constraints in **one** permission are ANDed: when `selector`, `request` and `mutation` coexist, all must pass. Different permissions are independent alternatives; partial matches are never combined. Selectors observe state at authorization time. Docker service version checks protect updates against intervening changes; delete APIs have no conditional version parameter, so administrative concurrent relabeling should be coordinated.

## Service mutation

| Public semantic field | Permitted subtree |
| --- | --- |
| `container.secrets` | The container's complete secret-reference list and file targets |
| `container.image` | The container image string; registry authentication accompanying an image update is permitted |
| `replicas` | Replica count on an existing replicated service; mode changes and job counts are not permitted |

Multiple fields can be explicitly listed in a single permission. A request must provide the full desired Docker `ServiceSpec`, not a JSON merge patch. Start from inspect output and preserve all other fields.

The plugin strictly decodes current and requested specs using `encoding/json` and Moby types. It makes a fresh copy of the request, replaces only permitted fields with current values and compares the complete typed object. It preserves nil/empty distinctions. Unknown fields, additions outside the permitted subtrees and unexpected parent structures deny the operation. This can conservatively deny an update that Docker would normalize; inspect/rebuild the complete request instead of weakening the permission.

Constrained service updates require exactly one numeric `version` parameter. When state is inspected, it must equal `Version.Index`. `registryAuthFrom=spec` is the only other accepted query option. Rollback, `registryAuthFrom=previous-spec`, duplicate/unknown options and `X-Registry-Auth` on mutation grants without `container.image` are denied because they can change state outside the checked body.

## Wildcards and examples

Full administrator, including Docker endpoints the resolver does not support:

```yaml
permissions:
  "*":
    "*": {}
```

All supported service actions:

```yaml
permissions:
  service:
    "*": {}
```

Read-only access to every supported resource:

```yaml
permissions:
  "*":
    list: {}
    inspect: {}
```

A wildcard **action** must have `{}`; adding any constraints is a startup error. Resource wildcards with concrete actions may carry constraints if those constraints apply to every supported resource for that action. `"*" / update` currently refers only to service updates.

The complete example at the top includes cloud-secrets, a CI image updater and an autoscaler. Their grants remain independent: a secrets permission and a separate image permission cannot jointly authorize a request changing both.

## Internal inspection

At startup the process generates a 256-bit token stored only in memory. The dedicated Unix-socket client attaches `X-Dockauthz-Internal-Token` to inspect requests. Constant-time token comparison happens before public identity checks. A valid token authorizes only `GET /services/{id}`, `/secrets/{id}`, `/tasks/{id}` and `/nodes/{id}` (with optional API version prefix and no query parameters). Invalid/duplicate token headers, list operations and all writes are denied. No token is persisted, logged or exported. Inspect calls have a five-second timeout and an 8 MiB response limit; AuthZ envelopes have a 16 MiB limit.
