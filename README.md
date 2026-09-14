# dockauthz

dockauthz is a state-aware authorization plugin for Docker Engine. It uses Docker mTLS identities and a small, client-centric, allow-only policy engine.

```yaml
authentication:
  unidentified: deny

clients:
  cloud-secrets:
    identity:
      certificate:
        commonName: cloud-secrets
    permissions:
      service:
        update:
          mutation:
            only:
              - container.secrets
```

An endpoint-only permission for `POST /services/{id}/update` also permits changes to the image, command, environment, mounts and replica count. dockauthz inspects the current service, substitutes the permitted subtree in a fresh copy of the requested `ServiceSpec`, and compares the entire spec. The policy above permits changes confined to secrets. CI can receive `container.image`; an autoscaler can receive `replicas`.

## Requirements

- **Docker Engine >= 29.3.1**, on a Linux Swarm manager for Swarm resource operations. [Docker's release notes](https://docs.docker.com/engine/release-notes/29/) document the fix for CVE-2026-34040, an AuthZ request-body bypass. dockauthz does not probe daemon versions on each request.
- Go >= 1.26.3 to build. Docker/Moby API types and official OpenTelemetry Go packages are pinned in `go.mod`.
- Administrative access to install/configure the plugin and mTLS. State-dependent operations need the manager's local Docker Unix socket.

## Build and install

```sh
make test
make vet
make build
make plugin-package
```

This creates `bin/dockauthz`, `bin/dockauthz-cert`, `plugin/rootfs/` and a portable build context in `dist/dockauthz-plugin-linux-<arch>.tar.gz`. Set `GOARCH=arm64` for an ARM manager. `CA_BUNDLE=/path/to/ca-bundle.pem` selects the system/organizational roots included for OTLP TLS. The rootfs contains a static Linux binary; it needs no shell or OpenSSL.

On each target manager, review [examples/config.yaml](examples/config.yaml), adjust identities and collector address (or omit `telemetry`), then install the root-owned policy:

```sh
sudo install -d -m 0755 /etc/dockauthz
sudo install -o root -g root -m 0600 examples/config.yaml /etc/dockauthz/config.yaml
make plugin-create PLUGIN_NAME=dockauthz:dev
docker plugin enable dockauthz:dev
```

`plugin-create` creates a local managed plugin without publishing it. To use a previously generated build context, extract its archive and run `docker plugin create dockauthz:dev ./extracted-context`. Merge the following into `/etc/docker/daemon.json`, alongside the mTLS settings from [docs/certificates.md](docs/certificates.md):

```json
{"authorization-plugins": ["dockauthz:dev"]}
```

Restart Docker through your host's service manager. Bootstrap the plugin and test an administrator certificate before enabling `unidentified: deny`. Distribute the same reviewed configuration to each manager. Configuration loads once at startup; changes require a controlled plugin/daemon restart.

The managed plugin requests a read-only configuration mount, a Docker socket mount and bridge networking for OTLP egress. It requests no Linux capabilities or devices. The socket mount's `ro` flag does **not** turn Docker's API into a read-only API: the process is privileged by possession of that socket. Its internal client only issues inspect requests, carrying a random in-memory token that authorizes only inspect callbacks. For deployments without telemetry, change `Network.Type` to `none` before creating the package.

## Behavior and limits

- Supported resources: `service` (list, inspect, create, update, delete), `secret` (list, inspect, create, delete), `task` and `node` (list, inspect).
- A full `"*" / "*"` administrator can use every Docker endpoint, including unrecognized endpoints. Other clients receive DENY for unrecognized operations. List/inspect permissions return whole resources; there is no response redaction or per-item list filtering.
- Docker CLI commands can make preliminary `/_ping`, `/version` or other requests beyond the listed operations. These endpoints are deliberately unavailable to restricted clients in v0.1. Use API clients with an explicit API version and no automatic negotiation; the administrator CLI works normally.
- Existing-resource constraints require **full canonical IDs**, not names or abbreviated IDs. Mutation checks require `?version=<inspected Version.Index>`. Concurrent service changes cause DENY or Docker's version conflict; re-inspect and retry.
- Unknown JSON spec fields, nil/empty differences, unavailable state and ambiguous identities fail closed. Future Docker API additions can require a dockauthz update. State lookup uses the caller's API version and has a five-second timeout.
- Constrained service updates reject rollback, unknown/repeated query options and `registryAuthFrom=previous-spec`. Registry credentials are allowed for `container.image` grants; other mutation grants reject `X-Registry-Auth`.
- `AuthZReq` authorizes once. `AuthZRes` allows the response, without checking changed state again.

## Security boundary

The plugin is a trusted privileged component. Compromising it compromises this boundary. Modifying `/etc/dockauthz/config.yaml` is equivalent to modifying authorization policy: the file must belong to root and be writable only by root. Docker TLS client private keys grant access as the corresponding configured identity. `unidentified: allow` explicitly trusts unauthenticated access, including local socket access; do not expose an unauthenticated TCP listener.

Telemetry is an observability subsystem and does not participate in authorization decisions. No bodies, secret values, private keys, certificate DER or internal token values are exported or logged. All authorization decisions produce JSON audit records with trace/span IDs when available.

Docker's AuthZ boundary covers the HTTP API; see [Docker's authorization documentation](https://docs.docker.com/engine/extend/plugins_authorization/) for streaming, upgrade and gRPC limitations. Restrict access to the daemon, plugin socket, host and manager credentials accordingly.

## Documentation and development

- [Configuration and policy schema](docs/configuration.md)
- [CA, server/client certificates and Docker mTLS](docs/certificates.md)
- [OpenTelemetry, collector configuration and security](docs/telemetry.md)

Run `make generate` after upgrading Docker types or changing the state-reader interface. Mutation equality is generated from the complete typed `ServiceSpec` graph, with compile-time structural guards, and preserves nil/empty distinctions without runtime reflection. Review generated changes before accepting new Docker fields. Tests use standard JSON decoding, generated GoMock readers, real local HTTP/gRPC endpoints and the OpenTelemetry SDK.
