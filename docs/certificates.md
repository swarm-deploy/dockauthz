# Docker mTLS certificates

Requires **Docker Engine >= 29.3.1**. Docker authenticates the peer; dockauthz consumes the authenticated leaf certificate and requires `UserAuthNMethod=TLS`.

```text
CA ──signs──> Docker server certificate ──> Docker daemon :2376
 └──signs──> client certificates ────────> Docker CLI / cloud-secrets / CI
```

## Create a CA

```sh
make build
bin/dockauthz-cert ca --name dockauthz-ca --out ./pki
```

Creates `ca.pem` (0644) and `ca-key.pem` (0600), using RSA-3072 and a cryptographically random serial number. CA certificates have `IsCA`, valid basic constraints and certificate/CRL signing usage. Default validity is 3650 days; use `--days` to override it. Keys use unencrypted PKCS#8 PEM. The helper uses only Go's standard cryptographic library and does not execute OpenSSL.

**The CA private key is especially sensitive material. Keep it offline/in a protected location and do not leave it on a Docker manager unnecessarily.** CA private key является особо чувствительным материалом. Храните его offline/в защищённом месте и не оставляйте на Docker manager без необходимости.

## Issue the server certificate

```sh
bin/dockauthz-cert server \
  --name docker-manager-1 \
  --dns docker-manager-1.example.com \
  --dns docker-manager \
  --ip 10.0.0.10 \
  --ca-cert ./pki/ca.pem \
  --ca-key ./pki/ca-key.pem \
  --out ./pki/server
```

Creates `ca.pem`, `server-cert.pem` and `server-key.pem`. The leaf has ServerAuth EKU and all repeated DNS/IP SANs. At least one SAN is mandatory. Include the exact DNS name or IP that clients use to connect: a common name alone is insufficient for hostname verification. The default lifetime is 365 days; `--days` must fit within the CA's remaining validity.

## Issue client certificates

```sh
bin/dockauthz-cert client --name docker-admin \
  --ca-cert ./pki/ca.pem --ca-key ./pki/ca-key.pem \
  --out ./pki/clients/docker-admin

bin/dockauthz-cert client --name cloud-secrets \
  --ca-cert ./pki/ca.pem --ca-key ./pki/ca-key.pem \
  --out ./pki/clients/cloud-secrets

bin/dockauthz-cert client --name github-ci \
  --ca-cert ./pki/ca.pem --ca-key ./pki/ca-key.pem \
  --out ./pki/clients/github-ci
```

Each directory contains Docker-compatible `ca.pem`, `cert.pem` and `key.pem`. Client leaves have ClientAuth EKU, a 365-day default lifetime and `Subject.CommonName` equal to `--name`. Certificates are mode 0644; keys are mode 0600; newly created output directories are mode 0700. `--days` overrides validity. Existing files are never overwritten without `--force`. Generation stages files before publishing them; a forced multi-file replacement is not a transactional directory switch, so rotate credentials through a new directory when readers are active.

The signing CA must be valid, have certificate-signing usage and match its private key. The helper accepts its own PKCS#8 RSA keys and unencrypted PKCS#1 RSA CA keys. It never prints a private key.

## Configure Docker

Copy only the CA **certificate**, server certificate and server key to the manager, protecting the key. For example, merge into `/etc/docker/daemon.json`:

```json
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2376"],
  "tlsverify": true,
  "tlscacert": "/etc/docker/pki/ca.pem",
  "tlscert": "/etc/docker/pki/server-cert.pem",
  "tlskey": "/etc/docker/pki/server-key.pem",
  "authorization-plugins": ["dockauthz:dev"]
}
```

Restrict the listening address/firewall to the intended management network. **Do not open port 2375 without TLS.** Docker's TLS endpoint convention is port **2376**. Install/enable the managed plugin before adding it to the daemon configuration, as described in the README. If your systemd unit already passes `-H`, configure listener settings in one place; Docker rejects duplicate settings between command-line flags and `daemon.json`. Apply changes through your normal controlled Docker restart procedure.

Copy the administrator's client bundle into `$HOME/.docker/dockauthz-admin`, retaining key mode 0600:

```sh
export DOCKER_HOST=tcp://docker-manager-1.example.com:2376
export DOCKER_TLS_VERIFY=1
export DOCKER_CERT_PATH=$HOME/.docker/dockauthz-admin
docker ps
```

`DOCKER_CERT_PATH` must contain `ca.pem`, `cert.pem`, `key.pem`. These environment variables configure the Docker CLI, not dockauthz. Applications should load credentials from mounted files. Restricted applications should select a compatible Docker API version explicitly and disable automatic ping/version negotiation; v0.1 only grants the operations listed in the policy schema.

## Identity mapping

```text
client certificate CN → Docker AuthN → authenticated leaf certificate → dockauthz client
```

`CN=cloud-secrets` matches:

```yaml
clients:
  cloud-secrets:
    identity:
      certificate:
        commonName: cloud-secrets
```

The logical client name may differ from the CN. Duplicate configured CNs are rejected at startup. Only `RequestPeerCertificates[0]` identifies the client; headers never establish identity. An authenticated certificate with an unknown CN is always denied. Missing, contradictory or unsupported authentication context is denied.

For migration, explicitly allow requests with no authenticated identity:

```yaml
authentication:
  unidentified: allow
```

This preserves ordinary local CLI access through `/var/run/docker.sock`. It also allows any other request reaching Docker without identity, so the daemon must not have an unauthenticated TCP listener.

For hardened deployments:

```yaml
authentication:
  unidentified: deny
```

Policy-controlled clients must use mTLS. Establish a working administrator certificate and recovery procedure before switching. Keep CA material and issued keys protected; the helper does not implement revocation, renewal automation or a certificate distribution service.
