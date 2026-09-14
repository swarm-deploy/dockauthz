#!/usr/bin/env bash
# e2e/run.sh exercises the real, managed dockauthz plugin binary against a
# throwaway nested Docker daemon running inside a privileged docker:dind
# container. It never touches the Docker daemon of the host/runner: every
# docker command executed against the system under test happens through
# `docker exec` into the dind container, which owns its own isolated
# dockerd, swarm, and plugin store.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/dockauthz-e2e.XXXXXX)"
CONTAINER="dockauthz-e2e-$$"

SERVICE=e2e-service
SECRET_A=e2e-secret-a
SECRET_B=e2e-secret-b

FAILURES=0

log() { printf '\n=== %s ===\n' "$*"; }

cleanup() {
  local status=$?
  log "cleanup"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  if [ "$FAILURES" -gt 0 ]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

dx() { docker exec "$CONTAINER" sh -c "$1"; }
dxq() { docker exec "$CONTAINER" sh -c "$1" >/dev/null 2>&1; }

# check runs a shell snippet inside the dind container and compares its exit
# status against the expected outcome ("allow" => must succeed, "deny" =>
# must fail). Any mismatch is a hard e2e failure.
check() {
  local name="$1" want="$2" cmd="$3"
  local out status
  set +e
  out="$(docker exec "$CONTAINER" sh -c "$cmd" 2>&1)"
  status=$?
  set -e
  if { [ "$want" = "allow" ] && [ "$status" -eq 0 ]; } ||
     { [ "$want" = "deny" ] && [ "$status" -ne 0 ]; }; then
    printf 'PASS  %-55s (%s, exit=%s)\n' "$name" "$want" "$status"
  else
    printf 'FAIL  %-55s (expected %s, exit=%s)\n%s\n' "$name" "$want" "$status" "$out"
    FAILURES=$((FAILURES + 1))
  fi
}

wait_ready() {
  local tries=60
  while [ "$tries" -gt 0 ]; do
    if dxq "docker info"; then
      return 0
    fi
    tries=$((tries - 1))
    sleep 1
  done
  echo "nested Docker daemon never became ready" >&2
  return 1
}

log "building managed plugin rootfs (plugin-rootfs)"
make -C "$ROOT" plugin-rootfs

log "building host-side test tooling (dockauthz-cert, svcupdate)"
go build -C "$ROOT" -o bin/dockauthz-cert ./cmd/dockauthz-cert
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -C "$ROOT" -o bin/svcupdate ./e2e/tools/svcupdate

log "generating a throwaway PKI for identified e2e clients"
"$ROOT/bin/dockauthz-cert" ca --name e2e-ca --out "$WORK/certs/ca"
"$ROOT/bin/dockauthz-cert" server --name docker-dind --out "$WORK/certs/server" \
  --ca-cert "$WORK/certs/ca/ca.pem" --ca-key "$WORK/certs/ca/ca-key.pem" \
  --dns localhost --ip 127.0.0.1
"$ROOT/bin/dockauthz-cert" client --name e2e-admin --out "$WORK/certs/admin" \
  --ca-cert "$WORK/certs/ca/ca.pem" --ca-key "$WORK/certs/ca/ca-key.pem"
"$ROOT/bin/dockauthz-cert" client --name e2e-mutator --out "$WORK/certs/mutator" \
  --ca-cert "$WORK/certs/ca/ca.pem" --ca-key "$WORK/certs/ca/ca-key.pem"

# A single plugin definition is reused across phases: instead of creating
# two simultaneous plugin objects with identical rootfs content (which the
# plugin content store rejects as a duplicate digest), the policy file is
# swapped and the plugin object is recreated between phases.
mkdir -p "$WORK/plugin"
cp -r "$ROOT/plugin/rootfs" "$WORK/plugin/rootfs"
cp "$ROOT/plugin/config.json" "$WORK/plugin/config.json"

log "starting privileged docker:dind container ($CONTAINER)"
docker run -d --privileged --init --name "$CONTAINER" docker:dind sleep infinity >/dev/null

docker cp "$WORK/certs/." "$CONTAINER:/certs"
docker cp "$WORK/plugin" "$CONTAINER:/workspace-plugin"
docker cp "$ROOT/bin/svcupdate" "$CONTAINER:/usr/local/bin/svcupdate"
dx "mkdir -p /etc/dockauthz"

log "starting nested dockerd WITHOUT the authz plugin"
dx "dockerd --host=unix:///var/run/docker.sock >/var/log/dockerd-setup.log 2>&1 &"
wait_ready

log "swarm init, test secrets and a test service"
dx "docker swarm init >/dev/null"
dx "printf %s current-a | docker secret create $SECRET_A -"
dx "printf %s current-b | docker secret create $SECRET_B -"
dx "docker service create --name $SERVICE --secret source=$SECRET_A,target=$SECRET_A nginx:1 >/dev/null"
SECRET_A_ID="$(dx "docker secret inspect $SECRET_A --format '{{.ID}}'" | tr -d '\r')"
SECRET_B_ID="$(dx "docker secret inspect $SECRET_B --format '{{.ID}}'" | tr -d '\r')"

log "docker plugin create + enable (permissive policy)"
docker cp "$ROOT/e2e/config.yaml" "$CONTAINER:/etc/dockauthz/config.yaml"
dx "docker plugin create dockauthz:e2e /workspace-plugin"
dx "docker plugin enable dockauthz:e2e"

log "restarting nested dockerd WITH --authorization-plugin=dockauthz:e2e"
dx "pkill -9 dockerd || true"
while dx "[ -e /var/run/docker.pid ] && kill -0 \$(cat /var/run/docker.pid)" 2>/dev/null; do sleep 1; done
dx "rm -f /var/run/docker.pid"
dx "dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 \
  --tlsverify --tlscacert=/certs/server/ca.pem --tlscert=/certs/server/server-cert.pem --tlskey=/certs/server/server-key.pem \
  --authorization-plugin=dockauthz:e2e >/var/log/dockerd-permissive.log 2>&1 &"
wait_ready

log "permissive policy: authentication.unidentified: allow, clients: {}"
check "unidentified GET /services -> ALLOW"                "allow" "docker service ls"
check "unidentified GET /services/{id} -> ALLOW"            "allow" "docker service inspect $SERVICE"

log "swapping to the stricter test policy (admin + mutator, mutation.only: [container.secrets])"
dx "docker plugin disable dockauthz:e2e --force"
dx "docker plugin rm dockauthz:e2e"
docker cp "$ROOT/e2e/config-strict.yaml" "$CONTAINER:/etc/dockauthz/config.yaml"
dx "docker plugin create dockauthz:e2e /workspace-plugin"
dx "docker plugin enable dockauthz:e2e"

log "restarting nested dockerd WITH the reloaded --authorization-plugin=dockauthz:e2e"
dx "pkill -9 dockerd || true"
while dx "[ -e /var/run/docker.pid ] && kill -0 \$(cat /var/run/docker.pid)" 2>/dev/null; do sleep 1; done
dx "rm -f /var/run/docker.pid"
dx "dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 \
  --tlsverify --tlscacert=/certs/server/ca.pem --tlscert=/certs/server/server-cert.pem --tlskey=/certs/server/server-key.pem \
  --authorization-plugin=dockauthz:e2e >/var/log/dockerd-strict.log 2>&1 &"
wait_ready

TLS_MUTATOR="export DOCKER_HOST=tcp://127.0.0.1:2376 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH=/certs/mutator;"
TLS_ADMIN="export DOCKER_HOST=tcp://127.0.0.1:2376 DOCKER_TLS_VERIFY=1 DOCKER_CERT_PATH=/certs/admin;"

log "strict policy: identified clients (admin, mutator) with mutation.only: [container.secrets]"
check "admin (full administrator) GET /services -> ALLOW" "allow" "$TLS_ADMIN docker service ls"
check "mutator GET /services -> ALLOW"                     "allow" "$TLS_MUTATOR docker service ls"
check "mutator GET /services/{id} -> ALLOW"                "allow" "$TLS_MUTATOR docker service inspect $SERVICE"
check "mutator GET /images/json (unknown endpoint) -> DENY" "deny" "$TLS_MUTATOR docker images"
check "mutator GET /secrets (no permission) -> DENY"        "deny" "$TLS_MUTATOR docker secret ls"

log "ServiceUpdate: current image=nginx:1 secrets=[$SECRET_A]"
log "ALLOW: image unchanged, secrets [$SECRET_A] -> [$SECRET_B]"
if svcupdate_out="$(docker exec "$CONTAINER" svcupdate \
    -addr https://127.0.0.1:2376 \
    -cacert /certs/mutator/ca.pem -cert /certs/mutator/cert.pem -key /certs/mutator/key.pem \
    -service "$SERVICE" -secret-id "$SECRET_B_ID" -secret-name "$SECRET_B" 2>&1)"; then
  printf 'PASS  %-55s (allow)\n%s\n' "ServiceUpdate secrets-only change" "$svcupdate_out"
else
  printf 'FAIL  %-55s (expected allow)\n%s\n' "ServiceUpdate secrets-only change" "$svcupdate_out"
  FAILURES=$((FAILURES + 1))
fi

log "DENY: image nginx:1 -> nginx:2 AND secrets [$SECRET_B] -> [$SECRET_A] (mutation outside container.secrets)"
if svcupdate_out="$(docker exec "$CONTAINER" svcupdate \
    -addr https://127.0.0.1:2376 \
    -cacert /certs/mutator/ca.pem -cert /certs/mutator/cert.pem -key /certs/mutator/key.pem \
    -service "$SERVICE" -secret-id "$SECRET_A_ID" -secret-name "$SECRET_A" -image nginx:2 2>&1)"; then
  printf 'FAIL  %-55s (expected deny)\n%s\n' "ServiceUpdate image+secrets change" "$svcupdate_out"
  FAILURES=$((FAILURES + 1))
else
  printf 'PASS  %-55s (deny)\n%s\n' "ServiceUpdate image+secrets change" "$svcupdate_out"
fi

log "verifying final service state matches only the ALLOWed mutation"
FINAL_IMAGE="$(dx "$TLS_ADMIN docker service inspect $SERVICE --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}'")"
FINAL_SECRETS="$(dx "$TLS_ADMIN docker service inspect $SERVICE --format '{{range .Spec.TaskTemplate.ContainerSpec.Secrets}}{{.SecretName}}{{end}}'")"
case "$FINAL_IMAGE" in
  nginx:1*) printf 'PASS  %-55s (%s)\n' "final image is still nginx:1" "$FINAL_IMAGE" ;;
  *) printf 'FAIL  %-55s (got %s)\n' "final image is still nginx:1" "$FINAL_IMAGE"; FAILURES=$((FAILURES + 1)) ;;
esac
case "$FINAL_SECRETS" in
  "$SECRET_B") printf 'PASS  %-55s (%s)\n' "final secret is $SECRET_B" "$FINAL_SECRETS" ;;
  *) printf 'FAIL  %-55s (got %s)\n' "final secret is $SECRET_B" "$FINAL_SECRETS"; FAILURES=$((FAILURES + 1)) ;;
esac

if [ "$FAILURES" -gt 0 ]; then
  log "e2e FAILED ($FAILURES assertion(s) failed)"
else
  log "e2e PASSED"
fi
