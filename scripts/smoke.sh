#!/usr/bin/env bash
# Post-deploy smoke test. Exits non-zero on the first failed check.
#
#   scripts/smoke.sh --mode enforce   also proves bad workloads are rejected
#   scripts/smoke.sh --mode detect    bad workloads must be admitted (audit only)
set -euo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

MODE="enforce"
[ "${1:-}" = "--mode" ] && MODE="${2:?}"
check_mode "$MODE"
fails=0

pass() { echo "ok    $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

# ---------- workload health ----------
kubectl -n "$NS" rollout status deploy/demo-app --timeout=120s >/dev/null && pass "demo-app rolled out" || fail "demo-app not ready"

POD="$(require_demo_pod)" || exit 1

# ---------- no static credentials, no API token ----------
vols="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.volumes[*].name}')"
[[ "$vols" != *kube-api-access* ]] && pass "no Kubernetes API token mounted" || fail "API token is mounted"

envs="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].env[*].name}')"
[[ "$envs" == *AWS_ROLE_ARN* ]] && pass "IRSA role injected" || fail "AWS_ROLE_ARN missing (IRSA not wired)"
[[ "$envs" != *AWS_ACCESS_KEY_ID* && "$envs" != *AWS_SECRET_ACCESS_KEY* ]] && pass "no static AWS keys in env" || fail "static AWS keys in env"

image="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].image}')"
[[ "$image" == *@sha256:* ]] && pass "running by digest" || fail "image not pinned by digest: $image"

# ---------- HTTP through the service ----------
port_forward_demo 18080 && pass "/healthz 200" || fail "/healthz failed"
body="$(curl -s localhost:18080/ || true)"
[[ "$body" == *greeting* ]] && pass "IRSA -> SSM works: $body" || fail "app could not read SSM via IRSA: $body"

# ---------- admission (server-side dry run hits the Kyverno webhook) ----------
admit() { kubectl "$@" --dry-run=server >/dev/null 2>&1; }

check_admission() {
  local name="$1"; shift
  if admit "$@"; then
    [ "$MODE" = "detect" ] && pass "$name admitted (audit mode)" || fail "$name was admitted"
  else
    [ "$MODE" = "enforce" ] && pass "$name rejected" || fail "$name rejected in audit mode"
  fi
}

# Fully PSS-restricted spec, so only the registry/signature policies can reject it
# (native Pod Security Admission would otherwise block it first).
check_admission "image from another registry (unsigned)" \
  -n "$NS" run cg-smoke-unsigned --image=nginxinc/nginx-unprivileged:1.27 --restart=Never \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":101,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"cg-smoke-unsigned","image":"nginxinc/nginx-unprivileged:1.27","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}'
check_admission "privileged pod" \
  -n default run cg-smoke-priv --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"cg-smoke-priv","image":"busybox:1.36","securityContext":{"privileged":true}}]}}'
check_admission "hostPath mount of /" \
  -n default run cg-smoke-hostpath --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"volumes":[{"name":"h","hostPath":{"path":"/"}}],"containers":[{"name":"cg-smoke-hostpath","image":"busybox:1.36","volumeMounts":[{"name":"h","mountPath":"/host"}]}]}}'
check_admission "cluster-admin bound to a ServiceAccount" \
  create clusterrolebinding cg-smoke-escalate --clusterrole=cluster-admin --serviceaccount="$NS:demo-app"

echo
[ "$fails" -eq 0 ] && echo "smoke test passed ($MODE)" || { echo "smoke test: $fails check(s) failed"; exit 1; }
