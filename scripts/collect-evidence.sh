#!/usr/bin/env bash
# Collect evidence from a live run (smoke test, attack chain, Wazuh alerts,
# Kyverno PolicyReports, Active Response log) into docs/evidence/<timestamp>/.
#
#   scripts/collect-evidence.sh <run-label>
set -uo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

LABEL="${1:?usage: collect-evidence.sh <run-label>}"
OUT="$ROOT/docs/evidence/$(date -u +%Y%m%dT%H%M%SZ)-${LABEL}"
mkdir -p "$OUT"
echo "Collecting evidence into $OUT"

{
  echo "# Evidence: $LABEL"
  echo "Collected: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## Cluster"
  kubectl get nodes -o wide 2>&1
  echo
  echo "## demo-app pod"
  kubectl -n "$NS" get pods -o wide 2>&1
} > "$OUT/00-cluster-state.txt"

kubectl -n "$NS" get networkpolicy -o yaml > "$OUT/01-networkpolicy.yaml" 2>&1
kubectl get validatingpolicies,imagevalidatingpolicies -o yaml > "$OUT/02-kyverno-policies.yaml" 2>&1
kubectl get policyreport,clusterpolicyreport -A -o yaml > "$OUT/03-policyreports.yaml" 2>&1
kubectl get events -A --sort-by=.lastTimestamp > "$OUT/04-k8s-events.txt" 2>&1

INSTANCE="$(instance_id "$PROJECT-wazuh")"
if [ -n "$INSTANCE" ]; then
  echo "Pulling Active Response log from $INSTANCE ..."
  ssm_run "$INSTANCE" "tail -n 200 /var/ossec/logs/active-responses.log 2>/dev/null || echo none; echo ---; tail -n 100 /var/ossec/logs/ossec.log 2>/dev/null" \
    > "$OUT/05-wazuh-manager-logs.txt" 2>&1
  echo "Pulling all CipherGuard alerts from Wazuh manager ..."
  wazuh_query "$INSTANCE" first 0 > "$OUT/06-wazuh-alert-rules.tsv" 2>&1
else
  echo "Wazuh instance not found; skipping manager-side evidence." | tee "$OUT/05-wazuh-manager-logs.txt"
fi

[ -f "$CG_LOG_DIR/cg-attack.log" ] && cp "$CG_LOG_DIR/cg-attack.log" "$OUT/07-attack-run.log"
[ -f "$CG_LOG_DIR/cg-smoke.log" ] && cp "$CG_LOG_DIR/cg-smoke.log" "$OUT/08-smoke-test.log"

echo "Evidence collected:"
ls -la "$OUT"
