#!/usr/bin/env bash
# Collect evidence from a live run (smoke test, attack chain, Wazuh alerts,
# Kyverno PolicyReports, Active Response log) into docs/evidence/<timestamp>/.
#
#   scripts/collect-evidence.sh <run-label>
set -uo pipefail

LABEL="${1:?usage: collect-evidence.sh <run-label>}"
ROOT="$(git rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/docs/evidence/${TS}-${LABEL}"
mkdir -p "$OUT"
REGION="${AWS_REGION:-ap-southeast-1}"
NS="demo"

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

INSTANCE="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=cipherguard-wazuh" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)"

if [[ "$INSTANCE" == i-* ]]; then
  echo "Pulling Active Response log from $INSTANCE ..."
  CMD_ID="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
    --document-name AWS-RunShellScript \
    --parameters 'commands=["tail -n 200 /var/ossec/logs/active-responses.log 2>/dev/null || echo none","echo ---","tail -n 100 /var/ossec/logs/ossec.log 2>/dev/null"]' \
    --query Command.CommandId --output text 2>/dev/null)"
  if [ -n "$CMD_ID" ]; then
    aws ssm wait command-executed --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" 2>/dev/null || true
    aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" \
      --query StandardOutputContent --output text > "$OUT/05-wazuh-manager-logs.txt" 2>&1
  fi

  echo "Pulling all CipherGuard alerts from Wazuh manager ..."
  B64="$(base64 -w0 "$ROOT/detection/wazuh/query-alerts.sh")"
  CMD="echo '$B64' | base64 -d > /tmp/cg-query.sh; bash /tmp/cg-query.sh first 0"
  CMD_ID="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
    --document-name AWS-RunShellScript --parameters "commands=[\"$CMD\"]" \
    --query Command.CommandId --output text 2>/dev/null)"
  if [ -n "$CMD_ID" ]; then
    aws ssm wait command-executed --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" 2>/dev/null || true
    aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" \
      --query StandardOutputContent --output text > "$OUT/06-wazuh-alert-rules.tsv" 2>&1
  fi
else
  echo "Wazuh instance not found; skipping manager-side evidence." | tee "$OUT/05-wazuh-manager-logs.txt"
fi

[ -f /tmp/cg-attack.log ] && cp /tmp/cg-attack.log "$OUT/07-attack-run.log"
[ -f /tmp/cg-smoke.log ] && cp /tmp/cg-smoke.log "$OUT/08-smoke-test.log"

echo "Evidence collected:"
ls -la "$OUT"
