#!/usr/bin/env bash
# Phase 7: generate normal activity for a while, then check that no critical
# (level >= 12) CipherGuard alert fired. This measures false positives so rules
# can be tuned before the 24-hour run.
#
#   scripts/baseline.sh                 default 1 hour
#   CG_BASELINE_SECONDS=86400 scripts/baseline.sh   full 24-hour run
set -uo pipefail

REGION="${AWS_REGION:-ap-southeast-1}"
PROJECT="cipherguard"
ROOT="$(git rev-parse --show-toplevel)"
NS="demo"
DURATION="${CG_BASELINE_SECONDS:-3600}"

INSTANCE="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$PROJECT-wazuh" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)"
[[ "$INSTANCE" == i-* ]] || { echo "Wazuh instance not found" >&2; exit 1; }

POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=demo-app -o jsonpath='{.items[0].metadata.name}')"
START="$(date -u +%s)"
END=$(( START + DURATION ))
echo "Baseline for ${DURATION}s. Generating normal traffic to demo-app ..."

# Normal app traffic through a port-forward.
kubectl -n "$NS" port-forward "svc/demo-app" 18080:80 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
sleep 3

reqs=0
while [ "$(date -u +%s)" -lt "$END" ]; do
  curl -fs localhost:18080/ >/dev/null 2>&1 && reqs=$((reqs+1))
  curl -fs localhost:18080/healthz >/dev/null 2>&1 && reqs=$((reqs+1))
  # Normal operator activity: listing pods, reading logs.
  kubectl -n "$NS" get pods >/dev/null 2>&1
  kubectl -n "$NS" logs "$POD" --tail=1 >/dev/null 2>&1
  sleep 15
done
echo "Sent ~$reqs app requests over $((DURATION/60)) minutes."

# Query the manager for critical alerts since START.
b64="$(base64 -w0 "$ROOT/detection/wazuh/query-alerts.sh")"
cmd="echo '$b64' | base64 -d > /tmp/cg-query.sh; bash /tmp/cg-query.sh crit $START"
id="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript --parameters "commands=[\"$cmd\"]" \
  --query Command.CommandId --output text)"
aws ssm wait command-executed --region "$REGION" --command-id "$id" --instance-id "$INSTANCE" 2>/dev/null || true
crit="$(aws ssm get-command-invocation --region "$REGION" --command-id "$id" \
  --instance-id "$INSTANCE" --query StandardOutputContent --output text | tr -d '[:space:]')"

echo
if [ "${crit:-0}" = "0" ]; then
  echo "PASS: no critical CipherGuard alerts during the baseline."
else
  echo "FAIL: $crit critical alert(s) during normal activity — tune the rules."
  exit 1
fi
