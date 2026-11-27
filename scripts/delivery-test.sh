#!/usr/bin/env bash
# Measure Falco -> Wazuh delivery: trigger the same Falco rule N times in the
# demo pod, then compare how many events Falco emitted with how many alerts
# reached Wazuh. Written after a live run lost ~4 in 5 alerts of rule 100114.
#
#   scripts/delivery-test.sh [N] [interval_s]     default 20 triggers, 3 s apart
set -uo pipefail

N="${1:-20}"
GAP="${2:-3}"
REGION="${AWS_REGION:-ap-southeast-1}"
ROOT="$(git rev-parse --show-toplevel)"
RULE_NAME="CipherGuard Escape Tooling In Container"
RULE_ID="100114"

POD="$(kubectl -n demo get pod -l app.kubernetes.io/name=demo-app --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
NODE="$(kubectl -n demo get pod "$POD" -o jsonpath='{.spec.nodeName}')"
FALCO="$(kubectl -n falco get pod -l app.kubernetes.io/name=falco --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')"
INSTANCE="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=cipherguard-wazuh" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)"
echo "pod=$POD node=$NODE falco=$FALCO manager=$INSTANCE  N=$N gap=${GAP}s"

START="$(date -u +%s)"
for i in $(seq 1 "$N"); do
  # nsenter fails without privileges; the exec of the tool is the detection.
  kubectl -n demo exec "$POD" -- sh -c "nsenter -t 1 -m sh -c 'echo $i' >/dev/null 2>&1; true" >/dev/null 2>&1 || true
  sleep "$GAP"
done
echo "triggers done; waiting 30 s for shipping"
sleep 30

# Window from START to now, by duration (not --since-time, which returned
# nothing intermittently). Only events after START carry our trigger index.
since="$(( $(date -u +%s) - START + 2 ))s"
falco_n="$(kubectl -n falco logs "$FALCO" -c falco --since="$since" \
  | grep -c "\"rule\":\"$RULE_NAME\"" || true)"

b64="$(base64 -w0 "$ROOT/detection/wazuh/query-alerts.sh")"
cmd="echo '$b64' | base64 -d > /tmp/cg-query.sh; bash /tmp/cg-query.sh count $START"
id="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript --parameters "commands=[\"$cmd\"]" \
  --query Command.CommandId --output text)"
aws ssm wait command-executed --region "$REGION" --command-id "$id" --instance-id "$INSTANCE" 2>/dev/null || true
counts="$(aws ssm get-command-invocation --region "$REGION" --command-id "$id" \
  --instance-id "$INSTANCE" --query StandardOutputContent --output text)"
wazuh_n="$(printf '%s\n' "$counts" | awk -v r="$RULE_ID" '$1==r {print $2}')"
wazuh_n="${wazuh_n:-0}"

echo "triggers=$N  falco_events=$falco_n  wazuh_alerts($RULE_ID)=$wazuh_n"
[ "$wazuh_n" -ge "$falco_n" ] && [ "$falco_n" -gt 0 ] && { echo "DELIVERY OK"; exit 0; }
echo "DELIVERY LOSS: $(( falco_n - wazuh_n )) of $falco_n events missing in Wazuh"
exit 1
