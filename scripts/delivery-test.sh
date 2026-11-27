#!/usr/bin/env bash
# Measure Falco -> Wazuh delivery: trigger the same Falco rule N times in the
# demo pod, then compare how many events Falco emitted with how many alerts
# reached Wazuh. Written after a live run lost ~4 in 5 alerts of rule 100114.
#
#   scripts/delivery-test.sh [N] [interval_s]     default 20 triggers, 3 s apart
set -uo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

N="${1:-20}"
GAP="${2:-3}"
RULE_NAME="CipherGuard Escape Tooling In Container"
RULE_ID="100114"

POD="$(require_demo_pod)" || exit 1
NODE="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')"
FALCO="$(kubectl -n falco get pod -l app.kubernetes.io/name=falco --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')"
INSTANCE="$(wazuh_instance)" || exit 1
echo "pod=$POD node=$NODE falco=$FALCO manager=$INSTANCE  N=$N gap=${GAP}s"

START="$(now)"
for i in $(seq 1 "$N"); do
  # nsenter fails without privileges; the exec of the tool is the detection.
  kubectl -n "$NS" exec "$POD" -- sh -c "nsenter -t 1 -m sh -c 'echo $i' >/dev/null 2>&1; true" >/dev/null 2>&1 || true
  sleep "$GAP"
done
echo "triggers done; waiting 30 s for shipping"
sleep 30

# Window from START to now, by duration (not --since-time, which returned
# nothing intermittently). Only events after START carry our trigger index.
since="$(( $(now) - START + 2 ))s"
falco_n="$(kubectl -n falco logs "$FALCO" -c falco --since="$since" \
  | grep -c "\"rule\":\"$RULE_NAME\"" || true)"

wazuh_n="$(wazuh_query "$INSTANCE" count "$START" | awk -v r="$RULE_ID" '$1==r {print $2}')"
wazuh_n="${wazuh_n:-0}"

echo "triggers=$N  falco_events=$falco_n  wazuh_alerts($RULE_ID)=$wazuh_n"
[ "$wazuh_n" -ge "$falco_n" ] && [ "$falco_n" -gt 0 ] && { echo "DELIVERY OK"; exit 0; }
echo "DELIVERY LOSS: $(( falco_n - wazuh_n )) of $falco_n events missing in Wazuh"
exit 1
