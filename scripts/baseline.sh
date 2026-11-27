#!/usr/bin/env bash
# Phase 7: generate normal activity for a while, then check that no critical
# (level >= 12) CipherGuard alert fired. This measures false positives so rules
# can be tuned before the 24-hour run.
#
#   scripts/baseline.sh                 default 1 hour
#   CG_BASELINE_SECONDS=86400 scripts/baseline.sh   full 24-hour run
set -uo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

DURATION="${CG_BASELINE_SECONDS:-3600}"
INSTANCE="$(wazuh_instance)" || exit 1
POD="$(require_demo_pod)" || exit 1
START="$(now)"
END=$(( START + DURATION ))
echo "Baseline for ${DURATION}s. Generating normal traffic to demo-app ..."

port_forward_demo 18080 || echo "warning: demo-app not answering on the port-forward yet"

reqs=0
while [ "$(now)" -lt "$END" ]; do
  curl -fs localhost:18080/ >/dev/null 2>&1 && reqs=$((reqs+1))
  curl -fs localhost:18080/healthz >/dev/null 2>&1 && reqs=$((reqs+1))
  # Normal operator activity: listing pods, reading logs.
  kubectl -n "$NS" get pods >/dev/null 2>&1
  kubectl -n "$NS" logs "$POD" --tail=1 >/dev/null 2>&1
  sleep 15
done
echo "Sent ~$reqs app requests over $((DURATION/60)) minutes."

crit="$(wazuh_query "$INSTANCE" crit "$START" | tr -d '[:space:]')"

echo
if [ "${crit:-0}" = "0" ]; then
  echo "PASS: no critical CipherGuard alerts during the baseline."
else
  echo "FAIL: $crit critical alert(s) during normal activity — tune the rules."
  exit 1
fi
