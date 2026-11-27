#!/usr/bin/env bash
# Phase 7: run the detect-only attack chain, then measure how long each rule
# took to alert in Wazuh. End-to-end latency from the start of the run (the
# steps execute within ~20s, so this is close to per-step latency).
#
#   scripts/measure-latency.sh            run the chain, then measure
#   scripts/measure-latency.sh --no-run   measure against a chain you already ran
set -uo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

RUN=1
[ "${1:-}" = "--no-run" ] && RUN=0
WAIT="${CG_WAIT:-80}"
INSTANCE="$(wazuh_instance)" || exit 1

START="$(now)"
if [ "$RUN" = 1 ]; then
  echo "Starting detect-only attack chain at epoch $START ..."
  "$ROOT/attack/run-attack.sh" --mode detect >"$CG_LOG_DIR/cg-attack.log" 2>&1 || true
  echo "Chain done; waiting ${WAIT}s for audit-log poll + indexing ..."
  sleep "$WAIT"
fi

declare -A DESC=(
  [100110]="Step1 shell in container|60" [100111]="Step2 API server contact|60"
  [100112]="Step2 token read|60" [100113]="ScenD IMDS|60"
  [100114]="ScenB container escape|60" [100115]="ScenG exec from /tmp|60"
  [100116]="ScenG log tampering|60" [100117]="ScenG kill agent|60"
  [100118]="ScenF recon tool|60" [100119]="Step4 data read|60"
  [100120]="Step4 outbound|60" [100130]="Step4 correlation|60"
  [100201]="Step0 admission denied|60" [100202]="Step1 kubectl exec|90"
  [100203]="Step2 forbidden API|90" [100205]="Step3 privileged pod|90"
  [100206]="Step3 cluster-admin bind|90" [100300]="Step3 pod role denied|900"
  [100301]="ScenD node cred misuse|900"
)

printf '\n%-28s %-6s %-9s %-6s\n' "RULE" "LEVEL" "LATENCY" "TARGET"
printf '%-28s %-6s %-9s %-6s\n' "----" "-----" "-------" "------"
pass=0; miss=0
while IFS=$'\t' read -r rid level ts; do
  [ -n "$rid" ] || continue
  entry="${DESC[$rid]:-rule $rid|60}"
  name="${entry%|*}"; target="${entry#*|}"
  lat=$(( ts - START ))
  if [ "$lat" -le "$target" ]; then verdict="ok (<=${target}s)"; pass=$((pass+1));
  else verdict="MISS (>${target}s)"; miss=$((miss+1)); fi
  printf '%-28s %-6s %-9s %s\n' "$name" "$level" "${lat}s" "$verdict"
done < <(wazuh_query "$INSTANCE" first "$START")

echo
echo "within target: $pass   over target: $miss"
echo "(CloudTrail rules 100300/100301 use a 15-min target; they back up the faster sources.)"
[ "$miss" -eq 0 ]