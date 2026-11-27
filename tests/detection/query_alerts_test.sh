#!/usr/bin/env bash
# Unit test for detection/wazuh/query-alerts.sh (phase 7 parser), run against a
# fixture alerts.json instead of a live manager.
#   first: earliest alert per cipherguard rule since the epoch, benign excluded
#   crit:  number of cipherguard alerts at level >= 12
#   count: alerts per cipherguard rule
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/alerts.json" <<'JSON'
{"timestamp":"2026-11-19T04:30:40.000+0000","rule":{"id":"100113","level":12,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:50.000+0000","rule":{"id":"100113","level":12,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:55.000+0000","rule":{"id":"100130","level":14,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:29:00.000+0000","rule":{"id":"100110","level":10,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:30.000+0000","rule":{"id":"5402","level":3,"groups":["syslog"]}}
JSON
sed "s#ALERTS=/var/ossec/logs/alerts/alerts.json#ALERTS=$tmp/alerts.json#" \
  "$ROOT/detection/wazuh/query-alerts.sh" >"$tmp/q.sh"
since="$(date -u -d "2026-11-19T04:30:00Z" +%s 2>/dev/null || echo 1795062600)"

fails=0
check() { # check <name> <want> <got>
  if [ "$2" = "$3" ]; then echo "ok    query-alerts $1"; else echo "FAIL  query-alerts $1: want '$2', got '$3'"; fails=$((fails + 1)); fi
}
# 100110 is older than the window, 5402 is not a cipherguard rule.
check first "100113,100130," "$(bash "$tmp/q.sh" first "$since" | awk '{print $1}' | tr '\n' ',')"
check crit "3" "$(bash "$tmp/q.sh" crit "$since")"
check count "100113:2,100130:1," "$(bash "$tmp/q.sh" count "$since" | awk '{printf "%s:%s,", $1, $2}')"
[ "$fails" -eq 0 ]
