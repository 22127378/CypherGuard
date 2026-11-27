#!/usr/bin/env bash
# Runs ON the Wazuh manager (via SSM, from scripts/measure-latency.sh and
# scripts/baseline.sh). Reads the alert log and prints, for each CipherGuard
# rule seen since a given epoch, the rule id, level and the FIRST alert time.
#
#   query-alerts.sh first  <since_epoch>   earliest alert per cipherguard rule (TSV)
#   query-alerts.sh crit   <since_epoch>   count alerts at level >= 12 (baseline FP check)
#   query-alerts.sh count  <since_epoch>   number of alerts per cipherguard rule (TSV)
set -euo pipefail

MODE="${1:?first|crit|count}"
SINCE="${2:?since epoch}"
ALERTS=/var/ossec/logs/alerts/alerts.json
PY=/var/ossec/framework/python/bin/python3
[ -x "$PY" ] || PY=python3

[ -f "$ALERTS" ] || { echo "no alerts.json yet" >&2; exit 0; }

"$PY" - "$MODE" "$SINCE" "$ALERTS" <<'PY'
import datetime as dt, json, sys

mode, since, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]

def epoch(ts: str) -> float:
    # Wazuh timestamp: 2026-11-19T04:30:00.000+0000
    try:
        return dt.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=dt.timezone.utc).timestamp()
    except ValueError:
        return 0.0

first = {}   # rule_id -> (epoch, level)
count = {}   # rule_id -> number of alerts
crit = 0
with open(path, errors="replace") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        rule = a.get("rule", {})
        rid = str(rule.get("id", ""))
        level = int(rule.get("level", 0))
        groups = rule.get("groups", []) or []
        when = epoch(a.get("timestamp", ""))
        if when < since:
            continue
        if mode == "crit":
            if level >= 12:
                crit += 1
            continue
        if "cipherguard" in groups or rid.startswith("1001") or rid.startswith("1003"):
            count[rid] = count.get(rid, 0) + 1
            if rid not in first or when < first[rid][0]:
                first[rid] = (when, level)

if mode == "crit":
    print(crit)
elif mode == "count":
    for rid in sorted(count):
        print(f"{rid}\t{count[rid]}")
else:
    for rid in sorted(first):
        when, level = first[rid]
        print(f"{rid}\t{level}\t{when:.0f}")
PY
