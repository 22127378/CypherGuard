#!/usr/bin/env bash
# Wazuh Active Response — runs ON the EKS node where the alert fired.
#
# Isolates the offending pod's container instead of the node, so the Wazuh
# agent on the node keeps reporting (success metric: node stays reachable).
# It reads the Wazuh AR JSON on stdin, pulls container.id from the Falco alert,
# and stops just that container with crictl. Every action is logged.
#
# Installed at /var/ossec/active-response/bin/ by the node user data.
set -uo pipefail

LOG="${CG_AR_LOG:-/var/ossec/logs/active-responses.log}"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') cipherguard-isolate: $*" >>"$LOG"; }

input="$(cat)"
command="$(echo "$input" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("command",""))' 2>/dev/null || true)"

# Wazuh calls with "add" to act, "delete" to roll back; we only act on add.
[ "$command" = "add" ] || { log "ignoring command=$command"; exit 0; }

cid="$(echo "$input" | python3 -c '
import sys, json
d = json.load(sys.stdin)
alert = d.get("parameters", {}).get("alert", {})
# container.id lives in the Falco output fields the Wazuh rule forwarded.
data = alert.get("data", {})
print(data.get("output_fields", {}).get("container.id", "") if isinstance(data, dict) else "")
' 2>/dev/null || true)"

if [ -z "$cid" ] || [ "$cid" = "host" ]; then
  log "no pod container id in alert (host-level event); taking no action"
  exit 0
fi

if ! command -v crictl >/dev/null 2>&1; then
  log "crictl not found on node; cannot isolate $cid"
  exit 1
fi

# crictl ids may be a short prefix; match it.
full="$(crictl ps -q 2>/dev/null | grep "^$cid" | head -1 || true)"
target="${full:-$cid}"

if crictl stop --timeout 5 "$target" >>"$LOG" 2>&1; then
  log "stopped container $target (Active Response)"
else
  log "failed to stop container $target"
  exit 1
fi
