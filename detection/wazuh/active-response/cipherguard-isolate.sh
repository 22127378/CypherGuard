#!/usr/bin/env bash
# Wazuh Active Response — runs ON the EKS node where the alert fired.
#
# Isolates the offending pod's container instead of the node, so the Wazuh
# agent on the node keeps reporting (success metric: node stays reachable).
# It reads the Wazuh AR JSON on stdin, pulls container.id from the Falco alert,
# and stops just that container with containerd's own CLI. Every action, and
# every parse failure, is logged (a prior version swallowed parse errors
# silently, which cost a long live-debugging session to track down).
#
# Installed at /var/ossec/active-response/bin/ by the node user data.
set -uo pipefail

LOG="${CG_AR_LOG:-/var/ossec/logs/active-responses.log}"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') cipherguard-isolate: $*" >>"$LOG"; }

# Wazuh 4.x execd writes ONE JSON line to stdin and keeps the pipe open (it
# may wait for a reply), so read exactly one line. Found live: a previous
# version used "$(cat)", which waits for EOF that never comes. The script hung,
# execd stopped reading its queue, wazuh-agentd blocked behind it and stopped
# sending keepalives and events: agents showed "Disconnected" and alerts were
# lost. The 10 s timeout keeps a stray caller from wedging execd again.
IFS= read -r -t 10 input || true

# One python call extracts both fields. Wazuh has been observed to nest
# "alert" either as an object or as a JSON-encoded string depending on
# version/path, so both are handled. Any failure is reported explicitly
# (tab-separated "OK <command> <cid>" or "PARSEFAIL <error>") instead of
# being caught and discarded, which previously masked the real bug.
parsed="$(printf '%s' "$input" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    ar_command = d.get("command", "")
    alert = d.get("parameters", {}).get("alert", {})
    if isinstance(alert, str):
        alert = json.loads(alert)
    data = alert.get("data", {}) if isinstance(alert, dict) else {}
    of = data.get("output_fields", {}) if isinstance(data, dict) else {}
    # Wazuh splits dotted JSON keys into nested objects when it writes the
    # alert: Falco "container.id" arrives as {"container": {"id": ...}}.
    # (Confirmed with wazuh-manager 4.14.10 logtest; the flat lookup a prior
    # version used always came back empty, live.) Flat key kept as fallback.
    cont = of.get("container", {}) if isinstance(of, dict) else {}
    cid = cont.get("id", "") if isinstance(cont, dict) else ""
    if not cid and isinstance(of, dict):
        cid = of.get("container.id", "")
    k8s = of.get("k8s", {}) if isinstance(of, dict) else {}
    ns = (k8s.get("ns", {}) or {}).get("name", "") if isinstance(k8s, dict) else ""
    if not ns and isinstance(of, dict):
        ns = of.get("k8s.ns.name", "")
    print(f"OK\t{ar_command}\t{cid}\t{ns}")
except Exception as e:
    print(f"PARSEFAIL\t{type(e).__name__}: {e}")
' 2>&1)"

status="${parsed%%$'\t'*}"
if [ "$status" != "OK" ]; then
  log "failed to parse AR input: $parsed"
  log "raw input (first 500 chars): $(printf '%s' "$input" | head -c 500)"
  exit 0
fi

ar_command="$(printf '%s' "$parsed" | cut -f2)"
cid="$(printf '%s' "$parsed" | cut -f3)"
ns="$(printf '%s' "$parsed" | cut -f4)"

# Only ever isolate application pods. Found live: the IMDS rule matched the
# VPC CNI (aws-node, kube-system), and this script killed it. Killing system
# pods breaks the node; those alerts are for a human, not for automation.
SCOPE="${CG_AR_NAMESPACES:-demo}"

# Wazuh calls with "add" to act, "delete" to roll back; we only act on add.
[ "$ar_command" = "add" ] || { log "ignoring command=$ar_command"; exit 0; }

if [ -z "$cid" ] || [ "$cid" = "host" ]; then
  log "no pod container id in alert (host-level event); taking no action"
  exit 0
fi

case " $SCOPE " in
  *" $ns "*) ;;
  *) log "container $cid is in namespace '${ns:-unknown}', outside AR scope ($SCOPE); taking no action"
     exit 0 ;;
esac

# containerd's own CLI: crictl is not present on this AL2023 AMI.
if ! command -v ctr >/dev/null 2>&1; then
  log "ctr not found on node; cannot isolate $cid"
  exit 1
fi

# ctr ids may be a short prefix; match it against the CRI (k8s.io) namespace.
full="$(ctr -n k8s.io containers ls -q 2>/dev/null | grep "^$cid" | head -1 || true)"
target="${full:-$cid}"

# SIGKILL, not ctr's default SIGTERM. Found live: the app is PID 1 in its
# PID namespace and installs no SIGTERM handler, so the kernel drops SIGTERM;
# the script logged "stopped" while the attacker's container kept running.
if ctr -n k8s.io tasks kill -s SIGKILL "$target" >>"$LOG" 2>&1; then
  log "stopped container $target (Active Response)"
else
  log "failed to stop container $target"
  exit 1
fi
