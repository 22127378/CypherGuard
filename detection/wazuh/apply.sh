#!/bin/bash
# Runs ON the Wazuh manager (via SSM, from scripts/wazuh-sync.sh).
# Installs CipherGuard rules, the eks-nodes group config and the AWS module
# block, validates, and restarts. Any validation failure restores the backup.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
OSSEC=/var/ossec

if [ ! -x "$OSSEC/bin/wazuh-control" ]; then
  echo "Wazuh manager is not installed yet (user data still running?)"
  exit 3
fi

# Fingerprint of everything this script manages. The manager is restarted only
# when it changes: found live, every restart drops the node agents' connections
# and repeated restarts in a row left them stuck "Disconnected", losing events.
fingerprint() {
  cat "$OSSEC/etc/ossec.conf" "$OSSEC"/etc/rules/cipherguard_*.xml \
      "$OSSEC/etc/shared/eks-nodes/agent.conf" 2>/dev/null | sha256sum | cut -d' ' -f1
}
BEFORE="$(fingerprint)"

BACKUP="$(mktemp -d)"
cp -a "$OSSEC/etc/ossec.conf" "$BACKUP/"
cp -a "$OSSEC/etc/rules" "$BACKUP/rules"

restore() {
  echo "Validation failed, restoring previous configuration"
  cp -a "$BACKUP/ossec.conf" "$OSSEC/etc/ossec.conf"
  rm -rf "$OSSEC/etc/rules" && cp -a "$BACKUP/rules" "$OSSEC/etc/rules"
  exit 1
}

# Rules
rm -f "$OSSEC"/etc/rules/cipherguard_*.xml
install -o wazuh -g wazuh -m 0660 "$SRC"/rules/cipherguard_*.xml "$OSSEC/etc/rules/"

# Agent group config
[ -d "$OSSEC/etc/shared/eks-nodes" ] || "$OSSEC/bin/agent_groups" -a -g eks-nodes -q
"$OSSEC/bin/verify-agent-conf" -f "$SRC/shared/eks-nodes/agent.conf" || restore
install -o wazuh -g wazuh -m 0660 "$SRC/shared/eks-nodes/agent.conf" "$OSSEC/etc/shared/eks-nodes/agent.conf"

# AWS module block (replace between markers)
sed -i '/<!-- cipherguard:aws:begin -->/,/<!-- cipherguard:aws:end -->/d' "$OSSEC/etc/ossec.conf"
cat "$SRC/ossec-aws.xml" >>"$OSSEC/etc/ossec.conf"

# Active Response block (present only when the prevent run enabled it).
sed -i '/<!-- cipherguard:ar:begin -->/,/<!-- cipherguard:ar:end -->/d' "$OSSEC/etc/ossec.conf"
if [ -f "$SRC/ossec-ar.xml" ]; then
  cat "$SRC/ossec-ar.xml" >>"$OSSEC/etc/ossec.conf"
  echo "Active Response enabled"
else
  echo "Active Response disabled"
fi

"$OSSEC/bin/wazuh-analysisd" -t || restore

rm -rf "$BACKUP"

if [ "$(fingerprint)" = "$BEFORE" ] && systemctl is-active --quiet wazuh-manager; then
  echo "Configuration unchanged; manager not restarted (agents stay connected)"
  exit 0
fi

systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager && echo "Wazuh manager restarted with CipherGuard config"

# Agents reconnect on their own within ~1 min of a restart. Report any that do
# not, so a deploy never silently runs a test against a disconnected node.
# (Agent 000 is the manager itself.) Not fatal: there may be no nodes yet.
for _ in $(seq 1 24); do
  agents="$("$OSSEC/bin/agent_control" -l 2>/dev/null | grep -E '^ +ID: ' | grep -v 'ID: 000' || true)"
  down="$(printf '%s\n' "$agents" | grep -v ', Active' | grep -E 'ID: ' || true)"
  [ -n "$agents" ] && [ -z "$down" ] && break
  sleep 5
done
if [ -z "$agents" ]; then
  echo "No node agents enrolled yet"
elif [ -n "$down" ]; then
  echo "WARNING: node agents not Active after restart (restart wazuh-agent on these nodes):"
  printf '%s\n' "$down"
else
  echo "All node agents Active: $(printf '%s\n' "$agents" | wc -l)"
fi
