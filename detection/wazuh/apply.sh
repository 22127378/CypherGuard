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

"$OSSEC/bin/wazuh-analysisd" -t || restore

systemctl restart wazuh-manager
systemctl is-active --quiet wazuh-manager && echo "Wazuh manager restarted with CipherGuard config"
rm -rf "$BACKUP"
