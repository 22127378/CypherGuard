#!/usr/bin/env bash
# Push detection/wazuh (rules, agent group config, AWS module block) to the
# Wazuh manager through SSM Run Command. No SSH, no inbound ports.
#
#   scripts/wazuh-sync.sh            sync once (fails if the manager is not ready)
#   scripts/wazuh-sync.sh --wait     retry for up to 20 min while the manager installs
#   scripts/wazuh-sync.sh --ar       also enable Active Response (prevent run only)
#
# The manager is restarted only when the synced config actually changed
# (apply.sh compares a fingerprint), because each restart drops the node agents'
# connections; found live, repeated restarts left agents "Disconnected". After a
# restart apply.sh waits for the agents and prints a WARNING naming any that are
# not Active. Fix for those: restart wazuh-agent on that node (nodes have no SSM
# agent; use a privileged kube-system pod chrooted into the host).
set -euo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/wazuh.sh"

WAIT=0
AR=0
for a in "$@"; do
  case "$a" in
    --wait) WAIT=1 ;;
    --ar) AR=1 ;;
    *) die "unknown argument: $a" ;;
  esac
done

ACCOUNT="$(aws_account)"
INSTANCE="$(wazuh_instance)" || exit 1
NAT_EIP="$(aws ec2 describe-nat-gateways \
  --filter "Name=tag:Project,Values=CipherGuard" "Name=state,Values=available" \
  --query 'NatGateways[0].NatGatewayAddresses[0].PublicIp' --output text)"

# Drop the inputs whose AWS resource is not in this lab (feature flags off).
opts=()
if ! aws s3api head-bucket --bucket "$(cloudtrail_bucket "$ACCOUNT")" >/dev/null 2>&1; then
  echo "No lab CloudTrail bucket; CloudTrail input disabled."
  opts+=(--no-cloudtrail)
fi
if ! aws logs describe-log-groups --log-group-name-prefix "$GUARDDUTY_LOG_GROUP" \
     --query 'logGroups[0].logGroupName' --output text 2>/dev/null | grep -q "$GUARDDUTY_LOG_GROUP"; then
  echo "No GuardDuty log group; GuardDuty input disabled."
  opts+=(--no-guardduty)
fi
if [ "$AR" = 1 ]; then
  echo "Active Response: on (prevent run)"
else
  echo "Active Response: off (detect-only)"
  opts+=(--no-ar)
fi

make_tmpdir STAGE
wazuh_render "$STAGE/bundle" "$NAT_EIP" "$ACCOUNT" "${opts[@]}"
BUNDLE="$(tar czf - -C "$STAGE/bundle" . | base64 -w0)"
echo "Bundle: ${#BUNDLE} bytes (NAT EIP $NAT_EIP, instance $INSTANCE)"
CMD="set -e; d=\$(mktemp -d); echo '$BUNDLE' | base64 -d | tar xz -C \"\$d\"; bash \"\$d/apply.sh\"; rc=\$?; rm -rf \"\$d\"; exit \$rc"

# apply.sh may wait up to 2 min for agents after a restart, hence the timeout.
deadline=$(( $(now) + 1200 ))
while :; do
  if ssm_run "$INSTANCE" "$CMD" 420; then
    echo "wazuh-sync: done"
    exit 0
  fi
  # rc 3 = manager still installing; SendFailed = SSM agent not up yet.
  case "$SSM_STATUS/$SSM_RC" in
    SendFailed/*|*/3) ;;
    *) die "wazuh-sync: failed ($SSM_STATUS, rc=$SSM_RC)" ;;
  esac
  [ "$WAIT" = 1 ] && [ "$(now)" -lt "$deadline" ] || die "Wazuh manager not ready"
  echo "Waiting for the Wazuh manager (SSM agent or install not ready)..."
  sleep 30
done
