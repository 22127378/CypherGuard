#!/usr/bin/env bash
# Push detection/wazuh (rules, agent group config, AWS module block) to the
# Wazuh manager through SSM Run Command. No SSH, no inbound ports.
#
#   scripts/wazuh-sync.sh            sync once (fails if the manager is not ready)
#   scripts/wazuh-sync.sh --wait     retry for up to 20 min while the manager installs
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-1}"
PROJECT="cipherguard"
ROOT="$(git rev-parse --show-toplevel)"
WAIT=0
[ "${1:-}" = "--wait" ] && WAIT=1

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
INSTANCE="$(aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=$PROJECT-wazuh" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)"
[[ "$INSTANCE" == i-* ]] || { echo "Wazuh instance not found (is the lab up?)" >&2; exit 1; }

NAT_EIP="$(aws ec2 describe-nat-gateways --region "$REGION" \
  --filter "Name=tag:Project,Values=CipherGuard" "Name=state,Values=available" \
  --query 'NatGateways[0].NatGatewayAddresses[0].PublicIp' --output text)"
BUCKET="$PROJECT-cloudtrail-$ACCOUNT"
LOG_GROUP="/aws/eks/$PROJECT-eks/cluster"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -r "$ROOT/detection/wazuh/." "$STAGE/"
NAT_RE="${NAT_EIP//./\\\\.}"
sed -i "s/__NAT_EIP__/$NAT_RE/g" "$STAGE"/rules/*.xml
sed -i -e "s|__REGION__|$REGION|g" -e "s|__EKS_LOG_GROUP__|$LOG_GROUP|g" -e "s|__CLOUDTRAIL_BUCKET__|$BUCKET|g" "$STAGE/ossec-aws.xml"
if ! aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "No lab CloudTrail bucket; CloudTrail input disabled."
  sed -i '/cipherguard:cloudtrail:begin/,/cipherguard:cloudtrail:end/d' "$STAGE/ossec-aws.xml"
fi

BUNDLE="$(tar czf - -C "$STAGE" . | base64 -w0)"
echo "Bundle: ${#BUNDLE} bytes (NAT EIP $NAT_EIP, instance $INSTANCE)"

python3 -I - "$BUNDLE" >"$STAGE/params.json" <<'PY'
import json, sys
b = sys.argv[1]
cmd = ("set -e; d=$(mktemp -d); echo '" + b + "' | base64 -d | tar xz -C \"$d\"; "
       "bash \"$d/apply.sh\"; rc=$?; rm -rf \"$d\"; exit $rc")
print(json.dumps({"commands": [cmd]}))
PY

deadline=$(( $(date +%s) + 1200 ))
while :; do
  CMD_ID="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
    --document-name AWS-RunShellScript --comment "cipherguard wazuh-sync" \
    --parameters "file://$STAGE/params.json" --query Command.CommandId --output text 2>/dev/null || true)"
  if [ -n "$CMD_ID" ]; then
    aws ssm wait command-executed --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" 2>/dev/null || true
    read -r STATUS RC < <(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" \
      --instance-id "$INSTANCE" --query '[Status,ResponseCode]' --output text)
    aws ssm get-command-invocation --region "$REGION" --command-id "$CMD_ID" --instance-id "$INSTANCE" \
      --query '[StandardOutputContent,StandardErrorContent]' --output text
    [ "$STATUS" = "Success" ] && { echo "wazuh-sync: done"; exit 0; }
    # 3 = manager still installing; anything else is a real failure.
    [ "$RC" != "3" ] && { echo "wazuh-sync: failed ($STATUS, rc=$RC)" >&2; exit 1; }
  fi
  [ "$WAIT" = 1 ] && [ "$(date +%s)" -lt "$deadline" ] || { echo "Wazuh manager not ready" >&2; exit 1; }
  echo "Waiting for the Wazuh manager (SSM agent or install not ready)..."
  sleep 30
done
