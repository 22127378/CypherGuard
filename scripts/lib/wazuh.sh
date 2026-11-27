# shellcheck shell=bash
# Render detection/wazuh into a ready-to-apply bundle. Used both for the live
# manager (scripts/wazuh-sync.sh) and for the CI replay (scripts/scan.sh
# detection), so the two can never drift apart in how placeholders are filled.
#
# Placeholders in the source tree:
#   rules/*.xml      __NAT_EIP__ (written as a regex, dots escaped)
#   ossec-aws.xml    __REGION__ __EKS_LOG_GROUP__ __CLOUDTRAIL_BUCKET__ __GUARDDUTY_LOG_GROUP__
[ -n "${CG_WAZUH_LOADED:-}" ] && return 0
CG_WAZUH_LOADED=1
# shellcheck source=common.sh
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

WAZUH_SRC="$ROOT/detection/wazuh"
EKS_LOG_GROUP="/aws/eks/$PROJECT-eks/cluster"
GUARDDUTY_LOG_GROUP="/$PROJECT/guardduty"
cloudtrail_bucket() { echo "$PROJECT-cloudtrail-$1"; }

# wazuh_render <dest> <nat_eip> <account_id> [--no-cloudtrail] [--no-guardduty] [--no-ar]
#   --no-cloudtrail / --no-guardduty  drop that AWS input (resource not in the lab)
#   --no-ar                           drop Active Response (detect-only run);
#                                     apply.sh merges ossec-ar.xml only if present
wazuh_render() {
  local dest="$1" nat="$2" account="$3" opt
  shift 3
  mkdir -p "$dest"
  cp -r "$WAZUH_SRC/." "$dest/"
  sed -i "s/__NAT_EIP__/${nat//./\\\\.}/g" "$dest"/rules/*.xml
  sed -i -e "s|__REGION__|$REGION|g" -e "s|__EKS_LOG_GROUP__|$EKS_LOG_GROUP|g" \
    -e "s|__CLOUDTRAIL_BUCKET__|$(cloudtrail_bucket "$account")|g" \
    -e "s|__GUARDDUTY_LOG_GROUP__|$GUARDDUTY_LOG_GROUP|g" "$dest/ossec-aws.xml"
  for opt in "$@"; do
    case "$opt" in
      --no-cloudtrail) sed -i '/cipherguard:cloudtrail:begin/,/cipherguard:cloudtrail:end/d' "$dest/ossec-aws.xml" ;;
      --no-guardduty) sed -i '/cipherguard:guardduty:begin/,/cipherguard:guardduty:end/d' "$dest/ossec-aws.xml" ;;
      --no-ar) rm -f "$dest/ossec-ar.xml" ;;
      *) echo "wazuh_render: unknown option $opt" >&2; return 2 ;;
    esac
  done
  if grep -rl '__[A-Z_]*__' "$dest/rules" "$dest/ossec-aws.xml" >/dev/null 2>&1; then
    echo "wazuh_render: unfilled placeholder in $(grep -rl '__[A-Z_]*__' "$dest/rules" "$dest/ossec-aws.xml")" >&2
    return 1
  fi
}
