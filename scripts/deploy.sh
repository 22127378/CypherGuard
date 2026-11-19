#!/usr/bin/env bash
# Deploy the platform (Kyverno + policies) and the demo app to the lab cluster.
#
#   scripts/deploy.sh                     prevent run: policies Enforce, network default-deny
#   scripts/deploy.sh --mode detect       detect-only run: policies Audit, egress open
#   scripts/deploy.sh --digest sha256:..  deploy a specific signed image
#
# Without --digest it deploys the image tagged with the current commit, or the
# most recently pushed image if that commit was never built.
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-1}"
PROJECT="cipherguard"
KYVERNO_CHART_VERSION="3.10.0"
FALCO_CHART_VERSION="9.2.2"
ROOT="$(git rev-parse --show-toplevel)"

MODE="enforce"
DIGEST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --digest) DIGEST="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  enforce) POLICY_MODE="Enforce"; NET_MODE="enforce" ;;
  detect)  POLICY_MODE="Audit";   NET_MODE="open" ;;
  *) echo "--mode must be enforce or detect" >&2; exit 2 ;;
esac

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REPO_NAME="$PROJECT/demo-app"
REPO="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME"

if [ -z "$DIGEST" ]; then
  TAG="${IMAGE_TAG:-$(git -C "$ROOT" rev-parse HEAD)}"
  DIGEST="$(aws ecr describe-images --region "$REGION" --repository-name "$REPO_NAME" \
    --image-ids "imageTag=$TAG" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null || true)"
  if [ -z "$DIGEST" ] || [ "$DIGEST" = "None" ]; then
    echo "No image tagged $TAG; using the most recently pushed application image."
    DIGEST="$(aws ecr describe-images --region "$REGION" --repository-name "$REPO_NAME" \
      --query 'sort_by(imageDetails[?imageTags != null && !starts_with(imageTags[0], `sha256-`)], &imagePushedAt)[-1].imageDigest' \
      --output text)"
  fi
fi
[[ "$DIGEST" == sha256:* ]] || { echo "could not resolve an image digest" >&2; exit 1; }

echo "Deploying $REPO@$DIGEST (mode: $MODE)"

helm repo add kyverno https://kyverno.github.io/kyverno >/dev/null 2>&1 || true
helm repo update kyverno >/dev/null

helm upgrade --install kyverno kyverno/kyverno \
  --version "$KYVERNO_CHART_VERSION" \
  --namespace kyverno --create-namespace \
  -f "$ROOT/platform/kyverno/values.yaml" \
  --set-string "admissionController.rbac.serviceAccount.annotations.eks\.amazonaws\.com/role-arn=arn:aws:iam::$ACCOUNT:role/$PROJECT-kyverno" \
  --wait --timeout 5m

kubectl apply -f "$ROOT/platform/namespaces.yaml"

# Runtime detection: Falco on every node, events to /var/log/falco for the Wazuh agent.
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null
helm upgrade --install falco falcosecurity/falco \
  --version "$FALCO_CHART_VERSION" \
  --namespace falco --create-namespace \
  -f "$ROOT/platform/falco/values.yaml" \
  --set-file "customRules.cipherguard_rules\.yaml=$ROOT/detection/falco/cipherguard_rules.yaml" \
  --wait --timeout 10m

# Detection-as-code on the Wazuh manager (rules, agent group config, AWS inputs).
# Active Response only in the prevent run, so it does not cut short the
# detect-only run while we are measuring alerts.
AR_FLAG=""
[ "$MODE" = "enforce" ] && AR_FLAG="--ar"
"$ROOT/scripts/wazuh-sync.sh" --wait $AR_FLAG

helm upgrade --install cluster-policies "$ROOT/charts/cluster-policies" \
  --set "images.repository=$REPO" \
  --set "mode=$POLICY_MODE" \
  --wait
# Give Kyverno time to compile the CEL policies and register its webhooks.
for _ in $(seq 1 24); do
  ready="$(kubectl get validatingpolicies,imagevalidatingpolicies -o jsonpath='{range .items[*]}{.status.conditionStatus.ready}{"\n"}{end}' 2>/dev/null || true)"
  [ -n "$ready" ] && ! grep -qv '^true$' <<<"$ready" && break
  sleep 5
done
kubectl get validatingpolicies,imagevalidatingpolicies

helm upgrade --install demo-app "$ROOT/charts/demo-app" \
  --namespace demo \
  --set "image.repository=$REPO" \
  --set "image.digest=$DIGEST" \
  --set "serviceAccount.roleArn=arn:aws:iam::$ACCOUNT:role/$PROJECT-demo-app" \
  --set "networkPolicy.mode=$NET_MODE" \
  --wait --timeout 5m

"$ROOT/scripts/smoke.sh" --mode "$MODE"
