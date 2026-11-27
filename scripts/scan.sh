#!/usr/bin/env bash
# Shift-left scanners, run in pinned containers so CI and laptops behave the same.
#
#   scripts/scan.sh secrets          gitleaks over git history
#   scripts/scan.sh dockerfile       hadolint on every Dockerfile
#   scripts/scan.sh sast             Semgrep (Python, Dockerfile, GitHub Actions)
#   scripts/scan.sh iac              Checkov (Terraform, Dockerfile, Actions, Kubernetes/Helm)
#   scripts/scan.sh policies         Kyverno CLI tests against the rendered charts
#   scripts/scan.sh detection        Falco rule validation + Wazuh rules replayed in analysisd
#   scripts/scan.sh image <ref>      Trivy: fail on fixable HIGH/CRITICAL
#   scripts/scan.sh sbom <ref>       Syft SPDX JSON to stdout
#   scripts/scan.sh all              everything except image/sbom
#   scripts/scan.sh negative         prove each scanner blocks a known-bad change
set -euo pipefail

GITLEAKS_IMG="zricethezav/gitleaks:v8.30.1"
HADOLINT_IMG="hadolint/hadolint:v2.15.1"
SEMGREP_IMG="semgrep/semgrep:1.186.0"
CHECKOV_IMG="bridgecrew/checkov:3.4.5"
TRIVY_IMG="aquasec/trivy:0.76.2"
SYFT_IMG="anchore/syft:v1.57.2"
HELM_IMG="alpine/helm:4.3.2"
KYVERNO_IMG="ghcr.io/kyverno/kyverno-cli:v1.20.0"
FALCO_IMG="falcosecurity/falco:0.45.2"
WAZUH_IMG="wazuh/wazuh-manager:4.14.10"

ROOT="$(git rev-parse --show-toplevel)"
NEG="tests/negative"

run() { docker run --rm -v "$ROOT:/src:ro" -w /src "$@"; }
docker_sock=(-v /var/run/docker.sock:/var/run/docker.sock -v cg-trivy-cache:/root/.cache)

secrets() {
  run "$GITLEAKS_IMG" git /src --redact --no-banner --config /src/.gitleaks.toml
}

dockerfile() {
  local files
  files=$(cd "$ROOT" && git ls-files '*Dockerfile*' | grep -v "^$NEG/" || true)
  [ -z "$files" ] && return 0
  # shellcheck disable=SC2086
  run "$HADOLINT_IMG" hadolint --config /src/.hadolint.yaml $files
}

sast() {
  run "$SEMGREP_IMG" semgrep scan \
    --config p/python --config p/dockerfile --config p/github-actions \
    --exclude "$NEG" --error --metrics=off --quiet
}

render_demo_app() {
  docker run --rm -v "$ROOT/charts:/charts:ro" "$HELM_IMG" template demo-app /charts/demo-app -n demo \
    --set image.repository="${1:-registry.example.com/cipherguard/demo-app}" \
    --set image.digest="sha256:$(printf '0%.0s' $(seq 64))" "${@:2}"
}

iac() {
  run "$CHECKOV_IMG" --config-file /src/.checkov.yaml -d /src
  # Rendered Helm output, as it would reach the cluster.
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  render_demo_app >"$tmp/demo-app.yaml"
  chmod -R a+rX "$tmp"
  docker run --rm -v "$tmp:/rendered:ro" "$CHECKOV_IMG" --framework kubernetes --compact --quiet -d /rendered
}

policies() {
  # Render the charts exactly as deployed (minus real account IDs), then run
  # the Kyverno CLI test suite. Signature verification needs a live registry,
  # so it is covered by `cosign verify` in build.yml and the smoke test.
  local tmp repo="registry.example.com/cipherguard/demo-app"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  cp "$ROOT"/tests/policies/* "$tmp/"
  docker run --rm -v "$ROOT/charts:/charts:ro" "$HELM_IMG" template cp /charts/cluster-policies \
    --set images.repository="$repo" --set mode=Enforce \
    --show-only templates/restrict-registries.yaml \
    --show-only templates/pod-security.yaml \
    --show-only templates/rbac-guardrails.yaml >"$tmp/policies.yaml"
  # Signature policy rendered against a repo no fixture uses: the CLI compiles
  # its CEL but never tries to reach a registry.
  docker run --rm -v "$ROOT/charts:/charts:ro" "$HELM_IMG" template cp /charts/cluster-policies \
    --set images.repository=example.invalid/never-matches --show-only templates/verify-images.yaml \
    >>"$tmp/policies.yaml"
  render_demo_app "$repo" --show-only templates/deployment.yaml >"$tmp/demo-app.yaml"
  chmod -R a+rX "$tmp" # kyverno-cli runs as non-root
  docker run --rm -v "$tmp:/tests:ro" "$KYVERNO_IMG" test /tests --detailed-results
}

detection() {
  # 0. query-alerts.sh parser (phase 7): earliest alert per rule, benign excluded.
  local qa
  qa="$(mktemp -d)"
  cat >"$qa/alerts.json" <<'JSON'
{"timestamp":"2026-11-19T04:30:40.000+0000","rule":{"id":"100113","level":12,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:50.000+0000","rule":{"id":"100113","level":12,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:55.000+0000","rule":{"id":"100130","level":14,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:29:00.000+0000","rule":{"id":"100110","level":10,"groups":["cipherguard"]}}
{"timestamp":"2026-11-19T04:30:30.000+0000","rule":{"id":"5402","level":3,"groups":["syslog"]}}
JSON
  sed "s#ALERTS=/var/ossec/logs/alerts/alerts.json#ALERTS=$qa/alerts.json#" \
    "$ROOT/detection/wazuh/query-alerts.sh" >"$qa/q.sh"
  local since; since="$(date -u -d "2026-11-19T04:30:00Z" +%s 2>/dev/null || echo 1795062600)"
  local got_first got_crit
  got_first="$(bash "$qa/q.sh" first "$since" | awk '{print $1}' | tr '\n' ',')"
  got_crit="$(bash "$qa/q.sh" crit "$since")"
  rm -rf "$qa"
  # first: 100113+100130 (100110 older, 5402 benign); crit: 3 events at level>=12.
  [ "$got_first" = "100113,100130," ] || { echo "query-alerts first wrong: $got_first"; return 1; }
  [ "$got_crit" = "3" ] || { echo "query-alerts crit wrong: $got_crit"; return 1; }
  echo "query-alerts parser: ok"

  # 0b. GuardDuty auto-fix Lambda guards (fake IAM client, no AWS calls).
  python3 "$ROOT/tests/lambda/test_autofix.py" || return 1

  # 1. Falco: custom rules load cleanly next to the default ruleset.
  docker run --rm -v "$ROOT/detection/falco:/rules:ro" --entrypoint falco "$FALCO_IMG" \
    -V /etc/falco/falco_rules.yaml -V /rules/cipherguard_rules.yaml 2>&1 | tee /tmp/cg-falco-validate.log
  grep -q "cipherguard_rules.yaml: Ok$" /tmp/cg-falco-validate.log || { echo "Falco rules invalid or have warnings"; return 1; }

  # 2. Wazuh: rules compile in a real analysisd, and each sample event hits the expected rule.
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/rules"
  for f in "$ROOT"/detection/wazuh/rules/*.xml; do
    sed 's/__NAT_EIP__/13\\.250\\.1\\.2/g' "$f" >"$tmp/rules/$(basename "$f")"
  done
  cp "$ROOT"/tests/detection/* "$tmp/"
  cp "$ROOT/detection/wazuh/shared/eks-nodes/agent.conf" "$tmp/agent.conf"
  sed -e 's|__REGION__|ap-southeast-1|g' -e 's|__EKS_LOG_GROUP__|/aws/eks/cipherguard-eks/cluster|g' \
      -e 's|__CLOUDTRAIL_BUCKET__|cipherguard-cloudtrail-123456789012|g' \
      -e 's|__GUARDDUTY_LOG_GROUP__|/cipherguard/guardduty|g' \
      "$ROOT/detection/wazuh/ossec-aws.xml" >"$tmp/ossec-aws.xml"
  cp "$ROOT/detection/wazuh/ossec-ar.xml" "$tmp/ossec-ar.xml"
  cp "$ROOT/detection/wazuh/active-response/cipherguard-isolate.sh" "$tmp/cipherguard-isolate.sh"
  chmod -R a+rX "$tmp"
  docker run --rm -v "$tmp:/tests:ro" --entrypoint bash "$WAZUH_IMG" -c '
    set -e
    # Restore the files the image entrypoint normally copies into place.
    cp -an /var/ossec/data_tmp/permanent/var/ossec/. /var/ossec/
    cp -an /var/ossec/data_tmp/exclusion/var/ossec/. /var/ossec/
    cp /tests/rules/*.xml /var/ossec/etc/rules/
    install -o root -g wazuh -m 0750 /tests/cipherguard-isolate.sh /var/ossec/active-response/bin/cipherguard-isolate.sh
    chown -R wazuh:wazuh /var/ossec/etc
    /var/ossec/bin/verify-agent-conf -f /tests/agent.conf
    cat /tests/ossec-aws.xml /tests/ossec-ar.xml >> /var/ossec/etc/ossec.conf
    /var/ossec/bin/wazuh-analysisd -t
    /var/ossec/bin/wazuh-modulesd -t
    /var/ossec/bin/wazuh-db
    /var/ossec/bin/wazuh-analysisd
    /var/ossec/framework/python/bin/python3 /tests/logtest.py /tests/cases.json
    /var/ossec/framework/python/bin/python3 /tests/ar_test.py'
}

image() {
  local ref="${1:?image ref required}"
  docker run --rm "${docker_sock[@]}" "$TRIVY_IMG" image \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress "$ref"
}

sbom() {
  local ref="${1:?image ref required}"
  docker run --rm "${docker_sock[@]}" "$SYFT_IMG" "$ref" -o spdx-json --quiet
}

# Each check must FAIL on its fixture; a pass means the gate is broken.
expect_fail() {
  local name="$1"; shift
  if "$@" >/tmp/cg-negative.log 2>&1; then
    echo "FAIL  $name: scanner did not block the bad change"; cat /tmp/cg-negative.log; return 1
  fi
  echo "ok    $name: blocked"
}

negative() {
  local tmp rc=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # 1. Secret: generated at runtime so no key-shaped string lives in the repo.
  local akid secret
  # pipefail off here: head closing the pipe makes tr exit with SIGPIPE.
  akid="AKIA$(set +o pipefail; LC_ALL=C tr -dc 'A-Z2-7' </dev/urandom | head -c 16)"
  secret="$(set +o pipefail; LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)"
  printf 'aws_access_key_id = %s\naws_secret_access_key = %s\n' "$akid" "$secret" >"$tmp/credentials"
  expect_fail "gitleaks: AWS key in file" \
    docker run --rm -v "$tmp:/scan:ro" "$GITLEAKS_IMG" dir /scan --no-banner || rc=1

  # 2. Root container Dockerfile.
  expect_fail "hadolint: USER root" \
    run "$HADOLINT_IMG" hadolint --config /src/.hadolint.yaml "$NEG/Dockerfile.root" || rc=1
  # Checkov auto-loads ./.checkov.yaml, whose skip-path excludes the fixtures,
  # so run it from inside the fixture directory.
  local neg_run=(docker run --rm -v "$ROOT/$NEG:/neg:ro" -w /neg "$CHECKOV_IMG" --compact --quiet)
  expect_fail "checkov: root container" \
    "${neg_run[@]}" --framework dockerfile -f Dockerfile.root || rc=1

  # 3. Public S3 bucket.
  expect_fail "checkov: public S3 bucket" \
    "${neg_run[@]}" --framework terraform -d terraform || rc=1

  # 4. Vulnerable base image.
  docker build -q -t cg-negative:vulnerable -f "$ROOT/$NEG/Dockerfile.root" "$ROOT/$NEG" >/dev/null
  expect_fail "trivy: vulnerable base image" image cg-negative:vulnerable || rc=1

  return $rc
}

cmd="${1:-all}"; shift || true
case "$cmd" in
  secrets|dockerfile|sast|iac|policies|detection|negative) "$cmd" ;;
  image|sbom) "$cmd" "$@" ;;
  all) secrets && dockerfile && sast && iac && policies && detection ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
