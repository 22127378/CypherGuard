#!/usr/bin/env bash
# Shift-left scanners, run in pinned containers so CI and laptops behave the same.
#
#   scripts/scan.sh secrets          gitleaks over git history
#   scripts/scan.sh dockerfile       hadolint on every Dockerfile
#   scripts/scan.sh sast             Semgrep (Python, Dockerfile, GitHub Actions)
#   scripts/scan.sh iac              Checkov (Terraform, Dockerfile, Actions, Kubernetes/Helm)
#   scripts/scan.sh policies         Kyverno CLI tests against the rendered charts
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
  secrets|dockerfile|sast|iac|policies|negative) "$cmd" ;;
  image|sbom) "$cmd" "$@" ;;
  all) secrets && dockerfile && sast && iac && policies ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
