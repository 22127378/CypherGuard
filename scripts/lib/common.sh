# shellcheck shell=bash
# Shared helpers for the operator scripts (scripts/*, attack/run-attack.sh).
# Source it, do not run it:   . "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"
#
# Scripts that run ON a host (detection/wazuh/apply.sh, query-alerts.sh, the
# Active Response script) are shipped there on their own and must stay
# self-contained, so they do not use this file.
[ -n "${CG_COMMON_LOADED:-}" ] && return 0
CG_COMMON_LOADED=1

ROOT="${ROOT:-$(git rev-parse --show-toplevel)}"
REGION="${AWS_REGION:-ap-southeast-1}"
export AWS_REGION="$REGION" # every aws call below inherits it; no --region needed
PROJECT="cipherguard"
NS="demo"
APP_LABEL="app.kubernetes.io/name=demo-app"
CG_LOG_DIR="${CG_LOG_DIR:-/tmp}" # run logs shared between run-full-verification and collect-evidence

die() { echo "$*" >&2; exit 1; }
ts() { date '+%H:%M:%S'; }
now() { date -u +%s; }

# Cleanup actions run on exit, so several helpers can each register their own
# without overwriting one another's trap.
CG_ON_EXIT=()
on_exit() {
  CG_ON_EXIT+=("$1")
  # shellcheck disable=SC2154 # _c is the loop variable inside the trap string
  trap 'for _c in "${CG_ON_EXIT[@]}"; do eval "$_c"; done' EXIT
}

# make_tmpdir <var>: create a temporary directory, removed on exit, into <var>.
# (Not "$(...)": the exit trap would then fire in the subshell, at once.)
make_tmpdir() {
  local d
  d="$(mktemp -d)"
  on_exit "rm -rf '$d'"
  printf -v "$1" '%s' "$d"
}

# --mode enforce|detect, shared by deploy, smoke and the attack runner.
check_mode() {
  case "$1" in enforce|detect) ;; *) die "--mode must be enforce or detect (got '$1')" ;; esac
}

# ---------- AWS / Terraform ----------

tf_output() { terraform -chdir="$ROOT/infra/terraform" output -raw "$1" 2>/dev/null || true; }
aws_account() { aws sts get-caller-identity --query Account --output text; }

# Instance id of the running EC2 instance tagged Name=<name>, or empty.
instance_id() {
  local id
  id="$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=$1" "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || true)"
  [[ "$id" == i-* ]] && echo "$id"
  return 0
}

# Usage: INSTANCE="$(wazuh_instance)" || exit 1
wazuh_instance() {
  local id
  id="$(instance_id "$PROJECT-wazuh")"
  [ -n "$id" ] || { echo "Wazuh instance not found (is the lab up?)" >&2; return 1; }
  echo "$id"
}

# ssm_run <instance> <shell command> [timeout_s]
# Runs the command with AWS-RunShellScript, prints its stdout (stderr goes to
# our stderr) and returns 0 only on Success. Sets SSM_STATUS and SSM_RC for
# callers that need them (call it directly, not inside $(...), for those).
# Polls instead of `aws ssm wait`, which gives up after ~100 s (found live).
SSM_STATUS=""
# shellcheck disable=SC2034 # read by callers (wazuh-sync.sh)
SSM_RC=""
ssm_run() {
  local inst="$1" cmd="$2" timeout="${3:-300}" params id deadline s out err
  params="$(mktemp)"
  # JSON-encode in Python: the command may be a large base64 bundle with quotes.
  python3 -I -c 'import json,sys; print(json.dumps({"commands": [sys.argv[1]]}))' "$cmd" >"$params"
  id="$(aws ssm send-command --instance-ids "$inst" --document-name AWS-RunShellScript \
    --comment "$PROJECT" --parameters "file://$params" --query Command.CommandId --output text 2>/dev/null || true)"
  rm -f "$params"
  SSM_STATUS="SendFailed"; SSM_RC=""
  [ -n "$id" ] && [ "$id" != None ] || return 1

  deadline=$(( $(now) + timeout ))
  while [ "$(now)" -lt "$deadline" ]; do
    s="$(aws ssm get-command-invocation --command-id "$id" --instance-id "$inst" \
      --query Status --output text 2>/dev/null || echo Pending)"
    case "$s" in Pending|InProgress|Delayed) sleep 3 ;; *) break ;; esac
  done
  # shellcheck disable=SC2034
  read -r SSM_STATUS SSM_RC < <(aws ssm get-command-invocation --command-id "$id" --instance-id "$inst" \
    --query '[Status,ResponseCode]' --output text 2>/dev/null || echo "Unknown -1")
  out="$(aws ssm get-command-invocation --command-id "$id" --instance-id "$inst" \
    --query StandardOutputContent --output text 2>/dev/null || true)"
  err="$(aws ssm get-command-invocation --command-id "$id" --instance-id "$inst" \
    --query StandardErrorContent --output text 2>/dev/null || true)"
  [ -n "$out" ] && printf '%s\n' "$out"
  [ -n "$err" ] && printf '%s\n' "$err" >&2
  [ "$SSM_STATUS" = Success ]
}

# ssm_script <instance> <local script> [args...]
# Ships a local script to the host inline and runs it there with bash.
ssm_script() {
  local inst="$1" script="$2" b64
  shift 2
  b64="$(base64 -w0 "$script")"
  ssm_run "$inst" "d=\$(mktemp -d); echo '$b64' | base64 -d >\"\$d/s.sh\"; bash \"\$d/s.sh\" $*; rc=\$?; rm -rf \"\$d\"; exit \$rc"
}

# wazuh_query <instance> first|crit|count <since_epoch>
# Runs detection/wazuh/query-alerts.sh on the manager.
wazuh_query() { ssm_script "$1" "$ROOT/detection/wazuh/query-alerts.sh" "$2" "$3"; }

# ---------- Kubernetes ----------

# Name of a Running demo-app pod, or empty. Running only: found live, an
# evicted pod listed first made every exec fail.
demo_pod() {
  kubectl -n "$NS" get pod -l "$APP_LABEL" --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

# Usage: POD="$(require_demo_pod)" || exit 1
require_demo_pod() {
  local p
  p="$(demo_pod)"
  [ -n "$p" ] || { echo "no Running demo-app pod; run 'make deploy' first" >&2; return 1; }
  echo "$p"
}

# in_pod <pod> <sh command>: run inside the pod, indent the output, never fail.
in_pod() { kubectl -n "$NS" exec "$1" -- sh -c "$2" 2>&1 | sed 's/^/    /' || true; }

# port_forward_demo <local_port>: forward svc/demo-app, wait until /healthz
# answers (up to 10 s), stop it on exit.
port_forward_demo() {
  local port="$1" pid
  kubectl -n "$NS" port-forward svc/demo-app "$port:80" >/dev/null 2>&1 &
  pid=$!
  on_exit "kill $pid 2>/dev/null || true"
  for _ in $(seq 1 20); do
    curl -fs "localhost:$port/healthz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# helm_repo <name> <url>: add (idempotent) and refresh one chart repo.
helm_repo() {
  helm repo add "$1" "$2" >/dev/null 2>&1 || true
  helm repo update "$1" >/dev/null
}
