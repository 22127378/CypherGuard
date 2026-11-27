#!/usr/bin/env bash
# One-shot verification run: deploy (detect) -> attack+measure -> evidence ->
# deploy (enforce) -> attack -> evidence -> short baseline -> evidence.
# Run once the EKS cluster + node group are Active. Logs everything to
# $CG_LOG_DIR/cg-*.log (default /tmp) and docs/evidence/.
set -uo pipefail
. "$(git rev-parse --show-toplevel)/scripts/lib/common.sh"

LOG="$CG_LOG_DIR/cg-full-run.log"
: > "$LOG"
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

run() { # run <label> <cmd...>  (writes $CG_LOG_DIR/cg-<label>.log, tee'd to $LOG)
  local label="$1"; shift
  log "=== $label ==="
  "$@" > >(tee -a "$LOG" "$CG_LOG_DIR/cg-${label}.log") 2>&1
  local rc=$?
  log "=== $label exit=$rc ==="
  return $rc
}

log "Step 1: deploy-detect"
run "deploy-detect" "$ROOT/scripts/deploy.sh" --mode detect
cp "$CG_LOG_DIR/cg-deploy-detect.log" "$CG_LOG_DIR/cg-smoke.log" 2>/dev/null || true

log "Step 2: attack chain + latency measurement (detect-only; runs the chain once)"
run "measure" "$ROOT/scripts/measure-latency.sh"
cp "$CG_LOG_DIR/cg-measure.log" "$CG_LOG_DIR/cg-attack.log" 2>/dev/null || true

log "Step 3: collect evidence (detect-only)"
"$ROOT/scripts/collect-evidence.sh" detect-only

log "Step 4: deploy-enforce (prevent run + Active Response)"
run "deploy-enforce" "$ROOT/scripts/deploy.sh" --mode enforce

log "Step 5: attack chain (prevent run)"
run "attack-enforce" "$ROOT/attack/run-attack.sh" --mode enforce
cp "$CG_LOG_DIR/cg-attack-enforce.log" "$CG_LOG_DIR/cg-attack.log" 2>/dev/null || true

log "Step 6: pod state after Active Response (restartCount > 0 if isolated)"
kubectl -n "$NS" get pods -o wide 2>&1 | tee -a "$LOG"

log "Step 7: collect evidence (prevent run)"
"$ROOT/scripts/collect-evidence.sh" prevent-run

log "Step 8: short baseline (5 min) for a false-positive sanity check"
run "baseline-short" env CG_BASELINE_SECONDS=300 "$ROOT/scripts/baseline.sh"

log "Step 9: collect evidence (baseline)"
"$ROOT/scripts/collect-evidence.sh" baseline-short

log "ALL STEPS DONE. Full log: $LOG"
