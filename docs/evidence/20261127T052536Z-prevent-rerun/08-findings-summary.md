# Re-run 2026-11-27: findings summary

Fresh deploy from zero (`terraform apply` on an empty state) to re-verify the
three config fixes made offline on 2026-11-27. Evidence folders:
`20261127T050329Z-detect-rerun/` (detect-only) and
`20261127T052536Z-prevent-rerun/` (prevent, incl. `09-active-response-node-logs.txt`).

## Results

| Check | Result |
|---|---|
| Smoke test (detect) | 11/11 |
| Detect-only chain, rules within latency target | **10/10** (incl. correlation 100130, level 14) |
| Falco -> Wazuh delivery, 20 triggers 3 s apart | **20/20** (previous run: ~1 in 5) |
| Same, 30 triggers back to back | **30/30** |
| Same, manager restarted mid-run | **20/20** |
| `wazuh-sync` re-run with unchanged config | no restart, agents stay connected |
| Unsigned image rejected in Enforce | yes (`verify-image-signatures`) |
| Active Response, escape tooling (100114) in demo pod | container SIGKILLed **~1 s** after trigger, pod restarted by Kubernetes, node and agent unaffected |
| Active Response, IMDS probe (100113) from demo pod | container killed in the same second; the attacker's exec session died with 137 |
| IMDS rule false positives from `kube-system` | 1,429 before the fix, **0** after |

## Bugs found by this run (all fixed and committed)

10. **Fresh `terraform apply` failed** ("Invalid count argument"). The node user
    data embedded `aws_instance.wazuh.private_ip`, unknown at plan time, so the
    EKS module could not size its cloud-init parts. Fix #4 from the previous run
    only worked because the Wazuh instance already existed. The manager now has
    a fixed private IP computed from the VPC CIDR (`10.20.0.10`).
11. **`apply.sh` aborted on a fresh manager**: the new config fingerprint `cat`
    a file that does not exist yet, which `set -e` + `pipefail` turned into an
    exit. Fixed (missing files are fine).
12. **Root cause of the old "agents Disconnected" and "lost alerts" issues: the AR
    script deadlocked.** It read stdin with `$(cat)`; Wazuh 4.x execd writes
    one JSON line and keeps the pipe open. The script waited forever, execd
    stopped reading its queue, and wazuh-agentd blocked behind it (seen
    live: agentd in `sock_alloc_send_pskb`, `last_ack` frozen, no TCP session to
    1514). A blocked agent sends no keepalives and no events. Fix: read exactly
    one line, with a 10 s timeout. `ar_test.py` now calls the script with stdin
    left open; the old script hangs there.
13. **IMDS rule matched the VPC CNI and AR killed it.** `aws-node` (kube-system,
    hostNetwork) talks to IMDS constantly; rule 100113 raised ~1,400 CRITICAL
    alerts, and one stuck AR invocation, released by an agent restart, killed
    the `aws-node` container. Fixes: the Falco rule excludes `kube-system`, and
    the AR script refuses to act outside `CG_AR_NAMESPACES` (default `demo`) as
    a second guard.
14. **AR "stopped" the container but it kept running.** `ctr tasks kill` sends
    SIGTERM; the app is PID 1 in its PID namespace with no SIGTERM handler, so
    the kernel drops it. Now SIGKILL. The test stub rejects any other signal.
15. `wazuh-sync.sh` reported failure (`InProgress`) because `aws ssm wait` gives
    up after ~100 s while `apply.sh` may wait 2 min for agents. Now polls.

Also seen (not a bug): after the attack chain, the demo pod was evicted because
its `/tmp` emptyDir exceeded the 16Mi `sizeLimit` (the exfil step stages data
there). The limit is a deliberate hardening control; Kubernetes recreated the pod.

## Still to do

- The scripts were hot-patched onto the running nodes for this run; a fresh
  deploy installs the fixed version from user data (same file).
- Demo pod image is still unsigned (no CI run yet), so Enforce keeps the old pod
  rather than rolling a new one. Signing via the GitHub pipeline is the next step.
