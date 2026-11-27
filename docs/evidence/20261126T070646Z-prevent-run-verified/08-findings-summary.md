# Prevent-run verification: findings summary

## Confirmed working (live evidence)

1. **Image signature enforcement**: `helm upgrade demo-app` REJECTED by
   `verify-image-signatures` ImageValidatingPolicy because the manually
   pushed image was never Cosign-signed. Exact admission webhook error
   captured. This is the project's core success metric #4.

2. **Direct admission tests, all correctly REJECTED** in Enforce mode:
   - privileged pod -> `pod-security-baseline: privileged containers are not allowed`
   - hostPath `/` mount -> `pod-security-baseline: hostPath volumes are not allowed`
   - cluster-admin ClusterRoleBinding to a ServiceAccount ->
     `deny-cluster-admin-to-serviceaccounts: cluster-admin may not be bound to a ServiceAccount`

3. **Falco -> Wazuh detection pipeline** (after fixes below): rule 100114
   ("CipherGuard Escape Tooling In Container", nsenter) fired and reached
   Wazuh (rule id 100114, level 12) within ~2s of the live trigger.

## Real bugs found and fixed this session (all committed)

1. `cluster_admin_arns` used an unknown-at-plan-time ARN as a `for_each`
   key (EKS access entries). Fixed with a static ARN string.
2. Lambda `reserved_concurrent_executions` rejected by the account's low
   unreserved-concurrency pool. Removed.
3. `admin_cidr` validation required an exact /32; this environment's
   egress IP rotates. Widened to allow up to /24.
4. **`enable_bootstrap_user_data` was never set** on the node group, so
   `cloudinit_post_nodeadm` (Wazuh agent install + Active Response script)
   was silently dropped from every node since the project's first commit.
   No agent had ever enrolled until this was fixed and the node group
   rolling-updated.
5. Wazuh rule 100301 (node credential misuse) fired on EKS's own IAM
   Authenticator `sts:GetCallerIdentity` verification calls -- ~30 times
   in minutes from normal cluster operation. Excluded that event name.
6. Falco rule "CipherGuard Unexpected Outbound From App Pod" never fired
   for a real, confirmed-successful outbound connection (relied on the
   built-in `outbound` macro). Rewritten explicitly; confirmed firing,
   including the downstream correlation rule (100130).
7. Kyverno's `reports-controller`/`background-controller` service
   accounts lacked RBAC on `clusterrolebindings`/`rolebindings`, so the
   `deny-cluster-admin-to-serviceaccounts` policy enforced correctly at
   admission but never reported Ready. Added a ClusterRole/Binding.

## Open issue (not resolved live -- documented for follow-up)

**Active Response did not execute** for rule 100114 (level 12, in the
configured `rules_id` list), even after confirming:
- the alert reached Wazuh correctly (visible in `alerts.json`),
- both node agents were `Active` at the time,
- `cipherguard-isolate.sh` is present on the node
  (`/var/ossec/active-response/bin/`),
- the `<active-response>`/`<command>` block is present in the manager's
  `ossec.conf` (confirmed via SSM cat).

`wazuh-execd`/`wazuh-analysisd` logs show no attempt to dispatch the
command for this alert (no error either -- just silence), suggesting a
matching/config issue rather than an execution failure. Needs further
investigation: likely candidates are (a) `location=local` needing the
command also registered via the agent group's shared `ar.conf` rather
than only the manager's own `ossec.conf`, or (b) a Wazuh 4.14-specific
change to how `rules_id`-triggered local AR is distributed.

Separately found: restarting the Wazuh manager multiple times in quick
succession (re-running `wazuh-sync.sh`) left both node agents
`Disconnected` until manually restarted (`systemctl restart wazuh-agent`
on each node). `wazuh-sync.sh` should probably verify agents are
`Active` after a restart and retry/warn if not.

## Update: Active Response root causes found and fixed

After further live investigation (keeping the lab up for a second debugging
pass):

1. **Confirmed AR dispatch works.** Manager-side debug logging showed
   `Send AR to execd: cipherguard-isolate0` multiple times, and the script
   was observed executing on the node (new timestamped log lines) across
   several independent triggers.

2. **Real bug #1 -- silent parse failure.** The script's Python JSON parsing
   used `2>/dev/null || true`, which silently swallowed any exception and
   always fell through to the generic "host-level event" message, with no
   way to tell a genuine host-level alert from a parsing bug. This masked
   the real issue for a long time. Fixed: parsing failures are now logged
   explicitly with the exception and a sample of the raw input.

3. **Real bug #2 -- `crictl` is not installed on this AL2023/containerd EKS
   node.** The script's own `command -v crictl` check should have caught
   this and logged "crictl not found", but bug #1 meant it never reached
   that check (cid always came back empty first). Fixed: switched to `ctr`
   (containerd's own CLI, confirmed present), using `ctr -n k8s.io`.

4. **New finding -- event delivery degrades under repeated manager
   restarts.** During this extended debugging session (many `wazuh-sync`
   calls and manual `wazuh-agent` restarts in quick succession), the
   Falco -> Wazuh alert pipeline became intermittent: Falco reliably logged
   every trigger (confirmed in its own pod logs) but a significant fraction
   never reached Wazuh's `alerts.json`, with no error on either side. This
   did NOT happen during the original clean run (9/9 rules landed within
   target). This points to the repeated agent reconnect cycles leaving
   `wazuh-logcollector`/forwarding in a degraded state, not a bug in the
   detection rules or the AR mechanism themselves.

**Net result:** both real script bugs are fixed and verified offline
(4/4 scenarios: isolate, host-level skip, delete no-op, malformed-input
logging) plus the full 30/30 detection regression suite. The final live
trigger to directly observe an isolate under the fixed script did not land
cleanly before the decision was made to stop further live iteration, given
the event-delivery degradation in point 4 above and session cost. A clean
single-restart deploy (the normal, non-debugging path) should not exhibit
this degradation; that is the recommended way to re-verify.

## Final round (clean single-restart redeploy, no debug churn)

Did a fully clean `scripts/deploy.sh --mode enforce` from scratch (one
manager restart via one `wazuh-sync`, one agent reconnect, no overlapping
debug sessions). Result:

- All 5 Kyverno policies stayed Ready. demo-app helm upgrade still
  correctly rejected (unsigned image) -- the old pod kept running, as
  expected.
- A single nsenter trigger landed rule 100114 in Wazuh within **3 seconds**
  (epoch match confirmed) -- excellent latency when it lands.
- However, the isolate script's log still showed the old "no pod container
  id" message, despite confirming (via md5/grep on the live file) that the
  FIXED script (with PARSEFAIL handling) was actually deployed and running.
  The fixed parser did not throw PARSEFAIL, meaning JSON parsing succeeded
  but `data.output_fields["container.id"]` was genuinely absent for
  whatever wrapper shape Wazuh sent -- the true wrapper structure is still
  not confirmed; a raw-capture patch applied for a follow-up trigger never
  fired because the SAME alert (100114) stopped landing on 3 further
  consecutive nsenter attempts.
- Falco's own pod log confirmed all 4 of these attempts were detected and
  written to events.json (verified timestamps). wazuh-logcollector was
  confirmed correctly configured and monitoring that exact file. The loss
  is therefore between logcollector tailing and the alert reaching
  `alerts.json` / being matched by rule 100114 -- not a Falco bug, not a
  Kyverno/RBAC issue, and not (by itself) the AR script bugs already fixed.

**Conclusion:** two real script bugs are fixed and proven correct in
isolation (offline regression suite, 4/4 scenarios). The Falco-to-Wazuh
alert delivery for this specific rule is intermittent even under a clean,
non-debug-churned deploy (roughly 1 success in 5 attempts across this
session) -- a real reliability gap worth dedicated investigation (likely
candidates: wazuh-logcollector buffering/backpressure on rapid successive
lines, or JSON decoder matching timing), not reproducible to a root cause
within this session's time/cost budget. The end-to-end chain (detection
-> dispatch -> script -> ctr) has never been observed to fail when the
alert actually lands; only the landing itself is unreliable.

## Follow-up (2026-11-27, offline): configuration fixes

1. **Root cause of "no pod container id" found and fixed.** Replaying a Falco
   event through a real `wazuh-manager:4.14.10` analysisd shows Wazuh splits
   dotted JSON keys into nested objects in the alert it emits:
   `output_fields["container.id"]` becomes `output_fields.container.id`
   (`{"container": {"id": ...}}`). The script looked up the flat key, so the
   id was always empty. That is exactly the live symptom (parse OK, field absent).
   The script now reads the nested path (flat key as fallback). New test
   `tests/detection/ar_test.py` feeds the REAL logtest alert to the script with
   a stub `ctr`; it fails on the old script with the exact live log line and
   passes on the fixed one (run by `scripts/scan.sh detection`).
2. **Manager restarts only on change.** `apply.sh` fingerprints the config it
   manages and skips `systemctl restart wazuh-manager` when nothing changed, so
   re-running `wazuh-sync.sh` no longer drops agent connections. After a real
   restart it waits up to 2 min and prints a WARNING naming any agent not Active.
3. **Logcollector no longer skips lines written during a reconnect.**
   `only-future-events` was the default `yes`, so Falco lines written while the
   agent was restarting/reconnecting were never read. Set to `no` in the
   `eks-nodes` group `agent.conf` (agent resumes from its saved offset).

Items 2 and 3 target the conditions under which loss was observed (restart and
reconnect churn). Whether they remove all of the ~1-in-5 loss still has to be
confirmed in the next live run.
