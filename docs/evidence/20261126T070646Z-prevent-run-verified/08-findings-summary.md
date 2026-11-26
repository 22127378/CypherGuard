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
