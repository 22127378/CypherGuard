# Prevent run, full: findings summary (2026-11-27, 07:00-07:19 UTC)

Policies Enforce, NetworkPolicy default-deny, Active Response on. Same lab as
`20261127T052536Z-prevent-rerun/`. Files 10-14 in this folder are the raw output
of each check below.

## Admission (smoke test, enforce): 11/11

Unsigned image from another registry, privileged pod, hostPath `/`, and
cluster-admin bound to a ServiceAccount: all **rejected**. App checks (no API
token, IRSA, digest, /healthz, IRSA -> SSM) pass.

## Attack chain (`run-attack.sh --mode enforce`) and follow-ups

| Step | Prevention observed | Detection (Wazuh rule) |
|---|---|---|
| 1 foothold | (admin exec allowed by design; developer RBAC not tested) | 100202 audit exec |
| 2 discovery | no SA token mounted; API server returned **401** | 100111, 100112 |
| D IMDS | **AR killed the container** (exec ended with 137) | 100113 (level 12) |
| 3 escalation | IAM **AccessDenied** on `s3:ListBuckets` and `iam:ListUsers` | 100300 CloudTrail, 12.5 min (target 15) |
| B escape | `nsenter`: **Operation not permitted** (PSS restricted); AR killed the container | 100114 |
| G exec from /tmp, wipe history | not blocked (alert only, by design) | 100115, 100116 |
| G kill security agent | **AR killed the container** 2 s after `/tmp/kill -TERM falco` | 100117 (level 13), after fix below |
| 4 exfiltration | egress to the attacker host **timed out** (NetworkPolicy); reading `/data` then sending got the container **killed by AR** | 100119, 100120, 100130 (level 14) |

All four Active Response rules (100113, 100114, 100117, 100130) were seen to kill
the app container; Kubernetes restarted it each time and the node and its agent
stayed up.

## Cloud side

- **GuardDuty -> EventBridge -> Lambda (direct):** a finding naming the
  `cipherguard-demo-app` role attached the Deny-all quarantine policy; the pod's
  next SSM call failed with *"explicit deny in an identity-based policy"*.
- **GuardDuty -> EventBridge -> Lambda (automatic):** a high-severity sample
  finding invoked the Lambda within ~14 s; it skipped the fake user safely.
- **GuardDuty -> CloudWatch Logs -> Wazuh:** 100312 (level 12) after the fix below.

## Bugs found by this run (fixed and committed)

16. **Falco reported only the first matching rule** (`rule_matching: first`,
    the default). `/tmp/kill -TERM falco` raised only "Exec From Writable Temp"
    (alert-only), never "Kill Security Agent" (Active Response). Set
    `rule_matching: all`.
17. **Auto-fix Lambda could disable any IAM user's key.** The key path had no
    scope guard (the role path did), any `cipherguard-*` IAM user was also
    "quarantined" as a role, and a missing user crashed the invocation (seen
    live on a GuardDuty sample). Now: users and roles must be `cipherguard-*`;
    the operator principals are protected; errors are reported. New offline test
    `tests/lambda/test_autofix.py` (8 cases; the old code fails 6).
18. **Wazuh could not read the GuardDuty log group**: its role only allowed the
    EKS log group, so every poll failed with `DescribeLogStreams` AccessDenied
    and no GuardDuty finding ever reached Wazuh. Added read on
    `/cipherguard/guardduty`.
19. `run-attack.sh`, `smoke.sh`, `baseline.sh`, `delivery-test.sh` picked the
    first demo pod even when it was a Failed (evicted) one, so the first enforce
    chain ran against nothing. They now select Running pods only.

## Observations (not changed)

- 100204/100205 fired on `helm upgrade falco` (Helm lists secrets; the Falco
  DaemonSet creates privileged pods). Correct, but 100205 will fire on every
  Falco rollout; candidate for an allowlist after the 24 h baseline.
- Repeated AR kills put the app container into kubelet back-off (restart
  delayed ~40 s), which is the desired effect for a pod under attack.
