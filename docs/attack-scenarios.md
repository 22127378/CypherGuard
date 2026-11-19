# CipherGuard v2.0 – Attack scenarios

All scenarios run only inside the lab VPC, on synthetic data, with egress limited to the attacker host.
Each scenario runs twice: **detect-only** (Kyverno audit, open network policy) and **prevent** (policies enforced).
Acceptance: Wazuh alert within 60 s in detect-only; blocked or alerted in prevent.

## Core chain (MVP, from proposal)

| Step | Action | MITRE | Telemetry | Prevention |
|---|---|---|---|---|
| 0. Before deploy | Deploy unsigned / root / vulnerable image | T1610 | Pipeline + admission logs | Trivy fails build; Kyverno rejects pod |
| 1. Foothold | `kubectl exec` shell in demo pod | T1609 | Falco: shell in container | RBAC limits `exec` |
| 2. Discovery | Read SA token and env; list resources | T1552.007, T1613 | Falco credential file read; EKS audit | No token mounted where not needed |
| 3. Escalation | Read secrets, create privileged pod, bind cluster-admin, try AWS calls | T1611, T1098, T1078.004 | EKS audit (403s); CloudTrail | Least-privilege RBAC and IAM; Kyverno blocks privileged |
| 4. Exfiltration | Encrypt test file (AES-256-GCM + RSA), send over HTTP to attacker host | T1041 | Falco: sensitive file read + outbound; Wazuh correlation | Default-deny egress |

## Additional scenarios

### MVP additions (build first)

| ID | Scenario | Simulated action | MITRE | Telemetry | Prevention |
|---|---|---|---|---|---|
| D | IMDS credential theft | Pod calls 169.254.169.254 to fetch node role credentials | T1552.005 | Falco: IMDS access; CloudTrail calls from node role | IMDSv2 with hop limit 1; NetworkPolicy blocks IMDS |
| B | Container escape | Try mounting `/var/run/docker.sock` or hostPath `/`, hostPID, `nsenter` | T1611 | Falco: sensitive mount, privileged; EKS audit | Kyverno blocks hostPath/hostPID/privileged; PSS restricted |
| G | Defense evasion | Delete logs in container, kill/modify Falco or Wazuh agent, exec binary from `/tmp` | T1070, T1562.001 | Falco: write to /tmp then exec, log file changes; Wazuh agent disconnect | Read-only root fs; agents run outside normal pod reach |

### Roadmap / Phase 7 if time allows

| ID | Scenario | Simulated action | MITRE | Telemetry | Prevention |
|---|---|---|---|---|---|
| A | Cryptominer | Run a harmless miner simulator (stress binary), connect to fake pool | T1496 | Falco: unexpected process, outbound to mining port; CPU spike | Default-deny egress; read-only root fs |
| C | Persistence | Create malicious CronJob/DaemonSet; edit Deployment to run unknown image | T1053.007, T1610 | EKS audit: create CronJob/DaemonSet | RBAC denies workload creation; Kyverno verifyImages |
| E | Secret theft | `kubectl get secrets -A`, read secrets in other namespaces | T1552.007 | EKS audit: list/get secrets, 403 | Namespace-scoped RBAC; no token mount |
| F | Lateral movement | Port scan internal services; connect to other pods or Wazuh | T1046, T1021 | Falco: network tools (nmap/nc); VPC Flow Logs | Default-deny NetworkPolicy |
| H | Supply chain | Push unsigned image; reuse mutable `latest` tag with changed content | T1195.002 | Admission log; Cosign verify failure | Kyverno verifyImages; digest pinning |
| I | Cloud-side abuse | Use pod IAM role for `s3:ListBucket` / `iam:*` beyond its permissions | T1078.004, T1530 | CloudTrail AccessDenied; GuardDuty | Narrow IAM role; EventBridge + Lambda disables key |

## Updated chain for phase 6

Steps 0–4 (core) plus D, B, G = 8 steps. Order: 0, 1, 2, D, 3, B, G, 4.

## Rule deliverables (phase 5)

- One Falco rule (or rule set) per scenario, tagged with MITRE technique IDs.
- One Wazuh rule per Falco/audit/CloudTrail event, plus a correlation rule for the full chain.
- Each rule tested with Falco event-generator or a scripted action in `tests/`.
