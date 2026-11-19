# Detecting an encrypted data heist you can't read: CipherGuard v2.0

> Draft blog post for the project. Audience: engineers and hiring managers
> reading a DevSecOps portfolio. Fill the `[measure]` placeholders with real
> numbers from `make measure` and add screenshots where marked.

## The problem

Content inspection fails the moment an attacker encrypts what they steal. If a
compromised pod reads your data, wraps it in AES-256-GCM, and ships it out over
HTTPS, a tool that looks *inside* the traffic sees noise. CipherGuard v2.0 is a
small lab that proves you can still catch the heist — by watching *behaviour*
instead of content — while every stage of the delivery pipeline is locked down.

It runs end to end on AWS (EKS in Singapore), is built entirely from code, and
is created and destroyed per session to keep the bill near zero.

## The shape of it

Security lives at all four stages of a container's life:

- **Code** — infrastructure, Helm charts, Kyverno policies and detection rules
  all live in Git and are scanned on every pull request.
- **Build** — GitHub Actions authenticates to AWS with OIDC (no static keys),
  Trivy gates on vulnerabilities, Syft produces an SBOM, and Cosign signs the
  image keyless.
- **Deploy** — EKS runs only images signed by the main-branch workflow; Kyverno
  enforces Pod Security, a default-deny NetworkPolicy and least-privilege RBAC.
- **Operate** — Falco watches syscalls, the EKS audit log and CloudTrail feed
  Wazuh, and rules map each step to MITRE ATT&CK.

## The attack

From an assumed-breach shell in a pod, the chain walks through: foothold
(`kubectl exec`), discovery (reading tokens, hitting the API), IMDS credential
theft, privilege escalation, container-escape attempts, defense evasion, and
finally exfiltration — read `/data`, encrypt it, POST it to the attacker host.

Two runs, one switch:

- **Detect-only** — policies in Audit, open egress. The attack reaches the end,
  and Wazuh must alert on every step.
- **Prevent** — policies enforced. The attack stops at escalation or
  exfiltration, alerts still fire, and Active Response isolates the pod's
  container (not the node, so the node keeps reporting).

## Why the exfil is still caught

The exfil script encrypts the body with AES-256-GCM and wraps the key with
RSA-OAEP. Wazuh never sees the plaintext. It does not need to: a Falco rule
fires when a non-application process reads `/data`, another fires on an outbound
connection to a port the app never uses, and a correlation rule ties the two
together when they happen in the same container within two minutes. The content
is opaque; the behaviour is not.

```
CipherGuard Sensitive Data Read   (T1005)  ─┐
                                            ├─►  Likely exfiltration (T1041, level 14)
CipherGuard Unexpected Outbound   (T1041)  ─┘   same container, < 2 min
```

## What I'd call out to a reviewer

A few things only showed up because every rule and gate has a test:

- **Kyverno 1.20 dropped the legacy `ClusterPolicy` executor.** The policies had
  to be rewritten in CEL. A `kyverno test` suite caught this before any deploy.
- **A registry allowlist pattern (`repo*`) let `repo-evil` through.** The test
  that a Docker Hub image is rejected turned into the test that caught it.
- **A negative-test job proves each scanner blocks a known-bad change** — a
  planted AWS key, a root Dockerfile, a public S3 bucket, a vulnerable base
  image. That job found a config bug that silently skipped Checkov on charts.
- **Detection rules are replayed through a real `wazuh-analysisd`** — 26 sample
  events, each asserting a rule id and MITRE technique, including benign events
  that must *not* alert.

## Results

[measure] Falco-sourced steps alerted in ~N seconds; audit-sourced steps in
~N seconds; all within target. Baseline: [measure] no critical false positives
over 24 hours.

![Wazuh showing the correlated exfiltration alert](screenshot-placeholder.png)

## Takeaway

Encryption defeats inspection, not detection. Put the controls in code, test the
rules like code, and watch what the workload *does* — then an encrypted heist is
still a heist you can see.

*Code: github.com/22127378/CipherGuard · built with Terraform, EKS, Kyverno,
Falco and Wazuh.*
