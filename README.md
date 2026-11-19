# CipherGuard v2.0

Secure container pipeline with Kubernetes runtime detection (EKS + Kyverno + Falco + Wazuh).
Region: `ap-southeast-1` (Singapore). Pod access to AWS: IRSA.

See [docs/attack-scenarios.md](docs/attack-scenarios.md) for the attack chain.

## Layout

```
infra/bootstrap/   persistent: S3 state, DynamoDB lock, budget, ECR, GitHub OIDC roles
infra/terraform/   the lab: VPC, EKS, Wazuh, attacker host, IRSA role (destroyed every session)
app/               demo application (attack target)
.github/workflows/ terraform (plan on PR, approved apply/destroy) and build (push to ECR)
attack/            attack simulation (receiver runs on the attacker host)
docs/              scenarios and notes
```

## One-time setup

```bash
cd infra/bootstrap
echo 'budget_alert_email = "you@example.com"' > terraform.tfvars
cd ../.. && make bootstrap        # also writes infra/terraform/backend.hcl
```

Then configure GitHub (variables, `lab` environment, branch protection): [docs/github-setup.md](docs/github-setup.md).
The lab can be created locally (`make up`) or from Actions > terraform > Run workflow.

## Each session

```bash
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars   # first time only
# set admin_cidr to your current IP: curl -s https://checkip.amazonaws.com

make up           # create lab (~15-20 min, mostly EKS) and update kubeconfig
kubectl get nodes

# Wazuh dashboard (install takes ~10 min after the instance boots)
terraform -chdir=infra/terraform output -raw wazuh_admin_password_command | bash
terraform -chdir=infra/terraform output -raw wazuh_dashboard_tunnel | bash
# open https://localhost:8443, user: admin

make down         # destroy everything, then list leftovers
```

Access to the Wazuh and attacker hosts is through SSM Session Manager only (no SSH, no public ports).
This needs the [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html).

## Cost notes

Billed per hour while the lab is up: EKS control plane, 2 x t3.large nodes, t3.large Wazuh, NAT Gateway.
Always run `make down` at the end. The state bucket, lock table and budget are kept.
