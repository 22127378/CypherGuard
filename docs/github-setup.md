# GitHub setup (phase 2)

Manual steps in the GitHub UI for `22127378/CypherGuard`. Run `make bootstrap` first.

## 1. Repository variables

Settings > Secrets and variables > Actions > **Variables** (not secrets; none of these are credentials):

```bash
terraform -chdir=infra/bootstrap output github_repository_variables
```

| Variable | Value |
|---|---|
| `AWS_PLAN_ROLE_ARN` | from output |
| `AWS_APPLY_ROLE_ARN` | from output |
| `AWS_ECR_PUSH_ROLE_ARN` | from output |
| `TF_STATE_BUCKET` | from output |
| `TF_LOCK_TABLE` | from output |
| `ECR_REPOSITORY` | from output |
| `ADMIN_CIDR` | your IP, e.g. `203.0.113.10/32` |
| `CLUSTER_ADMIN_ARNS` | JSON list, e.g. `["arn:aws:iam::123456789012:user/you"]` |

There should be **no** repository secrets for AWS. That is the phase 2 acceptance check.

## 2. Environment `lab` (manual approval)

Settings > Environments > New environment > `lab`:
- Required reviewers: yourself
- Deployment branches: **Selected branches** > `main`

The apply role trusts only `repo:22127378/CypherGuard:environment:lab`, so apply cannot run without this approval.

## 3. Protect `main`

Settings > Branches (or Rules > Rulesets) for `main`:
- Require a pull request before merging (1 approval, require review from Code Owners)
- Require status checks: `check`, `plan`, `build`, `secrets`, `dockerfile`, `sast`, `iac`, `policies`, `negative`
- Block force pushes and deletions
- Do not allow bypassing the above settings

## 4. Security features

Settings > Code security: enable Dependabot alerts, secret scanning and push protection.

## Verify

```bash
# No static AWS keys in the repo history
git log -p | grep -E 'AKIA[0-9A-Z]{16}' && echo FOUND || echo clean
```
Then Actions > terraform > Run workflow (`apply`), check the plan summary, approve, and confirm the lab comes up.
