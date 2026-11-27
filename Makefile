TF_DIR    := infra/terraform
BOOT_DIR  := infra/bootstrap
TF        := terraform -chdir=$(TF_DIR)

.DEFAULT_GOAL := help
.PHONY: help bootstrap init plan up down kubeconfig leftovers fmt validate scan scan-image negative policies deploy deploy-detect smoke detection wazuh-sync attack attack-detect measure baseline

help: ## list targets
	@awk -F':.*## ' '/^[a-z-]+:.*## / {printf "%-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------- lab lifecycle ----------

bootstrap: ## one-time: S3 state bucket, DynamoDB lock, budget, ECR, GitHub OIDC
	terraform -chdir=$(BOOT_DIR) init
	terraform -chdir=$(BOOT_DIR) apply

init:
	$(TF) init -backend-config=backend.hcl

plan: init ## terraform plan for the lab
	$(TF) plan -out=tfplan

up: init ## create the whole lab and update kubeconfig
	$(TF) apply
	$(MAKE) kubeconfig

down: init ## destroy the whole lab, then list leftovers
	$(TF) destroy
	$(MAKE) leftovers

kubeconfig:
	$$($(TF) output -raw kubeconfig_command)

leftovers: ## list resources still tagged Project=CipherGuard
	@echo "Resources still tagged Project=CipherGuard (state bucket/lock table are expected):"
	@aws resourcegroupstaggingapi get-resources --region ap-southeast-1 \
		--tag-filters Key=Project,Values=CipherGuard \
		--query 'ResourceTagMappingList[].ResourceARN' --output text | tr '\t' '\n'

fmt: ## terraform fmt
	terraform fmt -recursive infra

validate: ## terraform validate (no backend)
	terraform -chdir=$(BOOT_DIR) init -backend=false >/dev/null && terraform -chdir=$(BOOT_DIR) validate
	$(TF) init -backend=false >/dev/null && $(TF) validate

# ---------- shift-left gates (same as CI) ----------

scan: ## gitleaks, shellcheck, hadolint, Semgrep, Checkov, policies, detection
	scripts/scan.sh all

scan-image: ## build demo image and run the Trivy gate
	docker build -t demo-app:local app
	scripts/scan.sh image demo-app:local

negative: ## prove every scanner blocks a known-bad change
	scripts/scan.sh negative

policies: ## Kyverno CLI tests against the rendered charts
	scripts/scan.sh policies

detection: ## validate Falco rules, replay Wazuh rules and Active Response
	scripts/scan.sh detection

# ---------- live lab ----------

deploy: ## Kyverno (Enforce) + Falco + demo app + Wazuh rules + AR, then smoke test
	scripts/deploy.sh --mode enforce

deploy-detect: ## same, but policies Audit and egress open (detect-only run)
	scripts/deploy.sh --mode detect

smoke: ## post-deploy smoke test (prevent run)
	scripts/smoke.sh --mode enforce

wazuh-sync: ## push detection/wazuh to the Wazuh manager over SSM
	scripts/wazuh-sync.sh --wait

attack-detect: ## run the simulated attack chain (detect-only)
	attack/run-attack.sh --mode detect

attack: ## run the simulated attack chain (prevent run)
	attack/run-attack.sh --mode enforce

measure: ## run detect-only chain and report Wazuh alert latency
	scripts/measure-latency.sh

baseline: ## generate normal traffic, then check for critical false positives
	scripts/baseline.sh
