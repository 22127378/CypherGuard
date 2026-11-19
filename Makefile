TF_DIR    := infra/terraform
BOOT_DIR  := infra/bootstrap
TF        := terraform -chdir=$(TF_DIR)

.PHONY: help bootstrap init plan up down kubeconfig leftovers fmt validate scan scan-image negative policies deploy deploy-detect smoke detection wazuh-sync attack attack-detect measure baseline

help:
	@echo "bootstrap   one-time: create S3 state bucket + DynamoDB lock"
	@echo "up          create the whole lab"
	@echo "down        destroy the whole lab"
	@echo "leftovers   list resources still tagged Project=CipherGuard"
	@echo "scan        gitleaks, hadolint, Semgrep, Checkov (same as CI)"
	@echo "scan-image  build demo image and run the Trivy gate"
	@echo "negative    prove every scanner blocks a known-bad change"
	@echo "policies    Kyverno CLI tests against the rendered charts"
	@echo "detection   validate Falco rules, replay Wazuh rules against sample events"
	@echo "wazuh-sync  push detection/wazuh to the Wazuh manager over SSM"
	@echo "deploy      Kyverno + policies (Enforce) + Falco + demo app + Wazuh rules, then smoke test"
	@echo "deploy-detect  same, but policies Audit and egress open (detect-only run)"
	@echo "attack-detect  run the simulated attack chain (detect-only)"
	@echo "attack         run the simulated attack chain (prevent run)"
	@echo "measure        run detect-only chain and report Wazuh alert latency"
	@echo "baseline       generate normal traffic, then check for critical false positives"

bootstrap:
	terraform -chdir=$(BOOT_DIR) init
	terraform -chdir=$(BOOT_DIR) apply

init:
	$(TF) init -backend-config=backend.hcl

plan: init
	$(TF) plan -out=tfplan

up: init
	$(TF) apply
	$(MAKE) kubeconfig

down: init
	$(TF) destroy
	$(MAKE) leftovers

kubeconfig:
	$$($(TF) output -raw kubeconfig_command)

leftovers:
	@echo "Resources still tagged Project=CipherGuard (state bucket/lock table are expected):"
	@aws resourcegroupstaggingapi get-resources --region ap-southeast-1 \
		--tag-filters Key=Project,Values=CipherGuard \
		--query 'ResourceTagMappingList[].ResourceARN' --output text | tr '\t' '\n'

fmt:
	terraform fmt -recursive infra

validate:
	terraform -chdir=$(BOOT_DIR) init -backend=false >/dev/null && terraform -chdir=$(BOOT_DIR) validate
	$(TF) init -backend=false >/dev/null && $(TF) validate

scan:
	scripts/scan.sh all

scan-image:
	docker build -t demo-app:local app
	scripts/scan.sh image demo-app:local

negative:
	scripts/scan.sh negative

policies:
	scripts/scan.sh policies

deploy:
	scripts/deploy.sh --mode enforce

deploy-detect:
	scripts/deploy.sh --mode detect

smoke:
	scripts/smoke.sh --mode enforce

detection:
	scripts/scan.sh detection

wazuh-sync:
	scripts/wazuh-sync.sh --wait

attack-detect:
	attack/run-attack.sh --mode detect

attack:
	attack/run-attack.sh --mode enforce

measure:
	scripts/measure-latency.sh

baseline:
	scripts/baseline.sh
