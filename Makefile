TF_DIR    := infra/terraform
BOOT_DIR  := infra/bootstrap
TF        := terraform -chdir=$(TF_DIR)

.PHONY: help bootstrap init plan up down kubeconfig leftovers fmt validate

help:
	@echo "bootstrap   one-time: create S3 state bucket + DynamoDB lock"
	@echo "up          create the whole lab"
	@echo "down        destroy the whole lab"
	@echo "leftovers   list resources still tagged Project=CipherGuard"

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
