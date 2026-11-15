# InnovaBank. Run `make help` for the list of targets.

# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
# This Makefile is the project's command menu. Instead of remembering long
# Python and Terraform commands, you type a short name like `make test`.
#
# The commands fall into three groups:
#
#   1. Local, free, no AWS account needed:
#        install, test, lint, offline, ablation, gate, gate-demo, clean
#      These run everything on your machine with fake (mocked) AWS, so you can
#      try the whole lab safely.
#
#   2. Real AWS, costs money:
#        deploy-account, deploy-vulnerable, deploy-hardened, seed, ask,
#        attack-live, attack-live-one, check-live, report-live
#      These create the two banking agents (one weak, one protected) in your
#      AWS account and attack them with real Bedrock model calls.
#
#   3. Cleanup:
#        destroy (removes the AWS stacks so they stop costing money)
#
# Typical first run:  make install && make test && make offline
# Run `make help` at any time to see every target with a one-line summary.
#
# How the help works: any target line that ends with "## some text" is picked
# up automatically by `make help`. So when you add a target, add a "##" note
# on the same line and it shows up in the menu for free.
# =============================================================================

# -----------------------------------------------------------------------------
# Settings you can override on the command line, for example:
#   make ask MODE=vulnerable CUSTOMER=C-1002 MSG="What is my balance?"
# "?=" means "use this default only if the user did not set it", which is what
# makes those overrides work.
# -----------------------------------------------------------------------------
# Python interpreter used for every command.
PY      ?= python3
# AWS Region to deploy into. Bedrock models are not available everywhere, so
# keep this on a Region where the pinned models exist.
REGION  ?= us-east-1
# Terraform binary, overridable in case you use a wrapper or a specific version.
TF      ?= terraform
# Which posture `ask` and `attack-live-one` talk to. Defaults to the protected
# one so a casual test never targets the deliberately weak stack by accident.
MODE    ?= hardened
# Fictional customer the session is logged in as. Ownership checks are tied to
# this ID, so switching it lets you test "can I read someone else's account?".
CUSTOMER ?= C-1001
# How many times each live attack is repeated. Real models are not perfectly
# predictable, so several trials give a fairer success rate.
TRIALS  ?= 1
# The Python code lives in three folders that are not installed as packages.
# Exporting this lets every command below import them without extra setup.
export PYTHONPATH := app:harness:supplychain

# Running plain `make` shows the menu instead of doing something unexpected.
.DEFAULT_GOAL := help
# These names are commands, not files. Declaring them "phony" stops make from
# skipping a command just because a file or folder with the same name exists.
.PHONY: help install test lint offline ablation gate gate-demo deploy-account deploy-vulnerable deploy-hardened \
        seed ask attack-live attack-live-one check-live report-live destroy clean

# =============================================================================
# LOCAL COMMANDS (free, no AWS account needed)
# =============================================================================

# Builds the menu by scanning this file for "target: ## description" lines,
# so the help text can never drift out of date with the real targets.
help: ## Show this help
	@grep -E '^[a-z -]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

# One place for all dev tools (boto3, pytest, moto, ruff...) so a new machine
# is ready with a single command.
install: ## Install Python dependencies for tests, harness and gate
	$(PY) -m pip install -r requirements-dev.txt

# AWS is faked with moto, so tests are fast, free and safe to run anytime.
test: ## Unit tests (no AWS account needed)
	$(PY) -m pytest -q

# Runs the same style checks as CI, so you catch failures before pushing
# instead of waiting for the pipeline to tell you.
lint: ## Ruff on the Python code, terraform fmt check on infra/ (same as CI; checkov runs in CI)
	$(PY) -m ruff check .
	$(TF) fmt -check -recursive infra

# The heart of the lab without spending money: every attack is run against the
# weak posture and the protected posture, then the two are compared side by
# side. The report step also refreshes the results table in README.md, so the
# README always shows numbers that were really produced, never typed by hand.
offline: ## Run the attack catalog in process against both postures and write the report
	$(PY) -m innovabank_harness run --target offline --mode vulnerable --out results/offline-vulnerable.json
	$(PY) -m innovabank_harness run --target offline --mode hardened --out results/offline-hardened.json
	$(PY) -m innovabank_harness report --vulnerable results/offline-vulnerable.json \
		--hardened results/offline-hardened.json --out docs/results/offline.md --readme README.md

# Answers "is each defence actually pulling its weight?". It switches off one
# control at a time and shows which attacks start working again. A control
# that brings nothing back when removed may be redundant.
ablation: ## Remove one control at a time and list the attacks that come back
	$(PY) -m innovabank_harness ablation

# Protects against a poisoned model or file sneaking in: checks that model IDs
# match the pinned lock file, scans artifacts for dangerous pickles, and writes
# a bill of materials listing every ML component used.
gate: ## Supply chain gate: provenance, artifact scan, ML-BOM
	$(PY) -m ib_supplychain gate

# Proof that the scanner is not just always saying "OK": it builds a
# booby-trapped pickle (safe, because nothing ever loads it) and shows the
# scan rejecting it. The leading "-"
# on the scan line tells make to keep going even though the scan fails (that
# failure is the point), so the temporary folder is always cleaned up.
gate-demo: ## Show the scanner rejecting a malicious pickle (expected to fail)
	$(PY) supplychain/make_demo_fixture.py .demo-artifacts
	-$(PY) -m ib_supplychain scan .demo-artifacts
	rm -rf .demo-artifacts

# =============================================================================
# LIVE AWS COMMANDS (create real resources, cost money)
# =============================================================================

# Optional, done once per Region. Turns on Bedrock invocation logging so every
# prompt and model reply is recorded, which helps investigate attacks later.
# Kept separate because it is account wide, not tied to one stack.
deploy-account: ## Optional: enable Bedrock model invocation logging for the Region
	$(TF) -chdir=infra/account init -input=false
	$(TF) -chdir=infra/account apply -var region=$(REGION)

# One recipe serves both postures: "$*" is replaced by "vulnerable" or
# "hardened" depending on which target you typed. Steps:
#   1. init/apply: create the stack with Terraform.
#   2. output -json: save resource names (tables, Lambdas, keys) to a file, so
#      the harness can find this stack without you copying names by hand.
#   3. seed: load the fictional customers, accounts and documents, because a
#      freshly deployed bank is empty and the attacks need data to target.
deploy-vulnerable deploy-hardened: deploy-%: ## Deploy one posture, then seed it
	$(TF) -chdir=infra/envs/$* init -input=false
	$(TF) -chdir=infra/envs/$* apply -var region=$(REGION)
	$(TF) -chdir=infra/envs/$* output -json > infra/envs/$*/outputs.json
	$(PY) -m innovabank_harness seed --outputs infra/envs/$*/outputs.json

# Puts the demo data back to a known starting state. Useful after attacks have
# moved money or written messages, so the next run starts from a clean slate.
seed: ## Re-seed both deployed stacks
	$(PY) -m innovabank_harness seed --outputs infra/envs/vulnerable/outputs.json
	$(PY) -m innovabank_harness seed --outputs infra/envs/hardened/outputs.json

# Chat with a deployed agent by hand, one message at a time. Handy for trying
# your own attack ideas before writing them up as a YAML attack file.
ask: ## Talk to a deployed stack: make ask MSG="What is my balance?" [MODE=vulnerable] [CUSTOMER=C-1002]
	$(PY) -m innovabank_harness ask --outputs infra/envs/$(MODE)/outputs.json --customer $(CUSTOMER) "$(MSG)"

# Same comparison as `offline`, but against the real model in AWS. This is the
# real test: the offline model is scripted, the live one is not.
attack-live: ## Run the catalog against both deployed stacks (real Bedrock calls): make attack-live [TRIALS=3]
	$(PY) -m innovabank_harness run --target aws --outputs infra/envs/vulnerable/outputs.json --trials $(TRIALS) --out results/live-vulnerable.json
	$(PY) -m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials $(TRIALS) --out results/live-hardened.json

# Cheaper and faster than the full live run: hit only one stack, and with ONLY
# pick just the attacks you care about. The $(if ...) adds --only only when you
# set ONLY, and $(or ...) falls back to a default output file if OUT is empty.
attack-live-one: ## One deployed stack: make attack-live-one MODE=hardened [TRIALS=3] [ONLY=SD-02,PI-01] [OUT=results/x.json]
	$(PY) -m innovabank_harness run --target aws --outputs infra/envs/$(MODE)/outputs.json --trials $(TRIALS) \
		$(if $(ONLY),--only $(ONLY)) --out $(or $(OUT),results/live-$(MODE).json)

# Fails if the protected stack let through any attack beyond the known,
# documented residual ones, or if normal customer requests broke or raised
# alarms. Same rule CI applies to the offline run.
check-live: ## Regression guard on the last live hardened run
	$(PY) tests/check_regression.py results/live-hardened.json

# Turns the raw live JSON results into a readable report and refreshes the live
# results table in README.md, so published numbers come from a real run.
report-live: ## Render the live report and update the README results block
	$(PY) -m innovabank_harness report --vulnerable results/live-vulnerable.json \
		--hardened results/live-hardened.json --out docs/results/live.md --readme README.md

# =============================================================================
# CLEANUP
# =============================================================================

# Removes both stacks so you stop paying. The leading "-" means a failure on
# the first stack (for example, it was never deployed) does not stop the
# second one from being destroyed.
destroy: ## Tear down both stacks
	-$(TF) -chdir=infra/envs/vulnerable destroy -var region=$(REGION)
	-$(TF) -chdir=infra/envs/hardened destroy -var region=$(REGION)

# Local only, touches nothing in AWS. Deletes caches and the built Lambda zip,
# which forces a fresh build next deploy if you suspect a stale package.
clean: ## Remove local build and cache files
	rm -rf .pytest_cache .demo-artifacts infra/modules/stack/.build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
