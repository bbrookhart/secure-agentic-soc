.PHONY: help install run ui demo demo-offline test lint typecheck audit policy docker-up docker-down clean

PYTHON ?= .venv/bin/python
PIP    ?= .venv/bin/pip

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Create the virtualenv and install dev dependencies
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt

run:  ## Run an alert (make run ALERT=alert-001-ransomware)
	$(PYTHON) -m src.run_cli --alert $(or $(ALERT),alert-001-ransomware)

ui:  ## Launch the Streamlit analyst dashboard (local, unauthenticated)
	@echo "NOTE: running without an authenticating proxy. Approvals will be recorded"
	@echo "      as 'unauthenticated' in the audit trail. Do not expose this port."
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false .venv/bin/streamlit run src/ui/app.py

demo:  ## Full walkthrough: benign alert, then the HITL path, then injection
	@echo "NOTE: CLI approvals are self-asserted, so this runs with"
	@echo "      SOC_REQUIRE_AUTHENTICATED_APPROVAL=false. Decisions are recorded"
	@echo "      as unauthenticated, and separation of duties is off because a"
	@echo "      single operator is both initiator and approver. The console is"
	@echo "      the real approval surface."
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-003-false-positive --quiet-audit
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-001-ransomware --approve
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-005-prompt-injection --reject --quiet-audit

demo-offline:  ## Same walkthrough with no LLM (deterministic, fast)
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-003-false-positive --offline --quiet-audit
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-001-ransomware --offline --approve
	SOC_REQUIRE_AUTHENTICATED_APPROVAL=false SOC_REQUIRE_SEPARATION_OF_DUTIES=false $(PYTHON) -m src.run_cli --alert alert-005-prompt-injection --offline --reject --quiet-audit

test:  ## Run the test suite
	$(PYTHON) -m pytest

eval:  ## Score the pipeline against the labelled corpus (deterministic)
	$(PYTHON) -m evals.runner

eval-llm:  ## Same corpus, with the configured model
	$(PYTHON) -m evals.runner --llm

generate:  ## Regenerate the multi-host investigation scenarios
	$(PYTHON) -m evals.generate

baseline:  ## Re-record the offline baseline (per-case, so paired comparison works)
	$(PYTHON) -m evals.runner --json evals/baselines/offline.json

baseline-llm:  ## Record an LLM baseline: make baseline-llm NAME=qwen3-8b
	@test -n "$(NAME)" || { echo "usage: make baseline-llm NAME=<model-slug>"; exit 2; }
	$(PYTHON) -m evals.runner --llm --json evals/baselines/llm-$(NAME).json

eval-paired:  ## Is B actually better than A?  make eval-paired A=<report> B=<report>
	@test -n "$(A)" -a -n "$(B)" || { echo "usage: make eval-paired A=<report.json> B=<report.json>"; exit 2; }
	$(PYTHON) -m evals.paired $(A) $(B)

compare:  ## Supervisor vs. the single ReAct agent on the same corpus (needs Ollama)
	$(PYTHON) -m evals.compare

lint:  ## Lint with ruff
	.venv/bin/ruff check src tests

typecheck:  ## Type-check with mypy
	.venv/bin/mypy src

lock:  ## Regenerate the hash-pinned lockfile from requirements.txt
	$(PYTHON) -m piptools compile --generate-hashes --output-file=requirements.lock requirements.txt

audit-deps:  ## Check locked dependencies for known vulnerabilities
	@$(PYTHON) scripts/audit_deps.py

sbom:  ## Generate a CycloneDX SBOM for the current environment
	$(PYTHON) -m cyclonedx_py environment --output-format JSON --outfile sbom.json
	@echo "wrote sbom.json"

mode:  ## Show the operating mode (make mode SET=review_all REASON="...")
	$(PYTHON) -m src.run_cli --mode $(SET) $(if $(REASON),--reason "$(REASON)",)

backup:  ## Archive the state volume (audit, checkpoints, cases)
	scripts/backup.sh create

health:  ## Readiness checks (can this system triage an alert safely?)
	$(PYTHON) -m src.run_cli --health

evidence:  ## Generate the control-evidence bundle (reads live components)
	$(PYTHON) -m src.evidence --out evidence.md --json evidence.json
	@echo "wrote evidence.md and evidence.json"

policy:  ## Print the approval policy and agent capability matrix
	$(PYTHON) -m src.run_cli --policy

audit:  ## Verify a run's audit hash chain (make audit THREAD=run-xxxx)
	$(PYTHON) -m src.run_cli --verify-audit $(THREAD)

docker-up:  ## Build and start the full stack
	docker compose up --build

docker-down:  ## Stop the stack and remove volumes
	docker compose down -v

clean:  ## Remove runtime state (checkpoints, audit log, vector index)
	rm -rf state/ .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
