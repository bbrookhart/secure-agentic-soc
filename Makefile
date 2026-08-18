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
	$(PYTHON) -m src.run_cli --alert alert-003-false-positive --quiet-audit
	$(PYTHON) -m src.run_cli --alert alert-001-ransomware --approve
	$(PYTHON) -m src.run_cli --alert alert-005-prompt-injection --reject --quiet-audit

demo-offline:  ## Same walkthrough with no LLM (deterministic, fast)
	$(PYTHON) -m src.run_cli --alert alert-003-false-positive --offline --quiet-audit
	$(PYTHON) -m src.run_cli --alert alert-001-ransomware --offline --approve
	$(PYTHON) -m src.run_cli --alert alert-005-prompt-injection --offline --reject --quiet-audit

test:  ## Run the test suite
	$(PYTHON) -m pytest

eval:  ## Score the pipeline against the labelled corpus (deterministic)
	$(PYTHON) -m evals.runner

eval-llm:  ## Same corpus, with the configured model
	$(PYTHON) -m evals.runner --llm

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
