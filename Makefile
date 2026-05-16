PYTHON      := .venv/bin/python
SARIF       ?= ../medsecure/findings/codeql.sarif.json
TEST_SARIF  := fixtures/demo.sarif.json

.PHONY: run dry-run test check clean

run:
	@echo "WARNING: this will create live Devin sessions and may open PRs."
	@echo "Press Ctrl-C within 5 seconds to abort..."
	@sleep 5
	SARIF_PATH=$(SARIF) $(PYTHON) run_agent.py

dry-run:
	$(PYTHON) run_agent.py --dry-run

test:
	SARIF_PATH=$(TEST_SARIF) $(PYTHON) -m pytest tests/ -q

check:
	SARIF_PATH=$(TEST_SARIF) $(PYTHON) -m pytest tests/ -q && \
	$(PYTHON) run_agent.py --dry-run

clean:
	rm -f outputs/audit/finding-*-audit.md outputs/notification-summary.md outputs/state.json

clean-ci-cache:
	gh cache delete remediation-state-$$(gh repo view --json nameWithOwner -q .nameWithOwner) --repo $$(gh repo view --json nameWithOwner -q .nameWithOwner) 2>/dev/null || echo "No cache found"
