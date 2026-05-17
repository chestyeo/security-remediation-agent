# security-remediation-agent

## What This Is

An autonomous security remediation orchestrator that ingests CodeQL findings, tasks Devin to investigate and fix vulnerabilities, and generates audit-ready evidence for every remediated finding.

Devin is the central actor. This system is the orchestration layer around it.

---

## Project Structure

```
security-remediation-agent/
├── agent.md                        ← this file
├── run_agent.py                    ← entrypoint, run this
├── Makefile                        ← make test / dry-run / run / clean
├── .github/
│   └── workflows/
│       └── remediate.yml           ← CI: workflow_dispatch + repository_dispatch from medsecure
├── fixtures/
│   └── demo.sarif.json             ← bundled demo findings (used by make dry-run and make test)
├── outputs/
│   ├── .gitkeep
│   ├── state.json                  ← deduplication state: finding_id → status, written per finding
│   ├── notification-summary.md     ← generated at runtime
│   └── audit/
│       ├── .gitkeep
│       └── finding-*-audit.md      ← generated at runtime, one per finding
├── prompts/
│   ├── __init__.py
│   └── devin_task_template.py      ← Devin prompt builder
├── src/
│   ├── __init__.py
│   ├── parser.py                   ← SARIF parser
│   ├── triage.py                   ← triage and prioritisation logic
│   ├── devin_client.py             ← Devin API wrapper (v3)
│   ├── audit.py                    ← audit artifact generator
│   ├── escalate.py                 ← GitHub Issue creation for failed remediations
│   └── notify.py                   ← notification summary generator + Slack webhook
├── tests/
│   ├── conftest.py                 ← shared pytest fixtures (uses fixtures/demo.sarif.json)
│   ├── test_parser.py
│   ├── test_triage.py
│   ├── test_prompt.py
│   ├── test_devin_client.py
│   ├── test_audit.py
│   ├── test_escalate.py
│   ├── test_notify.py
│   ├── test_run_agent.py
│   ├── test_rules_sync.py          ← enforces rule dict consistency across modules
│   └── test_connection.py          ← live API connectivity check (skipped by default)
├── pytest.ini
├── requirements.txt
├── .env.example
└── .gitignore
```

---

## How to Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN, TARGET_REPO, SARIF_PATH

make test       # run test suite
make dry-run    # demo run using fixtures/demo.sarif.json, no Devin API calls
make run        # live run — reads SARIF_PATH from .env, calls Devin API
make clean      # remove generated outputs
```

---

## Workflow

```
Push to findings/codeql.sarif.json in medsecure
      ↓
medsecure workflow fires repository_dispatch → remediate.yml triggered
(or: workflow_dispatch manually from GitHub Actions UI)
      ↓
SARIF file ingested
      ↓
Findings parsed and normalised to JSON
      ↓
Triage: auto-remediable / requires-human / ignore
      ↓
For each auto-remediable finding:
  → Devin API v3 session created with task prompt
  → Devin reads file, checks CODEOWNERS, understands context
  → Devin generates minimal safe fix on branch: security/fix-{finding_id}
  → Devin runs tests and validates
  → Devin opens review-ready PR
      ↓
Audit artifact generated per finding (including failed/timeout cases)
      ↓
Notification summary generated
      ↓
Slack webhook posted (if SLACK_WEBHOOK_URL set)
      ↓
Audit artifacts uploaded to GitHub Actions run
      ↓
Job summary written to Actions run (rendered markdown report)
      ↓
For any failed/timeout findings: GitHub Issue opened in medsecure
```

---

## Module Specs

### run_agent.py
Entrypoint. Accepts `--sarif` and `--dry-run` flags. Orchestrates the full pipeline with clear terminal output at each step.

```python
validate_env(dry_run)

findings = parse_sarif(sarif_path)
triaged  = triage_findings(findings)
state    = _load_state()   # outputs/state.json

for i, finding in enumerate(triaged["auto_remediable"], 1):
    if _already_remediated(finding_id, state):   # skip if state.json shows awaiting-approval
        continue
    result     = call_devin(finding, dry_run=dry_run)
    if result["status"] == "complete" and result["structured_output"].get("tests_passed") is False:
        result["status"] = "complete-tests-failed"
    state[finding_id] = result["status"]
    _save_state(state)   # written immediately after each finding
    audit_path = generate_audit_artifact(finding, result, timestamps)
    results.append({"finding": finding, "devin": result, "audit_path": audit_path})

generate_notification_summary(triaged, results)
```

`validate_env()` runs before any file I/O. Always checks `TARGET_REPO`. In non-dry-run mode also checks `DEVIN_API_KEY`, `DEVIN_ORG_ID`, and `GITHUB_TOKEN`. Exits with code 1 and a clear message if any are missing.

Log level: controlled by the `LOG_LEVEL` environment variable (default: `INFO`). Set `LOG_LEVEL=DEBUG` to surface prompt SHA256 tracing and full Devin response bodies on failure.

SARIF path resolution: `--sarif` flag → if `--dry-run` with no flag, uses `fixtures/demo.sarif.json` → else uses `$SARIF_PATH` → else `../medsecure/findings/codeql.sarif.json`.

Captures four real UTC timestamps per finding: `ingested_at`, `triaged_at`, `session_started_at`, `completed_at`.

Deduplication: before calling Devin, reads `outputs/state.json` (created on first run). Skips any finding whose `finding_id` maps to `awaiting-approval` or `tests-failed` in the state file — both are treated as already-handled. State is written after every finding so a mid-run crash does not lose progress. Remove a `finding_id` entry from `state.json` to force a re-run of that specific finding — this applies to `tests-failed` findings too; removing the entry is the only way to trigger a new Devin session for a finding whose PR has failing tests.

Terminal summary reports three distinct counts: `Remediated` (complete), `Tests failed (PR open)` (complete-tests-failed), `Failed (no PR)` (failed or timeout).

Fatal errors (parse/triage failure) exit with code 1. Per-finding errors (Devin failure, audit write failure) are logged and the loop continues. Notification summary failure propagates — silent loss of the summary is treated as a fatal error.

---

### src/parser.py
Parses CodeQL SARIF 2.1.0 output.

Input: path to a `.sarif.json` file

Severity resolution: prefers CVSS `security-severity` float from rule properties (8.8 → `high`), falls back to SARIF `level` string.

Output: list of normalised finding dicts with fields:
- `finding_id` — derived as `{rule_id}-{filename}-L{line}`, e.g. `py-sql-injection-payments.py-L20`
- `severity` — `critical` / `high` / `medium` / `low`
- `rule_id` — e.g. `py/sql-injection`
- `file` — relative path to vulnerable file
- `line` — line number
- `message` — CodeQL finding message

---

### src/triage.py
Classifies and prioritises findings.

Classification:
- `auto-remediable` — rule is in the known-safe set: SQL injection, hardcoded credentials, unsafe deserialisation, unsafe subprocess
- `requires-human` — anything not in the auto-remediable set
- `ignore` — file path matches a test/generated/vendor pattern

Priority score (0–100):
- Severity weight: critical=40, high=30, medium=20, low=10
- Rule exploitability bonus: 0–35 per rule
- `REPO_CRITICAL=true` env var adds 20

Output per finding adds: `classification`, `priority`, `reasoning`.

---

### prompts/devin_task_template.py
Builds the Devin task prompt for a specific finding.

Prompt includes:
- Target repo, branch (`security/fix-{finding_id}`), file, line, rule, severity
- Rule-specific vulnerability description and fix instruction
- Hard constraints (do not refactor, rename, modify other files)
- Validation steps (run pytest, confirm passing before PR)
- Investigation-first instruction (read file and CODEOWNERS before writing any fix)
- Exact PR title: `[Security] Fix {vulnerability} in {filename}`
- PR body template with audit metadata: `finding_id`, `rule_id`, `severity`, `file`, `line`, `timestamp`

Falls back to generic guidance for rules not in the known-rule dict.

---

### src/devin_client.py
Wrapper around the Devin API v3.

```
Base URL:  https://api.devin.ai/v3/organizations/{DEVIN_ORG_ID}/sessions
Auth:      Authorization: Bearer {DEVIN_API_KEY}   (cog_ prefix key)
Create:    POST /sessions  →  200  {"session_id": "..."}
Poll:      GET  /sessions/{session_id}  every 15s, 600s timeout
```

Terminal states: `complete`, `finished`, `failed`, `error`, `stopped`, `blocked`.

`dry_run=True` skips the API entirely and returns a mock result with a PR URL in the form `https://github.com/demo/repo/pull/DRY-RUN-{hash}`. The `demo/repo` path is hardcoded — audit artifacts generated during a dry run will contain this placeholder regardless of `TARGET_REPO`. This is intentional: dry-run outputs are not real and should not reference a real repository.

`call_devin(finding, dry_run)` returns: `{status, pr_url, session_url, structured_output}`.

Retry and resilience:
- `create_session` retries up to 3 times with exponential backoff (2s, 4s, 8s) on any network error or non-200 response. Raises after all attempts exhausted.
- `poll_session` logs elapsed time on every poll cycle. Tolerates up to 3 consecutive network errors per session, resetting the counter on each successful poll. Abandons and returns `status: "failed"` only after 3 consecutive failures.

Failure handling:
- `failed` / `blocked` / `stopped` — logged with reason, returned as `status: "failed"`; full response body logged at DEBUG
- Timeout — logged with duration, returned as `status: "timeout"`
- Both cases always return `session_url` for direct inspection

Observability:
- Prompt SHA256 (first 12 chars) logged at DEBUG before every session creation — enables prompt-version tracing
- Full Devin response body logged at DEBUG on any failure — enables post-mortem without re-running

---

### src/audit.py
Generates a markdown audit artifact per finding, regardless of outcome.

Output: `outputs/audit/finding-{finding_id}-audit.md`

Sections:
- **Finding** — rule, severity, file, line
- **Triage** — classification, priority score, reasoning
- **Remediation Timeline** — timestamped entries from ingestion through PR open
- **Pull Request** — URL and status (or explicit failure message — no URL fabricated)
- **Devin Session** — session URL, outcome, and prompt version (from `PROMPT_VERSION` constant in `devin_task_template.py`)
- **Compliance** — rule mapped to CWE, OWASP Top 10, and HIPAA control (e.g. `py/sql-injection` → CWE-089 / A03:2021 / § 164.312(a)(1) Access Control)
- **Resolution** — living-document fields: PR status, merge confirmed, CodeQL closure
- **Compliance Notes** — human approval required before merge

Timeline branches on status:
- `complete` with `pr_url` — full 8-entry happy path ending with "Awaiting engineer approval"
- `complete` without `pr_url` — Devin session completed but no PR URL was returned; PR status recorded as `complete-no-pr-url`; not escalated as a failure but requires manual investigation
- `complete-tests-failed` — PR opened but Devin reported tests failing; flagged for engineer review; finding is skipped on re-run (remove from `state.json` to retry)
- `failed` — terminal entry with session URL, no PR URL fabricated
- `timeout` — terminal entry with session URL, no PR URL fabricated

Takes an optional `timestamps` dict (`ingested_at`, `triaged_at`, `session_started_at`, `completed_at`); defaults all to `now()` when omitted.

---

### src/notify.py
Generates a run summary after all findings are processed and posts it to Slack.

Output: `outputs/notification-summary.md`

Sections:
- **Results** — five-row counts: ingested, auto-remediated, PRs opened with failing tests, failed (no PR), requires-human, ignored
- **PRs Opened** — one line per `complete` remediation with PR URL, rule, file
- **PRs Opened — Tests Failing** — one line per `complete-tests-failed` result; includes PR URL and session URL; engineer review required before merge
- **Failed Remediations** — status, rule, file, session URL for `failed` and `timeout` results only (no PR URL fabricated)
- **Requires Human Investigation** — rule, file, severity, triage reasoning, and a link to the GitHub Issue if one was opened
- **Audit Artifacts** — path per attempted remediation
- **Next Steps** — review PRs, audit artifacts available

Slack: after writing the summary file, posts a formatted message to `SLACK_WEBHOOK_URL` if set. Message includes run status, counts, clickable PR links, clickable requires-human issue links (one per finding, if issue creation succeeded), and a direct link to the Actions run when `GITHUB_SERVER_URL`, `GITHUB_REPOSITORY`, and `GITHUB_RUN_ID` are present. Silently skips if the webhook URL is absent — dry-run and test runs are unaffected.

---

### src/escalate.py
Two issue-creation functions, both using the same GitHub API wrapper and deduplication logic.

**`create_requires_human_issue(finding)`** — called from `run_agent.py` during triage for every `requires-human` finding. Skipped in dry-run mode. The returned issue URL is stored on the finding dict (`finding["issue_url"]`) so the notification summary and Slack message can link to it.

- Title: `[Security] Requires human review — {rule_id} in {file}`
- Body: finding details table (ID, rule, file, line, severity, priority), triage reasoning, next steps
- Labels: `security`, `needs-manual-review`

**`create_failure_issue(finding, devin_result)`** — called from `run_agent.py` immediately after state is written for `failed` or `timeout` outcomes.

- Title: `[Security] Remediation failed — {rule_id} in {file}`
- Body: finding details table (ID, rule, file, line, severity, status, Devin session URL), next steps, audit artifact path
- Labels: `security`, `needs-manual-review`

Both functions use `GITHUB_TOKEN` and `TARGET_REPO` — no additional credentials required. Return the issue URL on success, empty string on failure. Silently skip if either env var is absent. Deduplicate — search open issues with the `security` label before posting; skip creation if a matching title already exists.

---

## Environment Variables

```
DEVIN_API_KEY=cog_your_service_user_key
DEVIN_ORG_ID=your_org_id
GITHUB_TOKEN=your_github_token
TARGET_REPO=https://github.com/your-username/medsecure
SARIF_PATH=../medsecure/findings/codeql.sarif.json
```

Optional:
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...   ← posts run summary to Slack channel
REPO_CRITICAL=true    ← adds 20 points to every finding's priority score
LOG_LEVEL=DEBUG       ← enables prompt SHA256 tracing and full Devin response bodies on failure (default: INFO)
TEST_COMMAND=pytest tests/   ← override if the target repo uses a different test runner (e.g. "npm test", "python -m pytest")
```

In GitHub Actions, all variables are set as repository secrets. `GITHUB_TOKEN` is provided automatically by the runner.

`SARIF_PATH` can point to a findings file in a separate repository (e.g. the target app being remediated). The `--sarif` CLI flag overrides it when provided. `make dry-run` bypasses `SARIF_PATH` and always uses `fixtures/demo.sarif.json`.

`GITHUB_TOKEN` must have `repo` scope. It is validated at startup in non-dry-run mode. It is passed to Devin as a secret so Devin can clone and push to the target repository.

---

## Design Principles

- Devin owns remediation end to end. This system orchestrates. Engineers approve.
- Human approval is always required before merge.
- Every finding produces a timestamped audit record, including failures.
- No silent failures. No fabricated PR URLs.
- Devin is the only non-deterministic component. Everything else is deterministic and replayable.
- Reliability over autonomy: Devin cannot affect a protected branch without a human gate.
- Every Devin action is auditable by design, not by convention.

---

## Success Criteria

The project succeeds if the viewer believes:

> "Security findings can move from detection to validated closure with minimal human coordination."

The strongest outcome is not "AI generated code."
The strongest outcome is "the remediation process now closes itself."