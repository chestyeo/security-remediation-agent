# security-remediation-agent

An autonomous security remediation orchestrator that ingests CodeQL findings, tasks Devin to investigate and fix vulnerabilities, and generates audit-ready evidence for every remediated finding.

---

## The Problem

CodeQL scans flag dozens of issues every week. Security teams file tickets. Engineering teams ignore them — they're not in the sprint. The backlog grows. Auditors flag it. The cycle repeats.

For regulated industries like healthcare and financial services, unresolved findings are a compliance liability, not just tech debt.

---

## How It Works

```
Push to findings/codeql.sarif.json in medsecure
      |
GitHub Actions triggers security-remediation-agent workflow
      |
SARIF ingested → parsed → triaged: auto-remediable / requires-human / ignore
      |
For each auto-remediable finding:
  --> Devin session created with task prompt
  --> Devin reads the file, checks CODEOWNERS, understands context
  --> Devin generates a minimal safe fix on branch: security/fix-{finding_id}
  --> Devin runs tests and validates
  --> Devin opens a review-ready PR
      |
Audit artifact generated per finding (including failures)
      |
Notification summary posted to Slack + written as Actions job summary
      |
Audit artifacts uploaded to GitHub Actions run
      |
Failed/timeout findings: GitHub Issue opened with needs-manual-review label
```

The only human step is approving the merge.

---

## What Gets Generated

**Pull Request** — diff, remediation rationale, test output, audit metadata, and a manual test plan for the reviewer.

**Audit Artifact** — `outputs/audit/finding-{id}-audit.md` — full remediation chain from detection to PR open, timestamped at every step. CWE, OWASP, and HIPAA control mappings per rule. Uploaded to the Actions run on every execution.

**Notification Summary** — `outputs/notification-summary.md` — PRs opened, failing-test PRs, failed remediations, requires-human findings. Posted to Slack and written as the Actions job summary.

**Failure Issues** — GitHub Issue opened for every failed or timed-out Devin session. Labels: `security`, `needs-manual-review`. Every failure has a named owner.

**Requires-Human Issues** — GitHub Issue opened for every finding that triage routes to a human. Includes the rule, file, line, severity, and the triage reasoning explaining why it was not automated. Same labels and deduplication as failure issues.

**State File** — `outputs/state.json` — `finding_id → status` for deduplication on re-runs. Written after every finding. Remove an entry to force re-remediation.

---

## The Requires-Human Boundary

Not every finding gets sent to Devin. The triage layer classifies each finding into one of three buckets before any agent is invoked:

- **auto-remediable** — rule is in the known-safe set (SQL injection, hardcoded credentials, unsafe deserialisation, unsafe subprocess). Fix pattern is deterministic. Devin is dispatched.
- **requires-human** — rule requires contextual judgement to fix safely, or the fix pattern carries a risk of behaviour change. The finding is surfaced but not automated.
- **ignored** — file path is a test, generated, migration, or vendor file. Fixing it would not reduce real exposure.

Every `requires-human` finding appears in the Slack notification, the Actions job summary, and `outputs/notification-summary.md` with its rule, severity, file, and the triage reasoning explaining why it was not automated. A GitHub Issue is also opened automatically in the target repository so the finding has a named owner and a durable ticket. Nothing is silently dropped.

This boundary is intentional and configurable — the auto-remediable ruleset can be extended as your security team signs off on additional fix patterns. The point is that autonomy is opt-in per rule class, not blanket.

For enterprise and compliance reviewers: the audit trail accounts for 100% of ingested findings, not just the ones that were fixed. An auditor can verify that every finding was seen, triaged, and either remediated or explicitly routed to a human owner.

---

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN, TARGET_REPO

make test       # run test suite
make dry-run    # mock Devin results, no API calls
make run        # live run against Devin API
make clean      # remove generated outputs
```

See `agent.md` for full module specs and project structure.

---

## Environment Variables

```
DEVIN_API_KEY=cog_your_service_user_key
DEVIN_ORG_ID=your_org_id
GITHUB_TOKEN=your_github_token
TARGET_REPO=https://github.com/your-username/medsecure
SARIF_PATH=../medsecure/findings/codeql.sarif.json

# Optional Variables
SLACK_WEBHOOK_URL=... 
REPO_CRITICAL=true    
LOG_LEVEL=DEBUG       
TEST_COMMAND=pytest tests/
```

---

## Design Principles

- Human approval is always required before merge.
- Every finding produces a timestamped audit record, including failures.
- No silent failures. No fabricated PR URLs.
- Devin is the only non-deterministic component. Everything else is deterministic and replayable.
- Every Devin action is auditable by design, not by convention.

---

## Security Considerations

`GITHUB_TOKEN` requires `repo` scope — rotate regularly and store as a secret, never in source control. The Devin task prompt includes file paths and vulnerability descriptions but no secrets or PII. Devin operates on a repository clone and has no access to production systems unless explicitly granted. Review Devin's data residency documentation before connecting production codebases.

---

## Roadmap

### Phase 1 — Production Hardening (Now)

| Item | Status | Detail |
|---|---|---|
| Retry and backoff | ✅ | Exponential backoff on session creation; poll loop tolerates 3 consecutive errors |
| Env validation | ✅ | Exits code 1 with a clear message on any missing required variable |
| Deduplication | ✅ | `state.json` prevents duplicate Devin sessions on re-run |
| CI trigger | ✅ | `workflow_dispatch` and `repository_dispatch` on SARIF push |
| Slack notification | ✅ | Run summary posted after every run |

### Phase 2 — Team Integration (2 Months)

| Item | Detail |
|---|---|
| GitHub Code Scanning integration | Close findings in the Security tab on PR merge |
| Living audit artifact | Resolution section updated via webhook post-merge |
| Multi-repo support | Run across an entire GitHub organisation on a schedule |
| Parallel processing | ThreadPoolExecutor across findings — 80% wall-clock reduction |

**Target:** Mean time to remediation under 24 hours for auto-remediable findings.

### Phase 3 — Compliance and Scale (6 Months)

| Item | Detail |
|---|---|
| Compliance report generation | Monthly reports mapped to HIPAA, SOC 2, ISO 27001 |
| Issue tracker integration | Auto-create Jira/Linear tickets for requires-human findings |
| Client-configurable rulesets | Per-repository auto-remediable rule sets |
| Metrics dashboard | Remediation velocity, MTTR, backlog burn-down by team |
| Expanded language support | JavaScript, TypeScript, Java |

**Target:** Compliance officer produces an audit-ready report in one click.

---

## Current Constraints

Known Phase 1 scope boundaries, each with a resolution path above.

- **Sequential processing** — one finding at a time; parallelism is Phase 2.
- **No circuit breaker** — a sustained Devin outage fails the run; planned for Phase 2.
- **Point-in-time audit artifact** — merge confirmation and post-merge CodeQL closure require a webhook update (Phase 2).
- **Devin PR quality is partially verified** — failing tests are caught automatically; diff correctness requires engineer review before merge. This is by design.
- **Fixed auto-remediable ruleset** — covers the most common exploitable rules; per-repo configuration is Phase 3.
- **Audit intermediate timestamps are estimated** — `ingested_at`, `triaged_at`, `session_started_at`, and `completed_at` are real. Step-level entries (investigation, fix, validation, PR) are offsets from `completed_at`
- **State cache is best-effort** — `state.json` is persisted via `actions/cache` for the demo; production would use a durable store.
