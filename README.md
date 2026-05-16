# security-remediation-agent

An autonomous security remediation orchestrator that ingests CodeQL findings, tasks Devin to investigate and fix vulnerabilities, and generates audit-ready evidence for every remediated finding.

Devin is the central actor. This system is the orchestration layer around it.

---

## The Problem

Enterprise engineering teams accumulate security debt faster than they can clear it.

CodeQL scans flag dozens of issues every week. Security teams file tickets. Engineering teams ignore them because they fall outside sprint planning. The backlog grows. Auditors flag it. The cycle repeats.

For regulated industries like healthcare and financial services, unresolved findings are not just technical debt. They are a compliance liability.

---

## How It Works

```
Push to findings/codeql.sarif.json in medsecure
      |
GitHub Actions triggers security-remediation-agent workflow
      |
SARIF file ingested
      |
Findings parsed and normalised to JSON
      |
Triage: auto-remediable / requires-human / ignore
      |
For each auto-remediable finding:
  --> Devin API v3 session created with task prompt
  --> Devin reads the file, checks CODEOWNERS, understands context
  --> Devin generates a minimal safe fix on branch: security/fix-{finding_id}
  --> Devin runs tests and validates
  --> Devin opens a review-ready PR
      |
Audit artifact generated per finding
      |
Notification summary generated + Slack webhook posted
      |
Audit artifacts uploaded to GitHub Actions run
```

Devin does not generate a suggested fix for an engineer to implement. It investigates the repository context, understands the surrounding code, generates the fix, runs the test suite, and opens the PR. The only human step is approving the merge.

---

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Fill in DEVIN_API_KEY, DEVIN_ORG_ID, GITHUB_TOKEN, TARGET_REPO, SARIF_PATH

make test       # run test suite
make dry-run    # run agent with mock Devin results
make run        # run agent against live Devin API
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
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...  <- optional, posts run summary to channel
REPO_CRITICAL=true    <- optional, adds 20 points to priority score
LOG_LEVEL=DEBUG       <- optional, surfaces prompt SHA256 tracing and full Devin response bodies
```

In GitHub Actions these are set as repository secrets. Locally, copy `.env.example` to `.env` and fill them in.

---

## What Gets Generated

**Pull Request** — Devin opens a review-ready PR containing the diff, remediation rationale, test output, audit metadata, and a manual test plan for the reviewer.

**Audit Artifact** — `outputs/audit/finding-{id}-audit.md` mapping the full remediation chain from detection to PR open, timestamped at every step. Includes CWE, OWASP, and HIPAA control mappings per rule. Uploaded to the GitHub Actions run on every execution.

**Notification Summary** — `outputs/notification-summary.md` covering all findings: PRs opened (complete), PRs opened with failing tests (engineer review required), failed remediations (no PR), and requires-human findings, with session URLs and audit artifact paths. Posted to Slack if `SLACK_WEBHOOK_URL` is set.

**State File** — `outputs/state.json` tracking `finding_id → status` for every attempted remediation. Used for deduplication on re-runs. Written after every finding so a mid-run crash does not lose progress. Remove an entry to force re-remediation of that finding.

---

## Design Principles

- Devin owns remediation end to end.
- Human approval is always required before merge.
- Every finding produces a timestamped audit record, including failures.
- No silent failures and no fabricated PR URLs.
- Devin is the only non-deterministic component. Everything else is deterministic and replayable.
- Reliability over autonomy: Devin cannot affect a protected branch without a human gate.
- Every Devin action is auditable by design, not by convention.

---

## Roadmap

### Phase 1 — Production Hardening (Now)

The agent works end to end. This phase makes it reliable enough to run unattended.

| Item | Status | Detail |
|---|---|---|
| Retry and backoff | ✅ Done | Exponential backoff on `create_session`, resilient poll loop tolerates 3 consecutive errors |
| Env validation | ✅ Done | `validate_env()` checks `TARGET_REPO`, `DEVIN_API_KEY`, `DEVIN_ORG_ID`, `GITHUB_TOKEN` — exits code 1 on missing |
| Deduplication | ✅ Done | `outputs/state.json` tracks `finding_id → status`; written after each finding; no duplicate Devin sessions on re-run |
| GitHub Actions trigger | ✅ Done | `workflow_dispatch` (manual) and `repository_dispatch` from medsecure on SARIF push; audit artifacts uploaded on every run |
| Slack notification | ✅ Done | Run summary posted to webhook after every run; silently skips if `SLACK_WEBHOOK_URL` unset |

**Success criteria:** Agent runs unattended on a live CodeQL pipeline with zero manual intervention. Transient failures recover automatically. No duplicate PRs.

---

### Phase 2 — Team Integration (2 Months)

The agent closes findings. This phase closes the loop with the humans who care.

| Item | Detail |
|---|---|
| GitHub Code Scanning integration | Close findings in the Security tab automatically when PRs merge |
| Living audit artifact | Webhook updates Resolution section on PR merge and post-merge scan |
| Multi-repo support | Run across an entire GitHub organisation on a schedule |
| Parallel processing | ThreadPoolExecutor across findings, reducing wall-clock time by 80% |

**Success criteria:** Security team receives a weekly automated summary with zero manual reporting. Audit artifacts reflect real-world resolution status. Mean time to remediation under 24 hours for auto-remediable findings.

---

### Phase 3 — Compliance and Scale (6 Months)

The agent remediates findings. This phase turns remediation data into compliance evidence.

| Item | Detail |
|---|---|
| Compliance report generation | Monthly audit reports mapped to HIPAA, SOC 2, and ISO 27001 |
| Issue tracker integration | Auto-create Jira and Linear tickets for requires-human findings, close on merge |
| Client-configurable rulesets | Per-repository auto-remediable rule sets based on risk tolerance |
| Metrics dashboard | Remediation velocity, mean time to remediation, backlog burn-down by team |
| Expanded language support | JavaScript, TypeScript, Java rule coverage beyond Python |

**Success criteria:** Compliance officer can produce an audit-ready remediation report in one click. Security backlog burn-down is measurable and improving quarter over quarter. Agent covers 80% of auto-remediable findings across the engineering organisation.

---

## Known Limitations

- No circuit breaker: a sustained Devin API outage fails the entire run with no fallback path
- Devin PR quality is partially verified: failing tests are caught via `structured_output.tests_passed`, but wrong branch or incorrect diff requires engineer review
- Findings are processed sequentially: ten findings at ten minutes each is one hundred minutes wall-clock time (Phase 2 item)
- Audit artifact Resolution section does not update post-merge: merge confirmed and CodeQL closure fields remain pending until manually updated (Phase 2 item)
- No prompt versioning: changes to devin_task_template.py affect all future runs with no rollback mechanism

---

## Security Considerations

The GitHub token requires repo scope and should be rotated regularly. Store it as a Devin secret and local environment variable. Never commit it to source control.

The Devin task prompt includes file paths, line numbers, and vulnerability descriptions. It does not include secrets, PII, or production credentials. Review what your SARIF file contains before running against a third-party API.

Devin operates on a clone of the target repository. It does not have access to production systems or databases unless explicitly granted. For regulated environments, review Devin's data handling and residency documentation before connecting production codebases.

This agent does not validate that Devin's fix was applied to the correct file or branch. Engineer review of the PR diff before approval is essential.