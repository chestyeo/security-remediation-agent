import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import requests

from src.audit import get_compliance
from prompts.devin_task_template import get_rule_title

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _pr_link(pr_url: str) -> str:
    if not pr_url:
        return "—"
    number = pr_url.rstrip("/").split("/")[-1]
    return f"[#{number}]({pr_url})"


def _issue_link(issue_url: str) -> str:
    if not issue_url:
        return "—"
    number = issue_url.rstrip("/").split("/")[-1]
    return f"[#{number}]({issue_url})"


def _compact_compliance(rule_id: str) -> str:
    c = get_compliance(rule_id)
    cwe   = c["cwe"].split(" — ")[0]
    hipaa = c["hipaa"].split(" — ")[0].split(";")[0].strip()
    return f"{cwe} / HIPAA {hipaa}"


def _remediated_section(successful: list[dict]) -> str:
    if not successful:
        return "## Remediated\n\nNone."
    lines = ["## Remediated", "", "| Finding | Severity | PR | Compliance |", "|---|---|---|---|"]
    for r in successful:
        f = r["finding"]
        title    = get_rule_title(f["rule_id"])
        filename = Path(f["file"]).name
        severity = f["severity"].capitalize()
        pr       = _pr_link(r["devin"].get("pr_url", ""))
        comp     = _compact_compliance(f["rule_id"])
        lines.append(f"| {title} in {filename} | {severity} | {pr} | {comp} |")
    return "\n".join(lines)


def _requires_human_table(requires_human: list) -> str:
    if not requires_human:
        return ""
    lines = ["## Requires Human Review", "", "| Finding | Severity | Reason | Issue |", "|---|---|---|---|"]
    for f in requires_human:
        title    = get_rule_title(f["rule_id"])
        filename = Path(f["file"]).name
        severity = f["severity"].capitalize()
        reason   = f.get("reasoning", "Requires contextual judgement")
        issue    = _issue_link(f.get("issue_url", ""))
        lines.append(f"| {title} in {filename} | {severity} | {reason} | {issue} |")
    return "\n".join(lines)


def _tests_failed_section(tests_failed: list[dict]) -> str:
    if not tests_failed:
        return ""
    lines = ["## PRs Opened — Tests Failing (Engineer Review Required)", ""]
    for r in tests_failed:
        f = r["finding"]
        pr_url = r["devin"].get("pr_url", "")
        session_url = r["devin"]["session_url"]
        lines.append(f"- **{f['finding_id']}** — PR opened but tests failed")
        lines.append(f"  - Rule: {f['rule_id']} in {f['file']} (line {f['line']})")
        if pr_url:
            lines.append(f"  - PR: {pr_url}")
        lines.append(f"  - Session: {session_url}")
    return "\n".join(lines) + "\n"


def _failures_section(failed: list[dict]) -> str:
    if not failed:
        return ""
    lines = ["## Failed Remediations", ""]
    for r in failed:
        f = r["finding"]
        status = r["devin"]["status"]
        session_url = r["devin"]["session_url"]
        lines.append(f"- **{f['finding_id']}** — {status}")
        lines.append(f"  - Rule: {f['rule_id']} in {f['file']} (line {f['line']})")
        lines.append(f"  - Session: {session_url}")
    return "\n".join(lines) + "\n"


def _artifacts_section(results: list[dict]) -> str:
    lines = ["## Audit Artifacts", "", "Available in Actions run artifacts — one file per finding.", ""]
    for r in results:
        if r.get("audit_path"):
            lines.append(f"- {r['audit_path']}")
    return "\n".join(lines)


def _post_slack(total: int, successful: list, tests_failed: list, failed: list,
                requires_human: list, results: list) -> None:
    url = os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return
    status = "✅ Complete" if not failed and not tests_failed else "⚠️ Needs Review"
    lines = [
        f"*Security Remediation Run — {status}*",
        f"• Findings ingested: {total}",
        f"• Auto-remediated: {len(successful)}",
    ]
    if tests_failed:
        lines.append(f"• PRs with failing tests (review required): {len(tests_failed)}")
    if failed:
        lines.append(f"• Failed (no PR): {len(failed)}")
    if requires_human:
        lines.append(f"• Requires human review: {len(requires_human)}")
        for f in requires_human:
            issue_url = f.get("issue_url", "")
            title = get_rule_title(f["rule_id"])
            name = Path(f["file"]).name
            if issue_url:
                lines.append(f"  - <{issue_url}|{title} in {name}>")
    if successful:
        lines.append("")
        lines.append("*Remediated*")
        for r in successful:
            f = r["finding"]
            title = get_rule_title(f["rule_id"])
            lines.append(f"• <{r['devin']['pr_url']}|{title} in {Path(f['file']).name}>")
    if results:
        lines.append("")
        lines.append("Audit artifacts uploaded to workflow run.")
    server = os.environ.get("GITHUB_SERVER_URL")
    gh_repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and gh_repo and run_id:
        lines.append(f"\n<{server}/{gh_repo}/actions/runs/{run_id}|View Actions run →>")
    try:
        resp = requests.post(url, json={"text": "\n".join(lines)}, timeout=10)
        resp.raise_for_status()
        logger.info("Slack notification posted successfully")
    except Exception as exc:
        logger.warning("Slack notification failed: %s", exc)


def generate_notification_summary(triaged: dict, results: list[dict]) -> str:
    """
    triaged  — dict from triage_findings: {auto_remediable, requires_human, ignored}
    results  — list of {finding, devin, audit_path} dicts, one per attempted remediation

    Returns the path of the written summary file.
    """
    auto_remediable = triaged["auto_remediable"]
    requires_human  = triaged["requires_human"]
    ignored         = triaged["ignored"]
    total           = len(auto_remediable) + len(requires_human) + len(ignored)

    successful   = [r for r in results if r["devin"]["status"] == "complete"]
    tests_failed = [r for r in results if r["devin"]["status"] == "complete-tests-failed"]
    failed       = [r for r in results if r["devin"]["status"] in ("failed", "timeout")]

    sections = [
        _remediated_section(successful),
        _requires_human_table(list(requires_human)),
        _tests_failed_section(tests_failed),
        _failures_section(failed),
        _artifacts_section(results),
    ]
    body_sections = "\n\n".join(s for s in sections if s)

    body = f"""\
# Security Remediation Run — {_date_str()}

Generated: {_now()}

## Results
| Metric | Count |
|---|---|
| Findings ingested | {total} |
| Auto-remediated | {len(successful)} |
| Requires human review | {len(requires_human)} |
| Failed | {len(failed) + len(tests_failed)} |
| Ignored | {len(ignored)} |

{body_sections}

## Next Steps
- Review and approve PRs in GitHub
- Audit artifacts available for compliance review in outputs/audit/
"""

    out_path = Path("outputs/notification-summary.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(body)

    _post_slack(total, successful, tests_failed, failed, list(requires_human), results)

    return str(out_path)
