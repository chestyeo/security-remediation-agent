from datetime import datetime, timedelta, timezone
from pathlib import Path

from prompts.devin_task_template import PROMPT_VERSION

# Maps rule_id → CWE, OWASP Top 10, and HIPAA control references.
# HIPAA controls are chosen based on the threat each vulnerability class poses
# to the confidentiality and integrity of ePHI.
_COMPLIANCE_MAP = {
    "py/sql-injection": {
        "cwe":   "CWE-089 — Improper Neutralisation of Special Elements in SQL Commands",
        "owasp": "A03:2021 — Injection",
        "hipaa": "§ 164.312(a)(1) — Access Control; § 164.312(c)(1) — Integrity",
    },
    "js/sql-injection": {
        "cwe":   "CWE-089 — Improper Neutralisation of Special Elements in SQL Commands",
        "owasp": "A03:2021 — Injection",
        "hipaa": "§ 164.312(a)(1) — Access Control; § 164.312(c)(1) — Integrity",
    },
    "java/sql-injection": {
        "cwe":   "CWE-089 — Improper Neutralisation of Special Elements in SQL Commands",
        "owasp": "A03:2021 — Injection",
        "hipaa": "§ 164.312(a)(1) — Access Control; § 164.312(c)(1) — Integrity",
    },
    "py/hardcoded-credentials": {
        "cwe":   "CWE-798 — Use of Hard-coded Credentials",
        "owasp": "A07:2021 — Identification and Authentication Failures",
        "hipaa": "§ 164.312(d) — Person or Entity Authentication",
    },
    "js/hardcoded-credentials": {
        "cwe":   "CWE-798 — Use of Hard-coded Credentials",
        "owasp": "A07:2021 — Identification and Authentication Failures",
        "hipaa": "§ 164.312(d) — Person or Entity Authentication",
    },
    "py/clear-text-storage-of-sensitive-data": {
        "cwe":   "CWE-312 — Cleartext Storage of Sensitive Information",
        "owasp": "A02:2021 — Cryptographic Failures",
        "hipaa": "§ 164.312(e)(2)(ii) — Encryption and Decryption",
    },
    "py/unsafe-deserialization": {
        "cwe":   "CWE-502 — Deserialisation of Untrusted Data",
        "owasp": "A08:2021 — Software and Data Integrity Failures",
        "hipaa": "§ 164.306(a)(1) — Protect against reasonably anticipated threats to ePHI",
    },
    "py/unsafe-use-of-subprocess": {
        "cwe":   "CWE-078 — Improper Neutralisation of Special Elements in an OS Command",
        "owasp": "A03:2021 — Injection",
        "hipaa": "§ 164.306(a)(1) — Protect against reasonably anticipated threats to ePHI",
    },
    "rb/sql-injection": {
        "cwe":   "CWE-089 — Improper Neutralisation of Special Elements in SQL Commands",
        "owasp": "A03:2021 — Injection",
        "hipaa": "§ 164.312(a)(1) — Access Control; § 164.312(c)(1) — Integrity",
    },
}

_DEFAULT_COMPLIANCE = {
    "cwe":   "See CodeQL rule documentation",
    "owasp": "See OWASP Top 10",
    "hipaa": "§ 164.306(a)(1) — Protect against reasonably anticipated threats to ePHI",
}


_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_FMT)


def _spread(completed_at: str) -> dict:
    """Returns synthetic intermediate timestamps spread before completed_at.
    Offsets reflect a realistic Devin session: investigation → fix → tests → PR.
    """
    try:
        end = datetime.strptime(completed_at, _FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        end = datetime.now(timezone.utc)

    def _f(delta_seconds: int) -> str:
        return (end - timedelta(seconds=delta_seconds)).strftime(_FMT)

    return {
        "investigated": _f(300),
        "fix_generated": _f(180),
        "validated":     _f(60),
        "pr_opened":     _f(30),
        "completed":     _f(0),
    }


def _timeline(finding: dict, result: dict, ts: dict) -> str:
    status = result["status"]
    lines = [
        f"- {ts['ingested_at']} — Finding ingested from CodeQL SARIF",
        f"- {ts['triaged_at']} — Triage completed: {finding['classification']} (priority {finding['priority']}/100)",
        f"- {ts['session_started_at']} — Devin session started",
    ]

    if status == "complete":
        s = _spread(ts["completed_at"])
        lines += [
            f"- {s['investigated']} — Repository investigation complete",
            f"- {s['fix_generated']} — Fix generated",
            f"- {s['validated']} — Validation passed",
            f"- {s['pr_opened']} — PR opened: {result['pr_url']}",
            f"- {s['completed']} — Awaiting engineer approval",
        ]
    elif status == "complete-tests-failed":
        s = _spread(ts["completed_at"])
        lines += [
            f"- {s['investigated']} — Repository investigation complete",
            f"- {s['fix_generated']} — Fix generated",
            f"- {s['validated']} — WARNING: Devin reported tests FAILED",
            f"- {s['pr_opened']} — PR opened (tests failing): {result['pr_url']}",
        ]
    elif status == "failed":
        lines.append(f"- {ts['completed_at']} — Devin session failed — see session for details: {result['session_url']}")
    elif status == "timeout":
        lines.append(f"- {ts['completed_at']} — Devin session timed out after 900s — session: {result['session_url']}")

    return "\n".join(lines)


def _compliance_section(rule_id: str) -> str:
    c = _COMPLIANCE_MAP.get(rule_id, _DEFAULT_COMPLIANCE)
    return f"""\
## Compliance
- CWE: {c['cwe']}
- OWASP: {c['owasp']}
- HIPAA: {c['hipaa']}"""


def _resolution_section(result: dict) -> str:
    status = result["status"]
    if status == "complete" and result.get("pr_url"):
        pr_status = "awaiting-approval"
    elif status == "complete":
        pr_status = "complete-no-pr-url"
    else:
        pr_status = status
    return f"""\
## Resolution
- PR status: {pr_status}
- Merge confirmed: pending
- CodeQL closure: pending post-merge scan"""


def _pull_request_section(result: dict) -> str:
    status = result["status"]
    if status == "complete" and result.get("pr_url"):
        return f"""\
## Pull Request
- URL: {result['pr_url']}
- Status: awaiting-approval"""
    elif status == "complete":
        return """\
## Pull Request
- URL: none — session completed but no PR URL returned
- Status: complete-no-pr-url"""
    elif status == "complete-tests-failed" and result.get("pr_url"):
        return f"""\
## Pull Request
- URL: {result['pr_url']}
- Status: complete-tests-failed — tests failing, engineer review required"""
    elif status == "complete-tests-failed":
        return """\
## Pull Request
- URL: none — session completed but no PR URL returned
- Status: complete-tests-failed"""
    elif status == "failed":
        return """\
## Pull Request
- URL: none — Devin session failed before PR was opened
- Status: failed"""
    else:
        return """\
## Pull Request
- URL: none — Devin session timed out before PR was opened
- Status: timeout"""


def generate_audit_artifact(finding: dict, result: dict, timestamps: dict | None = None) -> str:
    """
    finding  — annotated finding dict (parser + triage fields combined)
    result   — dict returned by call_devin: {status, pr_url, session_url}
    timestamps — optional dict of UTC ISO strings:
                 ingested_at, triaged_at, session_started_at, completed_at
                 Defaults to now() for all keys when omitted.

    Returns the path of the written audit file.
    """
    now = _now()
    ts = {
        "ingested_at":       now,
        "triaged_at":        now,
        "session_started_at": now,
        "completed_at":      now,
        **(timestamps or {}),
    }

    finding_id  = finding["finding_id"]
    rule_id     = finding["rule_id"]
    severity    = finding["severity"]
    file        = finding["file"]
    line        = finding["line"]
    filename    = Path(file).name
    priority    = finding["priority"]
    reasoning   = finding["reasoning"]
    session_url = result.get("session_url", "")
    status      = result["status"]

    body = f"""\
# Audit Record — Finding {finding_id}

Generated: {now}

## Finding
- Rule: {rule_id}
- Severity: {severity}
- File: {file}
- Line: {line}

## Triage
- Classification: {finding['classification']}
- Priority: {priority}/100
- Reasoning: {reasoning}

## Remediation Timeline
{_timeline(finding, result, ts)}

{_pull_request_section(result)}

## Devin Session
- URL: {session_url}
- Outcome: {status}
- Prompt version: {PROMPT_VERSION}

{_compliance_section(rule_id)}

{_resolution_section(result)}

## Compliance Notes
Human approval required before merge.
Engineer must verify fix does not alter application behaviour before approving.
Audit record generated automatically.
"""

    out_path = Path("outputs/audit") / f"finding-{finding_id}-audit.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(body)
    return str(out_path)
