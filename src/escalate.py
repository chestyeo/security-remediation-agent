import logging
import os
import re

import requests

logger = logging.getLogger(__name__)

_GITHUB_API = "https://api.github.com"


def _parse_repo(target_repo: str) -> tuple[str, str] | None:
    match = re.match(r"https://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", target_repo.strip())
    if not match:
        return None
    return match.group(1), match.group(2)


def _issue_exists(owner: str, repo: str, title: str, token: str) -> bool:
    try:
        resp = requests.get(
            f"{_GITHUB_API}/repos/{owner}/{repo}/issues",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            params={"labels": "security", "state": "open"},
            timeout=15,
        )
        resp.raise_for_status()
        return any(i.get("title") == title for i in resp.json())
    except Exception:
        return False


def create_failure_issue(finding: dict, devin_result: dict) -> str:
    """
    Opens a GitHub issue in the target repo for a failed or timed-out remediation.
    Returns the issue URL, or empty string if creation fails or credentials are absent.
    """
    token = os.environ.get("GITHUB_TOKEN")
    target_repo = os.environ.get("TARGET_REPO", "")
    if not token or not target_repo:
        return ""

    parsed = _parse_repo(target_repo)
    if not parsed:
        logger.warning("Could not parse TARGET_REPO for issue creation: %s", target_repo)
        return ""

    owner, repo = parsed
    fid = finding["finding_id"]
    status = devin_result["status"]
    session_url = devin_result.get("session_url", "")

    server = os.environ.get("GITHUB_SERVER_URL")
    gh_repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and gh_repository and run_id:
        artifact_ref = f"[View Actions run]({server}/{gh_repository}/actions/runs/{run_id})"
    else:
        artifact_ref = f"`outputs/audit/finding-{fid}-audit.md`"

    title = f"[Security] Remediation failed — {finding['rule_id']} in {finding['file']}"
    body = f"""\
## Remediation Failure

Devin could not automatically remediate this finding. Manual investigation required.

| Field | Value |
|---|---|
| Finding ID | `{fid}` |
| Rule | `{finding['rule_id']}` |
| File | `{finding['file']}` |
| Line | {finding['line']} |
| Severity | {finding['severity']} |
| Status | `{status}` |
| Devin session | {session_url} |

## Next Steps

1. Review the Devin session log for the failure reason
2. Apply the fix manually or re-run once the blocker is resolved
3. Close this issue when the finding is remediated

## Compliance

Audit artifact: {artifact_ref}
"""

    if _issue_exists(owner, repo, title, token):
        logger.info("[%s] Failure issue already exists — skipping creation", fid)
        return ""

    try:
        resp = requests.post(
            f"{_GITHUB_API}/repos/{owner}/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={"title": title, "body": body, "labels": ["security", "needs-manual-review"]},
            timeout=15,
        )
        resp.raise_for_status()
        issue_url = resp.json().get("html_url", "")
        logger.info("[%s] Failure issue created: %s", fid, issue_url)
        return issue_url
    except Exception as exc:
        logger.warning("[%s] Failed to create GitHub issue: %s", fid, exc)
        return ""
