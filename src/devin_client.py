import hashlib
import json
import logging
import os
import re
import time

import requests

_PR_URL_RE = re.compile(r"^https://github\.com/[^/]+/[^/]+/pull/\d+$")
from dotenv import load_dotenv

from prompts.devin_task_template import build_prompt

load_dotenv()

logger = logging.getLogger(__name__)

_SESSIONS_URL = "https://api.devin.ai/v3/organizations/{org_id}/sessions"
_APP_SESSION_URL = "https://app.devin.ai/sessions/{session_id}"
_POLL_INTERVAL = 15
_PR_CHECK_INTERVAL = 60  # check GitHub for a merged/opened PR every N seconds

# Devin v3 terminal states per API docs: exit = success, error = failed, suspended = blocked
_TERMINAL_STATES = {"exit", "error", "suspended"}
_SUCCESS_STATES   = {"exit"}


_PERMANENT_ERRORS = {
    401: "Invalid or expired Devin API key — check DEVIN_API_KEY",
    403: "Service user lacks required permission — check Devin org settings",
    404: "Resource not found — check DEVIN_ORG_ID",
}


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def _check_response(resp: requests.Response) -> dict:
    """Raise with a clear message on HTTP errors; return parsed JSON on success."""
    try:
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status in _PERMANENT_ERRORS:
            raise RuntimeError(_PERMANENT_ERRORS[status]) from exc
        if status == 429:
            raise requests.HTTPError("Rate limit exceeded — wait and retry", response=exc.response) from exc
        raise


def _extract_structured_output(session: dict) -> dict:
    raw = session.get("structured_output")
    if not raw:
        return {}
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError):
        return {}


_RETRY_DELAYS = [2, 4, 8]
_MAX_CONSECUTIVE_POLL_ERRORS = 3


def create_session(prompt: str, api_key: str, org_id: str) -> str:
    url = _SESSIONS_URL.format(org_id=org_id)
    last_exc: Exception = RuntimeError("unreachable")

    for attempt, delay in enumerate(_RETRY_DELAYS, 1):
        try:
            resp = requests.post(url, headers=_headers(api_key), json={"prompt": prompt}, timeout=30)
            data = _check_response(resp)
            session_id = data.get("session_id")
            if not session_id:
                raise ValueError(f"No session_id in response: {data}")
            return session_id
        except RuntimeError:
            raise  # permanent auth/permission error — no point retrying
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < len(_RETRY_DELAYS):
                logger.warning("create_session attempt %d/%d failed: %s — retrying in %ds",
                               attempt, len(_RETRY_DELAYS), exc, delay)
                time.sleep(delay)
            else:
                logger.error("create_session failed after %d attempts: %s", len(_RETRY_DELAYS), exc)

    raise last_exc


def poll_session(session_id: str, api_key: str, org_id: str, timeout: int = 600,
                 finding_id: str = "") -> dict:
    url = f"{_SESSIONS_URL.format(org_id=org_id)}/{session_id}"
    session_url = _APP_SESSION_URL.format(session_id=session_id)
    deadline = time.time() + timeout
    consecutive_errors = 0
    last_pr_check = 0.0

    while time.time() < deadline:
        # GitHub is ground truth: check for the expected PR branch periodically.
        # This exits early when Devin's API status doesn't transition to a terminal
        # state even though work is complete (observed in practice).
        if finding_id and (time.time() - last_pr_check) >= _PR_CHECK_INTERVAL:
            last_pr_check = time.time()
            from src.escalate import find_pr_for_finding
            pr_url = find_pr_for_finding(finding_id)
            if pr_url:
                elapsed = int(last_pr_check - (deadline - timeout))
                logger.info("Session %s — PR detected on GitHub after %ds, exiting poll early: %s",
                            session_id, elapsed, pr_url)
                return {
                    "status": "complete",
                    "pr_url": pr_url,
                    "session_url": session_url,
                    "structured_output": {},
                }

        try:
            resp = requests.get(url, headers=_headers(api_key), timeout=30)
            data = _check_response(resp)
            consecutive_errors = 0

            status = data.get("status", "")
            elapsed = int(time.time() - (deadline - timeout))
            logger.info("Session %s — status: %s (%ds elapsed)", session_id, status, elapsed)

            if status in _TERMINAL_STATES:
                structured = _extract_structured_output(data)
                pull_requests = data.get("pull_requests")
                if isinstance(pull_requests, list) and pull_requests:
                    pr_url = pull_requests[0].get("url") or ""
                else:
                    pr_url = (data.get("pull_request_url") or data.get("pr_url")
                              or structured.get("pr_url") or "")
                if pr_url and not _PR_URL_RE.match(pr_url):
                    logger.warning("Session %s — pr_url failed validation: %s", session_id, pr_url)
                    pr_url = ""
                outcome = "complete" if status in _SUCCESS_STATES else "failed"
                if outcome == "failed":
                    reason = data.get("error") or data.get("message") or status
                    logger.error("Session %s failed: %s", session_id, reason)
                    logger.debug("Session %s full response: %s", session_id, json.dumps(data))
                return {
                    "status": outcome,
                    "pr_url": pr_url,
                    "session_url": session_url,
                    "structured_output": structured,
                }

        except requests.RequestException as exc:
            consecutive_errors += 1
            logger.warning("Session %s — transient poll error %d/%d: %s",
                           session_id, consecutive_errors, _MAX_CONSECUTIVE_POLL_ERRORS, exc)
            if consecutive_errors >= _MAX_CONSECUTIVE_POLL_ERRORS:
                logger.error("Session %s — %d consecutive poll errors, abandoning",
                             session_id, _MAX_CONSECUTIVE_POLL_ERRORS)
                return {"status": "failed", "pr_url": "", "session_url": session_url,
                        "structured_output": {}}

        time.sleep(_POLL_INTERVAL)

    logger.error("Session %s timed out after %ds", session_id, timeout)
    return {"status": "timeout", "pr_url": "", "session_url": session_url, "structured_output": {}}


def call_devin(finding: dict, dry_run: bool = False) -> dict:
    if dry_run:
        logger.info("DRY RUN — Devin API call skipped")
        fid = finding["finding_id"]
        short = hashlib.md5(fid.encode()).hexdigest()[:6].upper()
        return {
            "status": "complete",
            "pr_url": f"https://github.com/demo/repo/pull/DRY-RUN-{short}",
            "session_url": f"https://app.devin.ai/sessions/dry-run-{fid}",
            "structured_output": {},
        }

    api_key = os.environ.get("DEVIN_API_KEY")
    org_id  = os.environ.get("DEVIN_ORG_ID")
    if not api_key or not org_id:
        raise EnvironmentError("DEVIN_API_KEY and DEVIN_ORG_ID must be set in .env")

    prompt = build_prompt(finding)
    logger.debug("Prompt SHA256: %s  finding: %s",
                 hashlib.sha256(prompt.encode()).hexdigest()[:12], finding["finding_id"])
    logger.info("Creating Devin session for finding: %s", finding["finding_id"])

    session_id = create_session(prompt, api_key, org_id)
    logger.info("Session created: %s", session_id)

    return poll_session(session_id, api_key, org_id, finding_id=finding["finding_id"])
