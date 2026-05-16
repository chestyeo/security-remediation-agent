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

# States where Devin will not progress further without external action.
_TERMINAL_STATES = {"complete", "completed", "finished", "failed", "error", "stopped", "blocked"}
_SUCCESS_STATES   = {"complete", "completed", "finished"}


def _headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


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
            resp.raise_for_status()
            data = resp.json()
            session_id = data.get("session_id")
            if not session_id:
                raise ValueError(f"No session_id in response: {data}")
            return session_id
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            if attempt < len(_RETRY_DELAYS):
                logger.warning("create_session attempt %d/%d failed: %s — retrying in %ds",
                               attempt, len(_RETRY_DELAYS), exc, delay)
                time.sleep(delay)
            else:
                logger.error("create_session failed after %d attempts: %s", len(_RETRY_DELAYS), exc)

    raise last_exc


def poll_session(session_id: str, api_key: str, org_id: str, timeout: int = 900) -> dict:
    url = f"{_SESSIONS_URL.format(org_id=org_id)}/{session_id}"
    session_url = _APP_SESSION_URL.format(session_id=session_id)
    deadline = time.time() + timeout
    consecutive_errors = 0

    while time.time() < deadline:
        try:
            resp = requests.get(url, headers=_headers(api_key), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            consecutive_errors = 0

            status = data.get("status", "")
            elapsed = int(time.time() - (deadline - timeout))
            logger.info("Session %s — status: %s (%ds elapsed)", session_id, status, elapsed)

            if status in _TERMINAL_STATES:
                pull_requests = data.get("pull_requests")
                if isinstance(pull_requests, list) and pull_requests:
                    pr_url = pull_requests[0].get("url") or ""
                else:
                    pr_url = data.get("pull_request_url") or data.get("pr_url") or ""
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
                    "structured_output": _extract_structured_output(data),
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

    return poll_session(session_id, api_key, org_id)
