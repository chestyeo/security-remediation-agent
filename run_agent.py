import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from src.parser import parse_sarif
from src.triage import triage_findings
from src.devin_client import call_devin
from src.audit import generate_audit_artifact
from src.escalate import create_failure_issue, find_pr_for_finding, create_requires_human_issue
from src.notify import generate_notification_summary

load_dotenv()

_log_level = getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
logging.Formatter.converter = time.gmtime
logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_env(dry_run: bool) -> None:
    required = {"TARGET_REPO": os.environ.get("TARGET_REPO")}
    if not dry_run:
        required["DEVIN_API_KEY"] = os.environ.get("DEVIN_API_KEY")
        required["DEVIN_ORG_ID"]  = os.environ.get("DEVIN_ORG_ID")
        required["GITHUB_TOKEN"]  = os.environ.get("GITHUB_TOKEN")

    missing = [k for k, v in required.items() if not v]
    if missing:
        logger.error("Missing required environment variable(s): %s", ", ".join(missing))
        logger.error("Copy .env.example to .env and fill in the missing values.")
        sys.exit(1)


def _separator(label: str = "") -> None:
    width = 64
    if label:
        pad = (width - len(label) - 2) // 2
        print(f"\n{'─' * pad} {label} {'─' * pad}")
    else:
        print("─" * width)


_STATE_FILE = Path("outputs/state.json")


def _load_state() -> dict:
    if _STATE_FILE.exists():
        try:
            return json.loads(_STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_state(state: dict) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(json.dumps(state, indent=2))


def _already_remediated(finding_id: str, state: dict) -> bool:
    return state.get(finding_id) in ("awaiting-approval", "tests-failed")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Security remediation agent — ingests CodeQL SARIF and tasks Devin to fix findings."
    )
    parser.add_argument(
        "--sarif",
        default=None,
        help="Path to CodeQL SARIF file (default in dry-run: fixtures/demo.sarif.json, else $SARIF_PATH)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Skip Devin API calls and use mock results")
    args = parser.parse_args()

    if args.sarif is None:
        if args.dry_run:
            args.sarif = "fixtures/demo.sarif.json"
        else:
            args.sarif = os.getenv("SARIF_PATH", "../medsecure/findings/codeql.sarif.json")

    if args.dry_run:
        logger.info("DRY RUN — Devin API calls will be skipped")

    validate_env(args.dry_run)

    # ── Step 1: Parse ─────────────────────────────────────────────
    _separator("PARSE")
    logger.info("Ingesting SARIF: %s", args.sarif)
    try:
        findings = parse_sarif(args.sarif)
    except Exception as exc:
        logger.error("Failed to parse SARIF: %s", exc)
        sys.exit(1)

    ingested_at = _now()
    logger.info("Parsed %d finding(s)", len(findings))

    # ── Step 2: Triage ────────────────────────────────────────────
    _separator("TRIAGE")
    try:
        triaged = triage_findings(findings)
    except Exception as exc:
        logger.error("Failed to triage findings: %s", exc)
        sys.exit(1)

    triaged_at = _now()
    auto    = sorted(triaged["auto_remediable"], key=lambda f: f["priority"], reverse=True)
    human   = triaged["requires_human"]
    ignored = triaged["ignored"]

    logger.info(
        "Triage complete — auto-remediable: %d  requires-human: %d  ignored: %d",
        len(auto), len(human), len(ignored),
    )
    for f in human:
        logger.info("  [requires-human] %s  %s  %s", f["severity"].upper(), f["rule_id"], f["file"])
        if not args.dry_run:
            issue_url = create_requires_human_issue(f)
            if issue_url:
                logger.info("  [requires-human] Issue opened: %s", issue_url)
    for f in ignored:
        logger.info("  [ignored]        %s", f["file"])

    if not auto:
        logger.info("No auto-remediable findings — nothing to send to Devin")

    # ── Step 3: Remediate ─────────────────────────────────────────
    results: list[dict] = []
    remediated    = 0
    failed        = 0
    tests_failed  = 0
    state         = _load_state()

    for i, finding in enumerate(auto, 1):
        fid = finding["finding_id"]
        _separator(fid)

        logger.info("[%s] Finding %d/%d — %s  %s  line %s",
                    fid, i, len(auto), finding["severity"].upper(), finding["rule_id"], finding["line"])
        logger.info("[%s] Classification: %s  priority %s/100", fid, finding["classification"], finding["priority"])

        if _already_remediated(fid, state):
            logger.info("[%s] Already remediated — skipping (remove from outputs/state.json to re-run)", fid)
            remediated += 1
            continue

        session_started_at = _now()
        logger.info("[%s] Sending to Devin (%s)", fid, session_started_at)

        try:
            devin_result = call_devin(finding, dry_run=args.dry_run)
        except Exception as exc:
            logger.error("[%s] call_devin raised exception: %s", fid, exc)
            devin_result = {"status": "failed", "pr_url": "", "session_url": "", "structured_output": {}}

        completed_at = _now()
        status = devin_result["status"]
        structured = devin_result.get("structured_output", {})

        tests_passed = structured.get("tests_passed")
        if status == "complete" and tests_passed is False:
            logger.warning("[%s] Devin completed but tests FAILED — flagging for review", fid)
            devin_result["status"] = "complete-tests-failed"
            status = "complete-tests-failed"
        elif status == "complete" and tests_passed is None:
            logger.warning("[%s] Devin completed but structured output missing — PR requires manual test verification", fid)

        if status == "complete":
            logger.info("[%s] Complete — PR: %s", fid, devin_result["pr_url"])
            state[fid] = "awaiting-approval"
            remediated += 1
        elif status == "complete-tests-failed":
            logger.warning("[%s] Complete but tests FAILED — PR: %s", fid, devin_result["pr_url"])
            state[fid] = "tests-failed"
            tests_failed += 1
        elif status == "failed":
            logger.error("[%s] Devin session failed — session: %s", fid, devin_result["session_url"])
            state[fid] = "failed"
            failed += 1
            issue_url = create_failure_issue(finding, devin_result)
            if issue_url:
                logger.info("[%s] Escalation issue: %s", fid, issue_url)
        elif status == "timeout":
            logger.warning("[%s] Devin polling window closed (600s) — session: %s", fid, devin_result["session_url"])
            pr_url = find_pr_for_finding(fid)
            if pr_url:
                logger.info("[%s] PR found after timeout: %s — counting as complete", fid, pr_url)
                devin_result["pr_url"] = pr_url
                devin_result["status"] = "complete"
                status = "complete"
                state[fid] = "awaiting-approval"
                remediated += 1
            else:
                state[fid] = "timeout"
                failed += 1

        _save_state(state)

        timestamps = {
            "ingested_at":        ingested_at,
            "triaged_at":         triaged_at,
            "session_started_at": session_started_at,
            "completed_at":       completed_at,
        }
        try:
            audit_path = generate_audit_artifact(finding, devin_result, timestamps)
            logger.info("[%s] Audit artifact: %s", fid, audit_path)
        except Exception as exc:
            logger.error("[%s] Failed to write audit artifact: %s", fid, exc)
            audit_path = ""

        results.append({"finding": finding, "devin": devin_result, "audit_path": audit_path})

    # ── Step 4: Notify ────────────────────────────────────────────
    _separator("NOTIFY")
    summary_path = generate_notification_summary(triaged, results)
    logger.info("Notification summary: %s", summary_path)

    # ── Final summary ─────────────────────────────────────────────
    _separator()
    print(f"  Remediated          {remediated}")
    print(f"  Tests failed (PR open)  {tests_failed}")
    print(f"  Failed (no PR)      {failed}")
    print(f"  Requires human      {len(human)}")
    print(f"  Ignored             {len(ignored)}")
    _separator()
    print()


if __name__ == "__main__":
    main()
