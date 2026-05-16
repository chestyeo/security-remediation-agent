import pytest
from pathlib import Path
from src.devin_client import call_devin
from src.audit import generate_audit_artifact

_TIMESTAMPS = {
    "ingested_at":        "2026-05-16T11:00:00Z",
    "triaged_at":         "2026-05-16T11:00:01Z",
    "session_started_at": "2026-05-16T11:00:03Z",
    "completed_at":       "2026-05-16T11:08:47Z",
}


def test_complete_audit_content(finding):
    result = call_devin(finding, dry_run=True)
    path = generate_audit_artifact(finding, result, _TIMESTAMPS)
    content = open(path).read()
    assert "auto-remediable"            in content
    assert "65/100"                     in content
    assert "parameterised"              in content
    assert result["pr_url"]             in content
    assert "Human approval required"    in content
    assert "Awaiting engineer approval" in content


def test_failed_audit_does_not_fabricate_pr_url(finding):
    result = {"status": "failed", "pr_url": "", "session_url": "https://app.devin.ai/sessions/abc123"}
    path = generate_audit_artifact(finding, result)
    content = open(path).read()
    assert "failed before PR was opened" in content
    assert "https://github.com/mock"    not in content


# ── Unhappy paths ─────────────────────────────────────────────

def test_complete_with_no_pr_url_records_unknown(finding):
    result = {"status": "complete", "pr_url": "", "session_url": "https://app.devin.ai/sessions/abc"}
    path = generate_audit_artifact(finding, result)
    content = open(path).read()
    assert "awaiting-approval" not in content


def test_creates_output_directory_if_missing(finding, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    result = {"status": "complete", "pr_url": "https://github.com/pr/1",
              "session_url": "https://app.devin.ai/sessions/x"}
    path = generate_audit_artifact(finding, result)
    assert Path(path).exists()
