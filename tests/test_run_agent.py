import os
import pytest
from unittest.mock import patch, MagicMock
from run_agent import _already_remediated


def _make_finding(rule_id="py/sql-injection", classification="auto-remediable"):
    return {
        "finding_id": f"{rule_id}-payments.py-L1",
        "rule_id": rule_id,
        "severity": "high",
        "file": "app/payments.py",
        "line": 1,
        "message": "test",
        "classification": classification,
        "priority": 65,
        "reasoning": "test reasoning",
    }


def _mock_devin_ok():
    return {"status": "complete", "pr_url": "https://github.com/pr/1",
            "session_url": "https://app.devin.ai/sessions/x", "structured_output": {}}


def _mock_devin_fail():
    return {"status": "failed", "pr_url": "",
            "session_url": "https://app.devin.ai/sessions/x", "structured_output": {}}


# ── Deduplication ────────────────────────────────────────────

def test_already_remediated_skips_awaiting_approval():
    assert _already_remediated("fid", {"fid": "awaiting-approval"}) is True


def test_already_remediated_skips_tests_failed():
    assert _already_remediated("fid", {"fid": "tests-failed"}) is True


def test_already_remediated_does_not_skip_failed():
    assert _already_remediated("fid", {"fid": "failed"}) is False


def test_already_remediated_does_not_skip_missing():
    assert _already_remediated("fid", {}) is False


# ── Test 8: SARIF file does not exist ─────────────────────────

def test_exits_on_missing_sarif(monkeypatch):
    from run_agent import main
    monkeypatch.setenv("TARGET_REPO", "https://github.com/org/repo")
    monkeypatch.setattr("sys.argv", ["run_agent.py",
                                     "--sarif", "/nonexistent/path.sarif.json",
                                     "--dry-run"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1


# ── Test 9: All findings require human — nothing sent to Devin ─

def test_all_requires_human_logs_and_completes(monkeypatch, capsys):
    from run_agent import main
    monkeypatch.setenv("TARGET_REPO", "https://github.com/org/repo")
    monkeypatch.setattr("sys.argv", ["run_agent.py", "--dry-run"])

    human_finding = _make_finding(rule_id="py/unknown-rule", classification="requires-human")
    triaged = {"auto_remediable": [], "requires_human": [human_finding], "ignored": []}

    with patch("run_agent.parse_sarif", return_value=[human_finding]), \
         patch("run_agent.triage_findings", return_value=triaged), \
         patch("run_agent._load_state", return_value={}), \
         patch("run_agent._save_state"), \
         patch("run_agent.generate_notification_summary"):
        main()

    captured = capsys.readouterr()
    assert "Remediated          0" in captured.out
    assert "Requires human      1" in captured.out


# ── Test 10: Devin fails on first finding, second still runs ──

def test_second_finding_processes_after_first_fails(monkeypatch):
    from run_agent import main
    monkeypatch.setenv("TARGET_REPO", "https://github.com/org/repo")
    monkeypatch.setattr("sys.argv", ["run_agent.py", "--dry-run"])

    finding_1 = _make_finding(rule_id="py/sql-injection")
    finding_2 = _make_finding(rule_id="py/hardcoded-credentials")
    triaged = {"auto_remediable": [finding_1, finding_2], "requires_human": [], "ignored": []}

    devin_results = [_mock_devin_fail(), _mock_devin_ok()]

    with patch("run_agent.parse_sarif", return_value=[finding_1, finding_2]), \
         patch("run_agent.triage_findings", return_value=triaged), \
         patch("run_agent.call_devin", side_effect=devin_results), \
         patch("run_agent._load_state", return_value={}), \
         patch("run_agent._save_state"), \
         patch("run_agent.generate_audit_artifact", return_value="outputs/audit/test.md"), \
         patch("run_agent.generate_notification_summary"):
        main()
