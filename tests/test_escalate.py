import os
import pytest
import requests
from unittest.mock import patch, MagicMock
from src.escalate import create_failure_issue, create_requires_human_issue, _parse_repo


def _make_finding():
    return {
        "finding_id": "py-sql-injection-payments.py-L20",
        "rule_id": "py/sql-injection",
        "file": "app/routes/payments.py",
        "line": 20,
        "severity": "high",
        "classification": "auto-remediable",
        "priority": 65,
        "reasoning": "test",
    }


def _make_failed_result():
    return {
        "status": "failed",
        "pr_url": "",
        "session_url": "https://app.devin.ai/sessions/abc123",
        "structured_output": {},
    }


# ── _parse_repo ───────────────────────────────────────────────

def test_parse_repo_standard():
    assert _parse_repo("https://github.com/acme/medsecure") == ("acme", "medsecure")


def test_parse_repo_with_git_suffix():
    assert _parse_repo("https://github.com/acme/medsecure.git") == ("acme", "medsecure")


def test_parse_repo_invalid_returns_none():
    assert _parse_repo("not-a-url") is None


# ── create_failure_issue ──────────────────────────────────────

def test_returns_empty_when_no_token(finding):
    with patch.dict(os.environ, {"GITHUB_TOKEN": "", "TARGET_REPO": "https://github.com/a/b"}):
        assert create_failure_issue(finding, _make_failed_result()) == ""


def test_returns_empty_when_no_target_repo(finding):
    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok", "TARGET_REPO": ""}):
        assert create_failure_issue(finding, _make_failed_result()) == ""


def test_returns_empty_on_invalid_target_repo(finding):
    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok", "TARGET_REPO": "not-a-url"}):
        assert create_failure_issue(finding, _make_failed_result()) == ""


def test_creates_issue_and_returns_url(finding):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"html_url": "https://github.com/acme/medsecure/issues/42"}

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.post", return_value=mock_resp) as mock_post:
        result = create_failure_issue(finding, _make_failed_result())

    assert result == "https://github.com/acme/medsecure/issues/42"
    payload = mock_post.call_args.kwargs["json"]
    assert "[Security]" in payload["title"]
    assert "security" in payload["labels"]
    assert "needs-manual-review" in payload["labels"]


def test_returns_empty_on_api_error(finding):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = requests.HTTPError("403")

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.post", return_value=mock_resp):
        result = create_failure_issue(finding, _make_failed_result())

    assert result == ""


def test_issue_body_contains_finding_details(finding):
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"html_url": "https://github.com/acme/medsecure/issues/1"}

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.post", return_value=mock_resp) as mock_post:
        create_failure_issue(finding, _make_failed_result())

    body = mock_post.call_args.kwargs["json"]["body"]
    assert "py/sql-injection"             in body
    assert "app/routes/payments.py"       in body
    assert "https://app.devin.ai"         in body


# ── create_requires_human_issue ──────────────────────────────

def _make_human_finding():
    return {
        "finding_id": "py-path-injection-documents.py-L34",
        "rule_id": "py/path-injection",
        "file": "app/routes/documents.py",
        "line": 34,
        "severity": "high",
        "classification": "requires-human",
        "priority": 55,
        "reasoning": "py/path-injection requires contextual judgement to fix safely.",
    }


def test_requires_human_returns_empty_when_no_token():
    with patch.dict(os.environ, {"GITHUB_TOKEN": "", "TARGET_REPO": "https://github.com/a/b"}):
        assert create_requires_human_issue(_make_human_finding()) == ""


def test_requires_human_returns_empty_when_no_target_repo():
    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok", "TARGET_REPO": ""}):
        assert create_requires_human_issue(_make_human_finding()) == ""


def test_requires_human_creates_issue_and_returns_url():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"html_url": "https://github.com/acme/medsecure/issues/99"}

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.get", return_value=MagicMock(
             raise_for_status=lambda: None, json=lambda: [])), \
         patch("src.escalate.requests.post", return_value=mock_resp) as mock_post:
        result = create_requires_human_issue(_make_human_finding())

    assert result == "https://github.com/acme/medsecure/issues/99"
    payload = mock_post.call_args.kwargs["json"]
    assert "Requires human review" in payload["title"]
    assert "security" in payload["labels"]
    assert "needs-manual-review" in payload["labels"]


def test_requires_human_issue_body_contains_reasoning():
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"html_url": "https://github.com/acme/medsecure/issues/99"}

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.get", return_value=MagicMock(
             raise_for_status=lambda: None, json=lambda: [])), \
         patch("src.escalate.requests.post", return_value=mock_resp) as mock_post:
        create_requires_human_issue(_make_human_finding())

    body = mock_post.call_args.kwargs["json"]["body"]
    assert "py/path-injection"                          in body
    assert "app/routes/documents.py"                   in body
    assert "py/path-injection requires contextual"     in body


def test_requires_human_skips_if_issue_exists():
    existing = [{"title": "[Security] Requires human review — py/path-injection in app/routes/documents.py"}]
    mock_get = MagicMock(raise_for_status=lambda: None, json=lambda: existing)

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.get", return_value=mock_get), \
         patch("src.escalate.requests.post") as mock_post:
        result = create_requires_human_issue(_make_human_finding())

    assert result == ""
    mock_post.assert_not_called()


def test_requires_human_returns_empty_on_api_error():
    mock_post_resp = MagicMock()
    mock_post_resp.raise_for_status.side_effect = requests.HTTPError("422")

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.get", return_value=MagicMock(
             raise_for_status=lambda: None, json=lambda: [])), \
         patch("src.escalate.requests.post", return_value=mock_post_resp):
        result = create_requires_human_issue(_make_human_finding())

    assert result == ""


# ── create_failure_issue ──────────────────────────────────────

def test_timeout_status_included_in_issue(finding):
    timeout_result = {**_make_failed_result(), "status": "timeout"}
    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {"html_url": "https://github.com/acme/medsecure/issues/2"}

    with patch.dict(os.environ, {"GITHUB_TOKEN": "tok",
                                  "TARGET_REPO": "https://github.com/acme/medsecure"}), \
         patch("src.escalate.requests.post", return_value=mock_resp) as mock_post:
        create_failure_issue(finding, timeout_result)

    body = mock_post.call_args.kwargs["json"]["body"]
    assert "timeout" in body
