import os
import pytest
import requests
from unittest.mock import MagicMock, patch, call
from src.devin_client import call_devin, create_session, poll_session


def test_dry_run_returns_complete_status(finding):
    result = call_devin(finding, dry_run=True)
    assert result["status"] == "complete"


def test_dry_run_returns_valid_urls(finding):
    result = call_devin(finding, dry_run=True)
    assert result["pr_url"].startswith("https")
    assert "devin.ai" in result["session_url"]


def test_missing_env_vars_raise(finding):
    with patch.dict(os.environ, {"DEVIN_API_KEY": "", "DEVIN_ORG_ID": ""}):
        with pytest.raises(EnvironmentError):
            call_devin(finding, dry_run=False)


# ── create_session retry tests ────────────────────────────────

def test_create_session_retries_on_transient_failure():
    ok_resp = MagicMock()
    ok_resp.raise_for_status.return_value = None
    ok_resp.json.return_value = {"session_id": "sess-abc"}

    fail_resp = MagicMock()
    fail_resp.raise_for_status.side_effect = requests.HTTPError("503")

    with patch("src.devin_client.requests.post", side_effect=[fail_resp, fail_resp, ok_resp]) as mock_post, \
         patch("src.devin_client.time.sleep"):
        result = create_session("prompt", "key", "org")

    assert result == "sess-abc"
    assert mock_post.call_count == 3


def test_create_session_raises_after_all_retries_exhausted():
    fail_resp = MagicMock()
    fail_resp.raise_for_status.side_effect = requests.HTTPError("503")

    with patch("src.devin_client.requests.post", return_value=fail_resp), \
         patch("src.devin_client.time.sleep"):
        with pytest.raises(requests.HTTPError):
            create_session("prompt", "key", "org")


# ── poll_session resilience tests ─────────────────────────────

def test_poll_session_recovers_from_transient_errors():
    error = requests.ConnectionError("blip")
    ok_resp = MagicMock()
    ok_resp.raise_for_status.return_value = None
    ok_resp.json.return_value = {"status": "complete", "pull_request_url": "https://github.com/pr/1"}

    with patch("src.devin_client.requests.get", side_effect=[error, error, ok_resp]), \
         patch("src.devin_client.time.sleep"), \
         patch("src.devin_client.time.time", side_effect=[0, 1, 2, 3, 4]):
        result = poll_session("sess-1", "key", "org", timeout=600)

    assert result["status"] == "complete"


def test_poll_session_fails_after_max_consecutive_errors():
    error = requests.ConnectionError("blip")

    with patch("src.devin_client.requests.get", side_effect=error), \
         patch("src.devin_client.time.sleep"), \
         patch("src.devin_client.time.time", side_effect=[0, 1, 2, 3, 4]):
        result = poll_session("sess-1", "key", "org", timeout=600)

    assert result["status"] == "failed"


def test_poll_session_blocked_returns_failed():
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"status": "blocked"}

    with patch("src.devin_client.requests.get", return_value=resp), \
         patch("src.devin_client.time.sleep"), \
         patch("src.devin_client.time.time", side_effect=[0, 1, 2]):
        result = poll_session("sess-1", "key", "org", timeout=600)

    assert result["status"] == "failed"


@pytest.mark.parametrize("status_code", [401, 403, 429, 500])
def test_create_session_raises_on_http_errors(status_code):
    resp = MagicMock()
    resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code}")

    with patch("src.devin_client.requests.post", return_value=resp), \
         patch("src.devin_client.time.sleep"):
        with pytest.raises(requests.HTTPError):
            create_session("prompt", "key", "org")


def test_poll_result_includes_structured_output():
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "status": "complete",
        "pull_request_url": "https://github.com/pr/1",
        "structured_output": '{"fix_applied": true, "tests_passed": true}',
    }

    with patch("src.devin_client.requests.get", return_value=resp), \
         patch("src.devin_client.time.sleep"), \
         patch("src.devin_client.time.time", side_effect=[0, 1, 2]):
        result = poll_session("sess-1", "key", "org", timeout=600)

    assert result["structured_output"]["fix_applied"] is True


def test_poll_result_uses_pull_requests_array():
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {
        "status": "complete",
        "pull_requests": [{"url": "https://github.com/acme/medsecure/pull/99"}],
    }

    with patch("src.devin_client.requests.get", return_value=resp), \
         patch("src.devin_client.time.sleep"), \
         patch("src.devin_client.time.time", side_effect=[0, 1, 2]):
        result = poll_session("sess-1", "key", "org", timeout=600)

    assert result["pr_url"] == "https://github.com/acme/medsecure/pull/99"


# ── validate_env tests ────────────────────────────────────────

def test_validate_env_exits_on_missing_vars():
    from run_agent import validate_env
    with patch.dict(os.environ, {"TARGET_REPO": "", "DEVIN_API_KEY": "", "DEVIN_ORG_ID": "", "GITHUB_TOKEN": ""}, clear=False):
        with pytest.raises(SystemExit) as exc:
            validate_env(dry_run=False)
    assert exc.value.code == 1


def test_validate_env_exits_on_missing_github_token():
    from run_agent import validate_env
    with patch.dict(os.environ, {"TARGET_REPO": "https://github.com/org/repo",
                                  "DEVIN_API_KEY": "key", "DEVIN_ORG_ID": "org",
                                  "GITHUB_TOKEN": ""}, clear=False):
        with pytest.raises(SystemExit) as exc:
            validate_env(dry_run=False)
    assert exc.value.code == 1


def test_validate_env_passes_in_dry_run_without_devin_creds():
    from run_agent import validate_env
    with patch.dict(os.environ, {"TARGET_REPO": "https://github.com/org/repo",
                                  "DEVIN_API_KEY": "", "DEVIN_ORG_ID": "", "GITHUB_TOKEN": ""}, clear=False):
        validate_env(dry_run=True)  # should not raise
