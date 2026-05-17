from dotenv import load_dotenv
from prompts.devin_task_template import build_prompt

load_dotenv()


def test_prompt_contains_finding_metadata(finding):
    prompt = build_prompt(finding)
    assert "py/sql-injection"      in prompt
    assert "app/routes/payments.py" in prompt
    assert "20"                    in prompt
    assert "high"                  in prompt


def test_prompt_contains_fix_guidance(finding):
    prompt = build_prompt(finding)
    assert "parameterised"         in prompt
    assert "Do NOT"                in prompt


def test_prompt_contains_pr_title(finding):
    prompt = build_prompt(finding)
    assert "[Security] Fix SQL injection in payments.py" in prompt


def test_prompt_contains_audit_metadata(finding):
    prompt = build_prompt(finding)
    assert "finding_id"            in prompt
    assert "py-sql-injection"      in prompt
    assert "timestamp"             in prompt


def test_prompt_contains_triage_and_compliance(finding):
    prompt = build_prompt(finding)
    assert "Triage Decision"       in prompt
    assert "Compliance Mapping"    in prompt
    assert "Remediation Timeline"  in prompt
    assert "auto-remediable"       in prompt
    assert "CWE-089"               in prompt


def test_prompt_uses_supplied_timestamps(finding):
    ts = {
        "ingested_at":        "2026-05-17T10:00:00Z",
        "triaged_at":         "2026-05-17T10:00:01Z",
        "session_started_at": "2026-05-17T10:08:43Z",
    }
    prompt = build_prompt(finding, timestamps=ts)
    assert "2026-05-17T10:00:00Z"  in prompt
    assert "2026-05-17T10:00:01Z"  in prompt
    assert "2026-05-17T10:08:43Z"  in prompt
