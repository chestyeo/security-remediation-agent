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
