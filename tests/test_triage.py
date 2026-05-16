from src.parser import parse_sarif
from src.triage import triage_findings

def _make_finding(**kwargs):
    base = {"finding_id": "test-id", "severity": "high", "rule_id": "py/sql-injection",
            "file": "app/foo.py", "line": 1, "message": "test"}
    base.update(kwargs)
    return base


def test_triage_buckets(triaged):
    # demo.sarif.json: 3 auto-remediable, 1 requires-human (py/path-injection), 0 ignored
    assert len(triaged["auto_remediable"]) == 3
    assert len(triaged["requires_human"])  == 1
    assert len(triaged["ignored"])         == 0


def test_classification(finding):
    assert finding["classification"] == "auto-remediable"


def test_priority_score(finding):
    # high(30) + py/sql-injection exploitability(35) + no REPO_CRITICAL = 65
    assert finding["priority"] == 65


def test_reasoning_names_rule_and_fix(finding):
    assert "py/sql-injection" in finding["reasoning"]
    assert "parameterised"    in finding["reasoning"]


def test_parser_fields_preserved(finding):
    assert finding["file"]     == "app/routes/payments.py"
    assert finding["line"]     == 20
    assert finding["severity"] == "high"


# ── Unhappy paths ─────────────────────────────────────────────

def test_unknown_rule_id_goes_to_requires_human():
    result = triage_findings([_make_finding(rule_id="py/some-unknown-rule")])
    assert len(result["requires_human"]) == 1
    assert len(result["auto_remediable"]) == 0


def test_empty_rule_id_goes_to_requires_human():
    result = triage_findings([_make_finding(rule_id="")])
    assert len(result["requires_human"]) == 1


def test_unknown_severity_does_not_crash():
    result = triage_findings([_make_finding(rule_id="py/sql-injection", severity="unknown")])
    f = result["auto_remediable"][0]
    assert f["priority"] >= 0


def test_test_file_path_is_ignored():
    result = triage_findings([_make_finding(file="tests/test_payments.py")])
    assert len(result["ignored"]) == 1
    assert len(result["auto_remediable"]) == 0


def test_empty_findings_list():
    result = triage_findings([])
    assert result == {"auto_remediable": [], "requires_human": [], "ignored": []}
