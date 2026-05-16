import json
import pytest
from src.parser import parse_sarif


def test_parse_returns_findings(triaged):
    total = sum(len(v) for v in triaged.values())
    assert total >= 1


def test_finding_fields(finding):
    f = finding
    assert f["rule_id"]    == "py/sql-injection"
    assert f["severity"]   == "high"
    assert f["file"]       == "app/routes/payments.py"
    assert f["line"]       == 20
    assert f["message"]
    assert f["finding_id"] == "py-sql-injection-payments.py-L20"


# ── Unhappy paths ─────────────────────────────────────────────

def test_missing_runs_raises(tmp_path):
    f = tmp_path / "bad.sarif.json"
    f.write_text(json.dumps({"version": "2.1.0"}))
    with pytest.raises(ValueError, match="missing or empty runs"):
        parse_sarif(str(f))


def test_empty_runs_raises(tmp_path):
    f = tmp_path / "bad.sarif.json"
    f.write_text(json.dumps({"version": "2.1.0", "runs": []}))
    with pytest.raises(ValueError, match="missing or empty runs"):
        parse_sarif(str(f))


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_sarif(str(tmp_path / "nonexistent.sarif.json"))


def test_missing_location_fields_handled_gracefully(tmp_path):
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}},
                  "results": [{"ruleId": "py/sql-injection", "level": "error",
                               "message": {"text": "test"}}]}],
    }
    f = tmp_path / "minimal.sarif.json"
    f.write_text(json.dumps(sarif))
    findings = parse_sarif(str(f))
    assert len(findings) == 1
    assert findings[0]["file"] == ""
    assert findings[0]["line"] == 0


def test_empty_results_returns_empty_list(tmp_path):
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}}, "results": []}],
    }
    f = tmp_path / "empty.sarif.json"
    f.write_text(json.dumps(sarif))
    assert parse_sarif(str(f)) == []
