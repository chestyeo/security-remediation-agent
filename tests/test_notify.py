from src.devin_client import call_devin
from src.audit import generate_audit_artifact
from src.notify import generate_notification_summary


def test_summary_counts(triaged, finding):
    devin_result = call_devin(finding, dry_run=True)
    audit_path   = generate_audit_artifact(finding, devin_result)
    results      = [{"finding": finding, "devin": devin_result, "audit_path": audit_path}]

    path    = generate_notification_summary(triaged, results)
    content = open(path).read()

    total = len(triaged["auto_remediable"]) + len(triaged["requires_human"]) + len(triaged["ignored"])
    assert f"| Findings ingested | {total} |"                             in content
    assert "| Auto-remediated | 1 |"                                      in content
    assert f"| Requires human review | {len(triaged['requires_human'])} |" in content


def test_summary_pr_and_artifacts(triaged, finding):
    devin_result = call_devin(finding, dry_run=True)
    audit_path   = generate_audit_artifact(finding, devin_result)
    results      = [{"finding": finding, "devin": devin_result, "audit_path": audit_path}]

    path    = generate_notification_summary(triaged, results)
    content = open(path).read()

    assert devin_result["pr_url"]    in content
    assert "SQL injection"           in content
    assert "payments.py"             in content
    assert "outputs/audit/"          in content
    assert "Review and approve PRs"  in content
