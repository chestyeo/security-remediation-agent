import os

# Rules where the fix is deterministic and Devin can apply it safely.
# Value is a plain-English description of what the fix looks like.
_AUTO_REMEDIABLE_RULES = {
    "py/sql-injection":                       "parameterised queries replace unsafe string concatenation",
    "js/sql-injection":                       "parameterised queries replace unsafe string concatenation",
    "java/sql-injection":                     "PreparedStatement replaces unsafe string concatenation",
    "rb/sql-injection":                       "parameterised queries replace unsafe string concatenation",
    "py/hardcoded-credentials":               "secrets moved to environment variables",
    "js/hardcoded-credentials":               "secrets moved to environment variables",
    "py/clear-text-storage-of-sensitive-data":"sensitive data encrypted before storage",
    "py/unsafe-deserialization":              "safe deserialisation API replaces unsafe call",
    "py/unsafe-use-of-subprocess":            "shell=True replaced with argument list form",
}

# Paths matching any of these substrings are ignored — test and generated files
# are excluded because fixes there don't reduce real exposure.
_IGNORE_PATH_PATTERNS = [
    "/tests/", "/test/", "test_", "_test.",
    "/spec/", "spec_", "_spec.",
    "/generated/", "/__generated__/",
    "/migrations/",
    "/vendor/",
    ".pb.py",
]

_SEVERITY_WEIGHT = {"critical": 40, "high": 30, "medium": 20, "low": 10}

# Per-rule exploitability bonus (0–40). Reflects how trivially the
# vulnerability can be weaponised if left unfixed.
_RULE_EXPLOITABILITY = {
    "py/sql-injection":        35,
    "js/sql-injection":        35,
    "java/sql-injection":      35,
    "rb/sql-injection":        35,
    "py/unsafe-deserialization": 28,
    "py/unsafe-use-of-subprocess": 26,
    "py/hardcoded-credentials":  22,
    "js/hardcoded-credentials":  22,
    "py/clear-text-storage-of-sensitive-data": 18,
}


def _is_ignored(file: str) -> tuple[bool, str]:
    lower = file.lower()
    for pattern in _IGNORE_PATH_PATTERNS:
        if pattern in lower:
            return True, f"file path matches ignore pattern '{pattern}'"
    return False, ""


def _priority_score(finding: dict) -> int:
    score = _SEVERITY_WEIGHT.get(finding.get("severity", "low"), 10)
    score += _RULE_EXPLOITABILITY.get(finding.get("rule_id", ""), 10)
    if os.environ.get("REPO_CRITICAL", "").lower() in ("1", "true", "yes"):
        score += 20
    return min(score, 100)


def _triage_one(finding: dict) -> dict:
    rule_id = finding.get("rule_id", "")
    file = finding.get("file", "")
    severity = finding.get("severity", "low")

    ignored, reason = _is_ignored(file)
    if ignored:
        return {"classification": "ignore", "priority": 0, "reasoning": f"Skipped: {reason}."}

    score = _priority_score(finding)

    fix_description = _AUTO_REMEDIABLE_RULES.get(rule_id)
    if fix_description:
        return {
            "classification": "auto-remediable",
            "priority": score,
            "reasoning": (
                f"{rule_id} has a deterministic fix: {fix_description}. "
                f"Severity is {severity} (priority {score}/100). "
                f"Devin can apply a minimal targeted patch without architectural changes."
            ),
        }

    return {
        "classification": "requires-human",
        "priority": score,
        "reasoning": (
            f"{rule_id} requires contextual judgement to fix safely. "
            f"Automated remediation risks incorrect behaviour changes."
        ),
    }


def triage_findings(findings: list[dict]) -> dict:
    auto_remediable, requires_human, ignored = [], [], []

    for finding in findings:
        result = _triage_one(finding)
        annotated = {**finding, **result}
        if result["classification"] == "auto-remediable":
            auto_remediable.append(annotated)
        elif result["classification"] == "requires-human":
            requires_human.append(annotated)
        else:
            ignored.append(annotated)

    return {
        "auto_remediable": auto_remediable,
        "requires_human": requires_human,
        "ignored": ignored,
    }
