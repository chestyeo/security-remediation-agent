import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# CVSS thresholds per SARIF spec property "security-severity"
_CVSS_BANDS = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]

_LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "low",
}


def _severity(rule: dict, result_level: str) -> str:
    cvss = rule.get("properties", {}).get("security-severity")
    if cvss is not None:
        score = float(cvss)
        for threshold, label in _CVSS_BANDS:
            if score >= threshold:
                return label
    return _LEVEL_MAP.get(result_level, "low")


def _finding_id(rule_id: str, file: str, line: int) -> str:
    stem = Path(file).name if file else "unknown"
    safe_rule = rule_id.replace("/", "-")
    return f"{safe_rule}-{stem}-L{line}"


def parse_sarif(sarif_path: str) -> list[dict]:
    with open(sarif_path) as f:
        data = json.load(f)

    if "runs" not in data or not data["runs"]:
        raise ValueError("Invalid SARIF: missing or empty runs array")

    findings = []
    for run in data.get("runs", []):
        rules = {
            rule["id"]: rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for idx, result in enumerate(run.get("results", [])):
            rule_id = result.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            level = result.get("level", "warning")

            if not result.get("ruleId"):
                logger.warning("Result at index %d is missing ruleId — using 'unknown'", idx)

            phys = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            file = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            message = result.get("message", {}).get("text", "")

            if not file:
                logger.warning("Result %s at index %d is missing file location", rule_id, idx)
            if not result.get("locations"):
                logger.warning("Result %s at index %d has no locations array", rule_id, idx)

            findings.append({
                "finding_id": _finding_id(rule_id, file, line),
                "severity": _severity(rule, level),
                "rule_id": rule_id,
                "file": file,
                "line": line,
                "message": message,
            })

    return findings
