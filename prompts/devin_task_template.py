import os
from datetime import datetime, timezone
from pathlib import Path

# Rule-specific vulnerability descriptions and fix guidance.
# Falls back to _DEFAULT_GUIDANCE for any rule not listed here.
_RULE_GUIDANCE = {
    "py/sql-injection": {
        "title": "SQL injection",
        "description": (
            "The vulnerable code builds a SQL query using string concatenation with "
            "user-controlled input. An attacker can manipulate the query to extract, "
            "modify, or delete arbitrary data from the database."
        ),
        "fix": (
            "Replace all string-concatenated SQL queries with parameterised queries. "
            "Pass user input exclusively as bound parameters — never interpolate it "
            "into the query string."
        ),
    },
    "js/sql-injection": {
        "title": "SQL injection",
        "description": (
            "The vulnerable code builds a SQL query by concatenating user-controlled "
            "input. An attacker can inject arbitrary SQL to read or modify database contents."
        ),
        "fix": (
            "Use parameterised queries or prepared statements. "
            "Never interpolate user input into SQL strings."
        ),
    },
    "java/sql-injection": {
        "title": "SQL injection",
        "description": (
            "The vulnerable code builds a SQL query by concatenating user-controlled "
            "input. An attacker can inject arbitrary SQL to read or modify database contents."
        ),
        "fix": (
            "Replace string-concatenated queries with PreparedStatement and bound parameters. "
            "Never interpolate user input into SQL strings."
        ),
    },
    "rb/sql-injection": {
        "title": "SQL injection",
        "description": (
            "The vulnerable code builds a SQL query by concatenating user-controlled "
            "input. An attacker can inject arbitrary SQL to read or modify database contents."
        ),
        "fix": (
            "Use parameterised queries or ActiveRecord's built-in sanitisation. "
            "Never interpolate user input into SQL strings."
        ),
    },
    "py/hardcoded-credentials": {
        "title": "hardcoded credentials",
        "description": (
            "API keys, passwords, or tokens are stored directly in source code. "
            "Anyone with repository access — or who finds the code in a leak — "
            "can use these credentials immediately."
        ),
        "fix": (
            "Remove the hardcoded value. Read the secret from an environment variable "
            "or a secrets manager at runtime. Add the variable name to .env.example."
        ),
    },
    "js/hardcoded-credentials": {
        "title": "hardcoded credentials",
        "description": (
            "A secret is embedded directly in source code and will be exposed to "
            "anyone who can read the file."
        ),
        "fix": (
            "Remove the hardcoded value and replace it with an environment variable read. "
            "Document the variable name in .env.example."
        ),
    },
    "py/clear-text-storage-of-sensitive-data": {
        "title": "clear-text storage of sensitive data",
        "description": (
            "Sensitive data is written to storage without encryption, exposing it to "
            "anyone with file or database access."
        ),
        "fix": (
            "Encrypt sensitive fields before writing. "
            "Use an established encryption library; do not implement your own."
        ),
    },
    "py/unsafe-deserialization": {
        "title": "unsafe deserialisation",
        "description": (
            "Deserialising untrusted data with an unsafe library (e.g. pickle) can "
            "lead to arbitrary code execution."
        ),
        "fix": (
            "Replace the unsafe deserialiser with a safe alternative such as "
            "json.loads or a schema-validated parser."
        ),
    },
    "py/unsafe-use-of-subprocess": {
        "title": "unsafe subprocess invocation",
        "description": (
            "A subprocess is launched with shell=True and user-controlled input, "
            "enabling shell command injection."
        ),
        "fix": (
            "Replace shell=True with an argument list. "
            "Never pass user input to a shell=True subprocess call."
        ),
    },
}

_DEFAULT_GUIDANCE = {
    "title": "security vulnerability",
    "description": "A security vulnerability was detected by CodeQL static analysis.",
    "fix": (
        "Investigate the flagged line and apply the minimal safe fix described "
        "in the CodeQL rule documentation."
    ),
}


def build_prompt(finding: dict) -> str:
    rule_id = finding["rule_id"]
    file = finding["file"]
    filename = Path(file).name
    line = finding["line"]
    severity = finding["severity"]
    finding_id = finding["finding_id"]
    message = " ".join(finding.get("message", "").split())[:200]
    target_repo = os.environ.get("TARGET_REPO", "https://github.com/your-org/medsecure-vulnerable-app")

    guidance = _RULE_GUIDANCE.get(rule_id, _DEFAULT_GUIDANCE)
    pr_title = f"[Security] Fix {guidance['title']} in {filename}"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"""\
You are investigating a {guidance['title']} vulnerability.

Repository: {target_repo}
Branch: Create a new branch named: security/fix-{finding_id}
File: {file}
Line: {line}
Rule: {rule_id}
Severity: {severity}

## Vulnerability

{guidance['description']}

CodeQL finding: {message}

## Required Fix

{guidance['fix']}

## Constraints

Do NOT:
- Refactor anything beyond the vulnerable line(s)
- Rename variables or functions
- Modify any other files
- Change formatting or whitespace outside the fix
- Add comments explaining what you changed

## Validation

After applying the fix:
1. Run: pytest tests/
2. Confirm all tests pass before opening the PR
3. If tests fail, investigate and fix the root cause — do not skip or delete tests

## Pull Request

Open a PR titled exactly: {pr_title}

PR body must include:

### Vulnerability
[Describe what was vulnerable and why it is a security risk]

### Fix
[Describe exactly what was changed and why the fix is correct]

### Validation
[Paste the test output confirming all tests pass]

## Investigation First
Before writing any fix:
1. Read the vulnerable file in full
2. Understand the surrounding code context
3. Check CODEOWNERS to identify the owning team
4. Only then generate the minimal fix

Do not generate a fix without reading the file first.

### Audit Metadata
- finding_id: {finding_id}
- rule_id: {rule_id}
- severity: {severity}
- file: {file}
- line: {line}
- timestamp: {timestamp}

## Completion Report

When your work is complete, output a JSON summary as your final message in this exact format and nothing else after it:

{{
  "fix_applied": true,
  "files_modified": ["{file}"],
  "tests_passed": true,
  "test_output": "<paste pytest output here>",
  "pr_url": "<PR URL>",
  "notes": "<any edge cases or reviewer warnings, or empty string>"
}}
"""
