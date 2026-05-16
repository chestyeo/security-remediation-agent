import os
import pytest
from src.parser import parse_sarif
from src.triage import triage_findings

_SARIF_PATH = os.getenv("SARIF_PATH", "fixtures/demo.sarif.json")


@pytest.fixture(scope="session")
def triaged():
    findings = parse_sarif(_SARIF_PATH)
    return triage_findings(findings)


@pytest.fixture(scope="session")
def finding(triaged):
    return triaged["auto_remediable"][0]
