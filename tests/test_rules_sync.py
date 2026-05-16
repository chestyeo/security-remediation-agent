from src.triage import _AUTO_REMEDIABLE_RULES
from prompts.devin_task_template import _RULE_GUIDANCE
from src.audit import _COMPLIANCE_MAP


def test_all_auto_remediable_rules_have_prompt_guidance():
    missing = [r for r in _AUTO_REMEDIABLE_RULES if r not in _RULE_GUIDANCE]
    assert missing == [], f"Rules missing from _RULE_GUIDANCE: {missing}"


def test_all_auto_remediable_rules_have_compliance_mapping():
    missing = [r for r in _AUTO_REMEDIABLE_RULES if r not in _COMPLIANCE_MAP]
    assert missing == [], f"Rules missing from _COMPLIANCE_MAP: {missing}"
