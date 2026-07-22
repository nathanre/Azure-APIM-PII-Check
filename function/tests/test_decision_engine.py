"""Tests for the deterministic decision engine."""

import pytest

from src.config import FailMode, PiiFamily, Settings
from src.models import (
    Action,
    AtlasFindings,
    Classification,
    ContentSafetyFinding,
    Findings,
    PiiFinding,
    PurviewFindings,
)
from src.policy.decision_engine import DecisionEngine, DecisionInput


def _settings(**overrides) -> Settings:
    base = dict(fail_mode=FailMode.FAIL_CLOSED, content_safety_severity_threshold=4)
    base.update(overrides)
    return Settings(**base)


def _pii(family: str, confidence: float = 0.95, category: str = "cat") -> PiiFinding:
    return PiiFinding(
        category=category, family=family, confidence=confidence, offset=0, length=5
    )


def _evaluate(decision_input: DecisionInput, **settings_overrides):
    return DecisionEngine(_settings(**settings_overrides)).evaluate(decision_input)


def test_block_on_ssn():
    findings = Findings(pii=[_pii(PiiFamily.SSN)])
    decision = _evaluate(DecisionInput(findings=findings))
    assert decision.action == Action.BLOCK
    assert any(rc.startswith("PII_BLOCK_") for rc in decision.reason_codes)


def test_block_on_credit_card():
    findings = Findings(pii=[_pii(PiiFamily.CREDIT_CARD)])
    assert _evaluate(DecisionInput(findings=findings)).action == Action.BLOCK


def test_pii_below_threshold_does_not_block():
    findings = Findings(pii=[_pii(PiiFamily.SSN, confidence=0.10)])
    decision = _evaluate(DecisionInput(findings=findings))
    assert decision.action != Action.BLOCK


def test_redact_on_email_when_requested_and_text_present():
    findings = Findings(pii=[_pii(PiiFamily.EMAIL)])
    decision = _evaluate(
        DecisionInput(
            findings=findings,
            return_redacted_text=True,
            redacted_text="redacted",
        )
    )
    assert decision.action == Action.REDACT
    assert decision.redacted_text == "redacted"


def test_email_without_redaction_request_warns():
    findings = Findings(pii=[_pii(PiiFamily.EMAIL)])
    decision = _evaluate(
        DecisionInput(findings=findings, return_redacted_text=False)
    )
    assert decision.action == Action.WARN
    assert decision.redacted_text is None


def test_block_on_highly_confidential_label():
    decision = _evaluate(
        DecisionInput(
            findings=Findings(),
            classification=Classification.HIGHLY_CONFIDENTIAL,
        )
    )
    assert decision.action == Action.BLOCK
    assert "LABEL_HIGHLY_CONFIDENTIAL" in decision.reason_codes


def test_block_on_regulated_label():
    decision = _evaluate(
        DecisionInput(findings=Findings(), classification=Classification.REGULATED)
    )
    assert decision.action == Action.BLOCK


def test_block_on_content_safety_threshold():
    findings = Findings(
        contentSafety=[ContentSafetyFinding(category="Hate", severity=6)]
    )
    assert _evaluate(DecisionInput(findings=findings)).action == Action.BLOCK


def test_content_safety_below_threshold_does_not_block():
    findings = Findings(
        contentSafety=[ContentSafetyFinding(category="Hate", severity=2)]
    )
    decision = _evaluate(DecisionInput(findings=findings))
    assert decision.action != Action.BLOCK


def test_review_on_purview_financial_classification():
    findings = Findings(
        purview=PurviewFindings(classifications=["FinancialData"])
    )
    decision = _evaluate(
        DecisionInput(findings=findings, classification=Classification.INTERNAL)
    )
    assert decision.action == Action.REVIEW
    assert "PURVIEW_CLASSIFICATION_REVIEW" in decision.reason_codes


def test_review_on_atlas_classification():
    findings = Findings(atlas=AtlasFindings(classifications=["PCI"]))
    decision = _evaluate(DecisionInput(findings=findings))
    assert decision.action == Action.REVIEW


def test_allow_when_no_findings_and_public():
    decision = _evaluate(
        DecisionInput(findings=Findings(), classification=Classification.PUBLIC)
    )
    assert decision.action == Action.ALLOW
    assert "NO_SENSITIVE_FINDINGS" in decision.reason_codes


def test_review_on_incomplete_inspection():
    decision = _evaluate(
        DecisionInput(
            findings=Findings(),
            classification=Classification.INTERNAL,
            inspection_complete=False,
        )
    )
    assert decision.action == Action.REVIEW
    assert "INSPECTION_INCOMPLETE" in decision.reason_codes


def test_file_too_large_fail_closed_blocks():
    decision = _evaluate(
        DecisionInput(findings=Findings(), file_too_large=True),
        fail_mode=FailMode.FAIL_CLOSED,
    )
    assert decision.action == Action.BLOCK
    assert "FILE_TOO_LARGE" in decision.reason_codes


def test_file_too_large_review_mode_reviews():
    decision = _evaluate(
        DecisionInput(findings=Findings(), file_too_large=True),
        fail_mode=FailMode.REVIEW,
    )
    assert decision.action == Action.REVIEW


def test_dependency_failure_fail_closed_blocks():
    decision = _evaluate(
        DecisionInput(findings=Findings(), dependency_failure=True),
        fail_mode=FailMode.FAIL_CLOSED,
    )
    assert decision.action == Action.BLOCK
    assert "INSPECTION_DEPENDENCY_FAILURE" in decision.reason_codes


def test_dependency_failure_fail_open_allows():
    decision = _evaluate(
        DecisionInput(findings=Findings(), dependency_failure=True),
        fail_mode=FailMode.FAIL_OPEN,
    )
    assert decision.action == Action.ALLOW


def test_most_restrictive_action_wins():
    # Email (redact) + SSN (block) -> Block must win.
    findings = Findings(pii=[_pii(PiiFamily.EMAIL), _pii(PiiFamily.SSN)])
    decision = _evaluate(
        DecisionInput(
            findings=findings,
            return_redacted_text=True,
            redacted_text="x",
        )
    )
    assert decision.action == Action.BLOCK


def test_risk_score_is_bounded():
    findings = Findings(
        pii=[_pii(PiiFamily.SSN), _pii(PiiFamily.CREDIT_CARD)],
        contentSafety=[ContentSafetyFinding(category="Hate", severity=7)],
        purview=PurviewFindings(classifications=["FinancialData", "PHI"]),
    )
    decision = _evaluate(
        DecisionInput(
            findings=findings, classification=Classification.REGULATED
        )
    )
    assert 0 <= decision.risk_score <= 100
    assert decision.risk_score == 100
