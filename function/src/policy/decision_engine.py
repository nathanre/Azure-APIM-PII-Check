"""Deterministic policy / decision engine.

Evaluates the aggregated inspection signals (PII, content safety, sensitivity
label, Purview Data Map, Atlas, source/user/model context, and inspection
completeness) and returns a single normalized decision:

    Allow, Warn, Redact, Block, or Review

The engine is deterministic and side-effect free so decisions are reproducible
and auditable. All thresholds come from :class:`Settings`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..config import FailMode, PiiFamily, Settings
from ..models import (
    Action,
    AtlasFindings,
    Classification,
    ContentSafetyFinding,
    Findings,
    PiiFinding,
    PurviewFindings,
)
from .risk_scoring import compute_risk_score

# PII families that force a Block when detected above threshold.
BLOCKING_PII_FAMILIES = {
    PiiFamily.SSN,
    PiiFamily.CREDIT_CARD,
    PiiFamily.BANK_ACCOUNT,
    PiiFamily.PASSPORT,
    PiiFamily.TAX_ID,
    PiiFamily.DRIVER_LICENSE,
}

# PII families that trigger redaction (when redacted text is requested).
REDACTABLE_PII_FAMILIES = {
    PiiFamily.EMAIL,
    PiiFamily.PHONE,
    PiiFamily.ADDRESS,
    PiiFamily.PERSON,
}

# Purview/Atlas classification markers that force a Review.
REVIEW_CLASSIFICATION_MARKERS = (
    "financialdata",
    "customerdata",
    "phi",
    "pci",
    "restricted",
)

# Reason codes.
RC_PII_BLOCK_PREFIX = "PII_BLOCK_"
RC_PII_REDACT_PREFIX = "PII_REDACT_"
RC_LABEL_HIGHLY_CONFIDENTIAL = "LABEL_HIGHLY_CONFIDENTIAL"
RC_LABEL_REGULATED = "LABEL_REGULATED"
RC_CONTENT_SAFETY = "CONTENT_SAFETY_THRESHOLD_EXCEEDED"
RC_PURVIEW_REVIEW = "PURVIEW_CLASSIFICATION_REVIEW"
RC_ATLAS_REVIEW = "ATLAS_CLASSIFICATION_REVIEW"
RC_INSPECTION_INCOMPLETE = "INSPECTION_INCOMPLETE"
RC_FILE_TOO_LARGE = "FILE_TOO_LARGE"
RC_NO_FINDINGS = "NO_SENSITIVE_FINDINGS"
RC_DEPENDENCY_FAILURE = "INSPECTION_DEPENDENCY_FAILURE"


# Action severity ordering (higher = more restrictive) for resolving conflicts.
_ACTION_RANK = {
    Action.ALLOW: 0,
    Action.WARN: 1,
    Action.REDACT: 2,
    Action.REVIEW: 3,
    Action.BLOCK: 4,
}


def _escalate(current: Action, candidate: Action) -> Action:
    return candidate if _ACTION_RANK[candidate] > _ACTION_RANK[current] else current


@dataclass
class DecisionInput:
    findings: Findings
    classification: Classification = Classification.UNKNOWN
    return_redacted_text: bool = False
    redacted_text: Optional[str] = None
    inspection_complete: bool = True
    file_too_large: bool = False
    dependency_failure: bool = False
    # Optional context (available for future rules / audit).
    source_application: Optional[str] = None
    user_groups: List[str] = field(default_factory=list)
    model: Optional[str] = None
    request_path: Optional[str] = None


@dataclass
class Decision:
    action: Action
    classification: Classification
    risk_score: int
    reason_codes: List[str]
    redacted_text: Optional[str] = None


class DecisionEngine:
    """Applies the default DLP/security policy to aggregated findings."""

    def __init__(self, settings: Settings):
        self._settings = settings

    def evaluate(self, decision_input: DecisionInput) -> Decision:
        settings = self._settings
        findings = decision_input.findings
        reason_codes: List[str] = []
        action = Action.ALLOW

        # 1. Dependency failure -> apply fail mode.
        if decision_input.dependency_failure:
            reason_codes.append(RC_DEPENDENCY_FAILURE)
            action = _escalate(action, self._fail_action())

        # 2. File too large -> Block or Review based on FAIL_MODE.
        if decision_input.file_too_large:
            reason_codes.append(RC_FILE_TOO_LARGE)
            action = _escalate(action, self._too_large_action())

        # 3. PII: block families above threshold.
        blocked = self._blocking_pii(findings.pii)
        for family in blocked:
            reason_codes.append(f"{RC_PII_BLOCK_PREFIX}{family.upper()}")
        if blocked:
            action = _escalate(action, Action.BLOCK)

        # 4. PII: redactable families above threshold.
        redactable = self._redactable_pii(findings.pii)
        if redactable:
            for family in redactable:
                reason_codes.append(f"{RC_PII_REDACT_PREFIX}{family.upper()}")
            if decision_input.return_redacted_text and decision_input.redacted_text:
                action = _escalate(action, Action.REDACT)
            else:
                action = _escalate(action, Action.WARN)

        # 5. Sensitivity label.
        if decision_input.classification == Classification.HIGHLY_CONFIDENTIAL:
            reason_codes.append(RC_LABEL_HIGHLY_CONFIDENTIAL)
            action = _escalate(action, Action.BLOCK)
        elif decision_input.classification == Classification.REGULATED:
            reason_codes.append(RC_LABEL_REGULATED)
            action = _escalate(action, Action.BLOCK)

        # 6. Content safety.
        if self._content_safety_exceeded(findings.contentSafety):
            reason_codes.append(RC_CONTENT_SAFETY)
            action = _escalate(action, Action.BLOCK)

        # 7. Purview / Atlas classifications -> Review.
        if self._classification_needs_review(findings.purview):
            reason_codes.append(RC_PURVIEW_REVIEW)
            action = _escalate(action, Action.REVIEW)
        if self._atlas_needs_review(findings.atlas):
            reason_codes.append(RC_ATLAS_REVIEW)
            action = _escalate(action, Action.REVIEW)

        # 8. Incomplete inspection -> Review.
        if not decision_input.inspection_complete:
            reason_codes.append(RC_INSPECTION_INCOMPLETE)
            action = _escalate(action, Action.REVIEW)

        # 9. Nothing sensitive and safe label -> Allow.
        if not reason_codes:
            if decision_input.classification in (
                Classification.PUBLIC,
                Classification.INTERNAL,
                Classification.UNKNOWN,
            ):
                reason_codes.append(RC_NO_FINDINGS)
                action = Action.ALLOW

        risk_score = compute_risk_score(
            pii=findings.pii,
            content_safety=findings.contentSafety,
            classification=decision_input.classification,
            purview=findings.purview,
            atlas=findings.atlas,
            inspection_complete=decision_input.inspection_complete,
        )

        redacted = (
            decision_input.redacted_text if action == Action.REDACT else None
        )
        return Decision(
            action=action,
            classification=decision_input.classification,
            risk_score=risk_score,
            reason_codes=reason_codes,
            redacted_text=redacted,
        )

    # --- rule helpers --------------------------------------------------------

    def _blocking_pii(self, pii: List[PiiFinding]) -> List[str]:
        families: List[str] = []
        for finding in pii:
            if (
                finding.family in BLOCKING_PII_FAMILIES
                and finding.confidence >= self._settings.threshold_for(finding.family)
                and finding.family not in families
            ):
                families.append(finding.family)
        return families

    def _redactable_pii(self, pii: List[PiiFinding]) -> List[str]:
        families: List[str] = []
        for finding in pii:
            if (
                finding.family in REDACTABLE_PII_FAMILIES
                and finding.confidence >= self._settings.threshold_for(finding.family)
                and finding.family not in families
            ):
                families.append(finding.family)
        return families

    def _content_safety_exceeded(
        self, findings: List[ContentSafetyFinding]
    ) -> bool:
        threshold = self._settings.content_safety_severity_threshold
        return any(f.severity >= threshold for f in findings)

    def _classification_needs_review(
        self, purview: Optional[PurviewFindings]
    ) -> bool:
        if not purview:
            return False
        return _contains_review_marker(purview.classifications)

    def _atlas_needs_review(self, atlas: Optional[AtlasFindings]) -> bool:
        if not atlas:
            return False
        return _contains_review_marker(atlas.classifications)

    def _fail_action(self) -> Action:
        mode = self._settings.fail_mode
        if mode == FailMode.FAIL_OPEN:
            return Action.ALLOW
        if mode == FailMode.FAIL_CLOSED:
            return Action.BLOCK
        return Action.REVIEW

    def _too_large_action(self) -> Action:
        # Block when failing closed; otherwise Review.
        if self._settings.fail_mode == FailMode.FAIL_CLOSED:
            return Action.BLOCK
        return Action.REVIEW


def _contains_review_marker(classifications: List[str]) -> bool:
    for raw in classifications:
        token = raw.replace(" ", "").replace("_", "").lower()
        if any(marker in token for marker in REVIEW_CLASSIFICATION_MARKERS):
            return True
    return False
