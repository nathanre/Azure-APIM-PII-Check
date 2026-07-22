"""Deterministic risk scoring.

Converts inspection findings into a bounded 0-100 risk score. Scoring is purely
additive and deterministic so the same findings always produce the same score,
which keeps policy decisions reproducible and auditable.
"""

from __future__ import annotations

from typing import Iterable, List

from ..config import PiiFamily
from ..models import (
    Classification,
    ContentSafetyFinding,
    PiiFinding,
    PurviewFindings,
    AtlasFindings,
)

# Per-family PII contribution to the risk score.
_PII_WEIGHTS = {
    PiiFamily.SSN: 60,
    PiiFamily.CREDIT_CARD: 60,
    PiiFamily.BANK_ACCOUNT: 55,
    PiiFamily.TAX_ID: 55,
    PiiFamily.PASSPORT: 55,
    PiiFamily.DRIVER_LICENSE: 50,
    PiiFamily.HEALTH_PLAN: 50,
    PiiFamily.PERSON: 15,
    PiiFamily.EMAIL: 10,
    PiiFamily.PHONE: 10,
    PiiFamily.ADDRESS: 15,
    PiiFamily.OTHER: 10,
}

# Classification contribution.
_CLASSIFICATION_WEIGHTS = {
    Classification.REGULATED: 60,
    Classification.HIGHLY_CONFIDENTIAL: 55,
    Classification.CONFIDENTIAL: 30,
    Classification.INTERNAL: 10,
    Classification.PUBLIC: 0,
    Classification.UNKNOWN: 5,
}

# Purview/Atlas classification tokens that indicate elevated risk.
_SENSITIVE_TOKENS = {
    "financialdata": 40,
    "customerdata": 35,
    "phi": 45,
    "pci": 45,
    "restricted": 35,
    "pii": 30,
}

_CONTENT_SAFETY_WEIGHT_PER_SEVERITY = 8


def _sensitive_token_score(classifications: Iterable[str]) -> int:
    score = 0
    for raw in classifications:
        token = raw.replace(" ", "").replace("_", "").lower()
        for marker, weight in _SENSITIVE_TOKENS.items():
            if marker in token:
                score += weight
    return score


def compute_risk_score(
    *,
    pii: List[PiiFinding],
    content_safety: List[ContentSafetyFinding],
    classification: Classification,
    purview: PurviewFindings | None,
    atlas: AtlasFindings | None,
    inspection_complete: bool = True,
) -> int:
    """Return a bounded 0-100 risk score for the aggregated findings."""
    score = 0

    for finding in pii:
        score += _PII_WEIGHTS.get(finding.family, _PII_WEIGHTS[PiiFamily.OTHER])

    for finding in content_safety:
        score += finding.severity * _CONTENT_SAFETY_WEIGHT_PER_SEVERITY

    score += _CLASSIFICATION_WEIGHTS.get(classification, 0)

    if purview:
        score += _sensitive_token_score(purview.classifications)
    if atlas:
        score += _sensitive_token_score(atlas.classifications)

    if not inspection_complete:
        score += 10

    return max(0, min(100, score))
