"""Azure AI Content Safety client wrapper.

Evaluates prompt text against configurable safety categories using the Azure
AI Content Safety ``:analyze`` REST endpoint. Content safety findings are
returned separately from PII/DLP findings and are never merged into the
Purview classification model.

Authentication uses a Managed Identity bearer token (Cognitive Services scope).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import Settings
from ..security.auth import COGNITIVE_SCOPE, auth_header
from ..utils.chunking import chunk_text
from ..utils.http import HttpError, request_with_retry

logger = logging.getLogger(__name__)

# Default Azure AI Content Safety categories.
DEFAULT_CATEGORIES = ("Hate", "SelfHarm", "Sexual", "Violence")


@dataclass
class SafetyFinding:
    category: str
    severity: int


@dataclass
class ContentSafetyResult:
    findings: List[SafetyFinding] = field(default_factory=list)
    succeeded: bool = True


class ContentSafetyClient:
    """Wrapper over the Azure AI Content Safety text analysis endpoint."""

    def __init__(
        self,
        settings: Settings,
        credential=None,
        categories: Optional[List[str]] = None,
    ):
        self._settings = settings
        self._credential = credential
        self._categories = list(categories) if categories else list(DEFAULT_CATEGORIES)

    def analyze(self, text: str) -> ContentSafetyResult:
        """Analyze ``text`` and return findings at or above the threshold."""
        if not text or not self._settings.content_safety_endpoint:
            return ContentSafetyResult(succeeded=True)

        threshold = self._settings.content_safety_severity_threshold
        # Content Safety limits request size; analyze the first chunk window.
        chunks = chunk_text(
            text,
            max_chunk_chars=self._settings.max_chunk_chars,
            overlap_chars=self._settings.chunk_overlap_chars,
        )

        aggregated: dict = {}
        try:
            for chunk in chunks:
                for finding in self._analyze_chunk(chunk.text):
                    prior = aggregated.get(finding.category)
                    if prior is None or finding.severity > prior:
                        aggregated[finding.category] = finding.severity
        except HttpError:
            logger.warning("Azure AI Content Safety analysis failed", exc_info=True)
            return ContentSafetyResult(succeeded=False)

        findings = [
            SafetyFinding(category=cat, severity=sev)
            for cat, sev in aggregated.items()
            if sev >= threshold
        ]
        return ContentSafetyResult(findings=findings, succeeded=True)

    def _analyze_chunk(self, text: str) -> List[SafetyFinding]:
        url = self._settings.content_safety_endpoint.rstrip("/") + (
            "/contentsafety/text:analyze"
        )
        headers = {
            "Content-Type": "application/json",
            **auth_header(COGNITIVE_SCOPE, self._credential),
        }
        body = {
            "text": text,
            "categories": self._categories,
            "outputType": "FourSeverityLevels",
        }
        response = request_with_retry(
            "POST",
            url,
            headers=headers,
            json_body=body,
            params={"api-version": self._settings.content_safety_api_version},
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )
        if response.status_code >= 400:
            raise HttpError(
                f"Azure AI Content Safety returned {response.status_code}"
            )
        return _parse_findings(response.json())


def _parse_findings(payload: dict) -> List[SafetyFinding]:
    findings: List[SafetyFinding] = []
    if not isinstance(payload, dict):
        return findings
    for item in payload.get("categoriesAnalysis", []):
        category = item.get("category")
        severity = item.get("severity")
        if category is not None and severity is not None:
            findings.append(SafetyFinding(category=category, severity=int(severity)))
    return findings
