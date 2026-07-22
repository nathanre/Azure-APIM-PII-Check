"""Azure AI Language PII detection client.

Detects PII/PHI-like entities in prompt or extracted text via the Azure AI
Language REST API. Large inputs are split into overlapping chunks, each chunk
is analyzed, and findings are aggregated with offsets re-based onto the source
text. Optionally returns redacted text when requested.

Authentication uses a Managed Identity bearer token (Cognitive Services scope).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from ..config import Settings, classify_pii_category
from ..security.auth import COGNITIVE_SCOPE, auth_header
from ..utils.chunking import chunk_text
from ..utils.http import HttpError, request_with_retry

logger = logging.getLogger(__name__)


@dataclass
class PiiEntity:
    category: str
    family: str
    confidence: float
    offset: Optional[int]
    length: Optional[int]


@dataclass
class PiiResult:
    entities: List[PiiEntity] = field(default_factory=list)
    redacted_text: Optional[str] = None
    succeeded: bool = True


class AzureLanguageClient:
    """Thin wrapper over the Azure AI Language ``:analyze-text`` endpoint."""

    def __init__(self, settings: Settings, credential=None):
        self._settings = settings
        self._credential = credential

    def detect_pii(
        self,
        text: str,
        *,
        want_redacted: bool = False,
    ) -> PiiResult:
        """Detect PII in ``text``, chunking as needed and aggregating results.

        Returns a :class:`PiiResult`. On failure, ``succeeded`` is ``False`` so
        the caller can apply the configured fail mode.
        """
        if not text or not self._settings.language_endpoint:
            return PiiResult(succeeded=bool(text) is False or True, entities=[])

        chunks = chunk_text(
            text,
            max_chunk_chars=self._settings.max_chunk_chars,
            overlap_chars=self._settings.chunk_overlap_chars,
        )

        all_entities: List[PiiEntity] = []
        # Redaction is reconstructed on the source string using entity spans.
        redacted_chars = list(text) if want_redacted else None

        try:
            for chunk in chunks:
                entities = self._analyze_chunk(chunk.text)
                for entity in entities:
                    abs_offset = (
                        entity.offset + chunk.offset
                        if entity.offset is not None
                        else None
                    )
                    all_entities.append(
                        PiiEntity(
                            category=entity.category,
                            family=entity.family,
                            confidence=entity.confidence,
                            offset=abs_offset,
                            length=entity.length,
                        )
                    )
                    if (
                        redacted_chars is not None
                        and abs_offset is not None
                        and entity.length is not None
                    ):
                        end = min(abs_offset + entity.length, len(redacted_chars))
                        for i in range(abs_offset, end):
                            redacted_chars[i] = "*"
        except HttpError:
            logger.warning("Azure AI Language PII detection failed", exc_info=True)
            return PiiResult(succeeded=False)

        deduped = _dedupe_entities(all_entities)
        redacted = "".join(redacted_chars) if redacted_chars is not None else None
        return PiiResult(entities=deduped, redacted_text=redacted, succeeded=True)

    def _analyze_chunk(self, text: str) -> List[PiiEntity]:
        url = self._settings.language_endpoint.rstrip("/") + "/language/:analyze-text"
        headers = {
            "Content-Type": "application/json",
            **auth_header(COGNITIVE_SCOPE, self._credential),
        }
        body = {
            "kind": "PiiEntityRecognition",
            "parameters": {"modelVersion": "latest"},
            "analysisInput": {
                "documents": [{"id": "1", "language": "en", "text": text}]
            },
        }
        response = request_with_retry(
            "POST",
            url,
            headers=headers,
            json_body=body,
            params={"api-version": self._settings.language_api_version},
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )
        if response.status_code >= 400:
            raise HttpError(
                f"Azure AI Language returned {response.status_code}"
            )
        return _parse_entities(response.json())


def _parse_entities(payload: dict) -> List[PiiEntity]:
    entities: List[PiiEntity] = []
    documents = (
        payload.get("results", {}).get("documents", [])
        if isinstance(payload, dict)
        else []
    )
    for doc in documents:
        for ent in doc.get("entities", []):
            category = ent.get("category", "")
            entities.append(
                PiiEntity(
                    category=category,
                    family=classify_pii_category(category),
                    confidence=float(ent.get("confidenceScore", 0.0)),
                    offset=ent.get("offset"),
                    length=ent.get("length"),
                )
            )
    return entities


def _dedupe_entities(entities: List[PiiEntity]) -> List[PiiEntity]:
    """Remove duplicate entities produced by overlapping chunk windows."""
    seen = set()
    result: List[PiiEntity] = []
    for entity in entities:
        key = (entity.category, entity.offset, entity.length)
        if key in seen:
            continue
        seen.add(key)
        result.append(entity)
    return result
