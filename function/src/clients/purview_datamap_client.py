"""Microsoft Purview Data Map client wrapper.

Looks up governed assets by qualifiedName, GUID, name, or keyword and returns
classifications, glossary terms, business metadata, collection, owner, and
asset type. Purview classifications are normalized into the shared risk model
used by the decision engine.

Authentication uses a Managed Identity bearer token (Purview scope).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import Settings
from ..security.auth import PURVIEW_SCOPE, auth_header
from ..utils.http import HttpError, request_with_retry
from ..utils.validation import ValidationError, safe_identifier

logger = logging.getLogger(__name__)


@dataclass
class PurviewAsset:
    guid: Optional[str] = None
    qualified_name: Optional[str] = None
    asset_type: Optional[str] = None
    classifications: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    glossary_terms: List[str] = field(default_factory=list)
    business_metadata: Dict[str, Any] = field(default_factory=dict)
    collection: Optional[str] = None
    owner: Optional[str] = None


@dataclass
class PurviewResult:
    asset: Optional[PurviewAsset] = None
    succeeded: bool = True


class PurviewDataMapClient:
    """Wrapper over the Purview Data Map (catalog) REST API."""

    def __init__(self, settings: Settings, credential=None):
        self._settings = settings
        self._credential = credential

    @property
    def _base(self) -> str:
        return self._settings.purview_account_endpoint.rstrip("/")

    def lookup(
        self,
        *,
        guid: Optional[str] = None,
        qualified_name: Optional[str] = None,
        name: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> PurviewResult:
        """Look up an asset by the most specific identifier available."""
        if not self._settings.purview_account_endpoint:
            return PurviewResult(succeeded=False)
        try:
            if guid:
                return PurviewResult(asset=self._get_by_guid(guid))
            search_term = qualified_name or name or keyword
            if search_term:
                return PurviewResult(asset=self._search(search_term))
            return PurviewResult(succeeded=True)
        except HttpError:
            logger.warning("Purview Data Map lookup failed", exc_info=True)
            return PurviewResult(succeeded=False)

    def _get_by_guid(self, guid: str) -> Optional[PurviewAsset]:
        try:
            encoded_guid = safe_identifier(guid)
        except ValidationError:
            logger.warning("Rejected malformed Purview GUID")
            raise HttpError("Invalid Purview asset identifier")
        url = f"{self._base}/datamap/api/atlas/v2/entity/guid/{encoded_guid}"
        response = self._get(url)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise HttpError(f"Purview entity lookup returned {response.status_code}")
        return _parse_entity(response.json())

    def _search(self, keyword: str) -> Optional[PurviewAsset]:
        url = f"{self._base}/datamap/api/search/query"
        headers = {
            "Content-Type": "application/json",
            **auth_header(PURVIEW_SCOPE, self._credential),
        }
        body = {"keywords": keyword, "limit": 1}
        response = request_with_retry(
            "POST",
            url,
            headers=headers,
            json_body=body,
            params={"api-version": "2023-09-01"},
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )
        if response.status_code >= 400:
            raise HttpError(f"Purview search returned {response.status_code}")
        value = response.json().get("value", [])
        if not value:
            return None
        hit = value[0]
        guid = hit.get("id") or hit.get("guid")
        if guid:
            return self._get_by_guid(guid)
        return _parse_search_hit(hit)

    def _get(self, url: str):
        headers = auth_header(PURVIEW_SCOPE, self._credential)
        return request_with_retry(
            "GET",
            url,
            headers=headers,
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )


def _parse_entity(payload: dict) -> Optional[PurviewAsset]:
    entity = payload.get("entity") if isinstance(payload, dict) else None
    if not entity:
        return None
    attributes = entity.get("attributes", {})
    classifications = [
        c.get("typeName")
        for c in entity.get("classifications", [])
        if c.get("typeName")
    ]
    labels = list(entity.get("labels", []))
    business_metadata = entity.get("businessAttributes", {}) or {}
    terms = [
        t.get("displayText")
        for t in entity.get("meanings", [])
        if t.get("displayText")
    ]
    return PurviewAsset(
        guid=entity.get("guid"),
        qualified_name=attributes.get("qualifiedName"),
        asset_type=entity.get("typeName"),
        classifications=classifications,
        labels=labels,
        glossary_terms=terms,
        business_metadata=business_metadata,
        collection=(entity.get("collectionId") or attributes.get("collection")),
        owner=attributes.get("owner"),
    )


def _parse_search_hit(hit: dict) -> PurviewAsset:
    return PurviewAsset(
        guid=hit.get("id") or hit.get("guid"),
        qualified_name=hit.get("qualifiedName"),
        asset_type=hit.get("entityType") or hit.get("objectType"),
        classifications=list(hit.get("classification", []) or []),
        labels=list(hit.get("label", []) or []),
        glossary_terms=list(hit.get("term", []) or []),
    )
