"""Apache Atlas v2 API client wrapper for Microsoft Purview.

Provides the Atlas operations used by the inspection service:
  * get entity by GUID
  * search / query by keyword
  * retrieve classifications on an entity
  * retrieve labels / business metadata where available
  * retrieve lineage where an asset identifier is supplied

Uses the ``/catalog/api/atlas/v2`` routes exposed by a Purview account and
bearer-token authentication (Purview scope). Timeouts and retries are
configurable via :class:`Settings`.
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
class AtlasEntity:
    guid: Optional[str] = None
    type_name: Optional[str] = None
    qualified_name: Optional[str] = None
    classifications: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    business_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AtlasResult:
    entity: Optional[AtlasEntity] = None
    lineage_available: bool = False
    succeeded: bool = True


class AtlasClient:
    """Wrapper over the Purview-hosted Apache Atlas v2 API."""

    def __init__(self, settings: Settings, credential=None):
        self._settings = settings
        self._credential = credential

    @property
    def _base(self) -> str:
        return self._settings.purview_account_endpoint.rstrip("/") + (
            "/catalog/api/atlas/v2"
        )

    def get_entity(self, guid: str) -> AtlasResult:
        """Retrieve an entity (with classifications/labels) by GUID."""
        if not guid or not self._settings.purview_account_endpoint:
            return AtlasResult(succeeded=False)
        try:
            entity = self._get_entity_by_guid(guid)
            if entity is None:
                return AtlasResult(succeeded=True)
            lineage = self._has_lineage(guid)
            return AtlasResult(entity=entity, lineage_available=lineage)
        except HttpError:
            logger.warning("Atlas entity lookup failed", exc_info=True)
            return AtlasResult(succeeded=False)

    def search(self, keyword: str) -> AtlasResult:
        """Search for an entity by keyword and return the top hit."""
        if not keyword or not self._settings.purview_account_endpoint:
            return AtlasResult(succeeded=False)
        try:
            guid = self._search_top_guid(keyword)
            if not guid:
                return AtlasResult(succeeded=True)
            return self.get_entity(guid)
        except HttpError:
            logger.warning("Atlas search failed", exc_info=True)
            return AtlasResult(succeeded=False)

    # --- internal helpers ----------------------------------------------------

    def _get_entity_by_guid(self, guid: str) -> Optional[AtlasEntity]:
        try:
            encoded_guid = safe_identifier(guid)
        except ValidationError:
            logger.warning("Rejected malformed Atlas GUID")
            raise HttpError("Invalid Atlas entity identifier")
        url = f"{self._base}/entity/guid/{encoded_guid}"
        response = self._get(url)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise HttpError(f"Atlas entity returned {response.status_code}")
        return _parse_atlas_entity(response.json())

    def _search_top_guid(self, keyword: str) -> Optional[str]:
        url = f"{self._base}/search/basic"
        headers = {
            "Content-Type": "application/json",
            **auth_header(PURVIEW_SCOPE, self._credential),
        }
        body = {"query": keyword, "limit": 1}
        response = request_with_retry(
            "POST",
            url,
            headers=headers,
            json_body=body,
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )
        if response.status_code >= 400:
            raise HttpError(f"Atlas search returned {response.status_code}")
        entities = response.json().get("entities", [])
        if not entities:
            return None
        return entities[0].get("guid")

    def _has_lineage(self, guid: str) -> bool:
        try:
            encoded_guid = safe_identifier(guid)
        except ValidationError:
            return False
        url = f"{self._base}/lineage/{encoded_guid}"
        try:
            response = self._get(url, params={"depth": 1, "direction": "BOTH"})
        except HttpError:
            return False
        if response.status_code >= 400:
            return False
        data = response.json()
        relations = data.get("relations", []) if isinstance(data, dict) else []
        return len(relations) > 0

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None):
        headers = auth_header(PURVIEW_SCOPE, self._credential)
        return request_with_retry(
            "GET",
            url,
            headers=headers,
            params=params,
            timeout=self._settings.http_timeout_seconds,
            max_retries=self._settings.http_max_retries,
            backoff_base=self._settings.http_backoff_base_seconds,
        )


def _parse_atlas_entity(payload: dict) -> Optional[AtlasEntity]:
    entity = payload.get("entity") if isinstance(payload, dict) else None
    if not entity:
        return None
    attributes = entity.get("attributes", {})
    classifications = [
        c.get("typeName")
        for c in entity.get("classifications", [])
        if c.get("typeName")
    ]
    return AtlasEntity(
        guid=entity.get("guid"),
        type_name=entity.get("typeName"),
        qualified_name=attributes.get("qualifiedName"),
        classifications=classifications,
        labels=list(entity.get("labels", []) or []),
        business_metadata=entity.get("businessAttributes", {}) or {},
    )
