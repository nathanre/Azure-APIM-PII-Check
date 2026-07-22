"""Optional Microsoft Graph sensitivity-label lookup client.

Resolves a sensitivity label GUID to its display name / metadata via Microsoft
Graph. This integration is optional and disabled by default
(``ENABLE_GRAPH_LABEL_LOOKUP=false``); the decision engine works from
request-supplied labels when it is off.

Authentication uses a Managed Identity bearer token (Graph scope). The identity
must be granted ``InformationProtectionPolicy.Read`` application permission.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ..config import Settings
from ..security.auth import GRAPH_SCOPE, auth_header
from ..utils.http import HttpError, request_with_retry

logger = logging.getLogger(__name__)


@dataclass
class GraphLabel:
    id: str
    name: Optional[str] = None
    is_active: bool = True


class GraphLabelClient:
    """Wrapper over Microsoft Graph information-protection label APIs."""

    def __init__(self, settings: Settings, credential=None):
        self._settings = settings
        self._credential = credential

    @property
    def enabled(self) -> bool:
        return (
            self._settings.enable_graph_label_lookup
            and bool(self._settings.graph_endpoint)
        )

    def get_label(self, label_id: str) -> Optional[GraphLabel]:
        """Resolve a sensitivity label by GUID. Returns ``None`` on failure."""
        if not self.enabled or not label_id:
            return None
        url = (
            self._settings.graph_endpoint.rstrip("/")
            + "/v1.0/security/informationProtection/sensitivityLabels/"
            + label_id
        )
        try:
            response = request_with_retry(
                "GET",
                url,
                headers=auth_header(GRAPH_SCOPE, self._credential),
                timeout=self._settings.http_timeout_seconds,
                max_retries=self._settings.http_max_retries,
                backoff_base=self._settings.http_backoff_base_seconds,
            )
        except HttpError:
            logger.warning("Graph sensitivity label lookup failed", exc_info=True)
            return None
        if response.status_code >= 400:
            logger.warning(
                "Graph label lookup returned non-success status",
                extra={"status": response.status_code},
            )
            return None
        data = response.json()
        return GraphLabel(
            id=data.get("id", label_id),
            name=data.get("name") or data.get("displayName"),
            is_active=data.get("isActive", True),
        )
