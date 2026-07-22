"""Azure Blob Storage loader using Managed Identity.

Downloads uploaded documents referenced by a blob URL or path so their text can
be extracted for inspection. Uses ``DefaultAzureCredential`` (Managed Identity
in Azure). Enforces a configurable size limit and streams into memory only up
to that limit to avoid loading arbitrarily large files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Optional
from urllib.parse import urlparse

from ..config import Settings
from ..utils.validation import (
    ValidationError,
    host_of,
    validate_blob_host,
)

logger = logging.getLogger(__name__)


@dataclass
class BlobPayload:
    content: bytes
    content_type: Optional[str]
    metadata: Dict[str, str]
    size: int
    truncated: bool = False
    too_large: bool = False


class BlobLoadError(Exception):
    """Raised when a blob cannot be located or downloaded."""


class BlobLoader:
    """Downloads blobs from Azure Storage using a Managed Identity credential."""

    def __init__(self, settings: Settings, credential=None):
        self._settings = settings
        self._credential = credential

    def _get_credential(self):
        if self._credential is not None:
            return self._credential
        from ..security.auth import get_credential

        return get_credential()

    def load(self, blob_url: str) -> BlobPayload:
        """Download a blob by full URL (or account-relative path).

        Enforces ``MAX_FILE_BYTES``. If the blob exceeds the limit, returns a
        payload with ``too_large=True`` and no content so the policy engine can
        decide (Review/Block) without loading the file.
        """
        account_url, container, blob_name = self._parse_blob_url(blob_url)

        from azure.storage.blob import BlobClient

        blob_client = BlobClient(
            account_url=account_url,
            container_name=container,
            blob_name=blob_name,
            credential=self._get_credential(),
        )
        try:
            props = blob_client.get_blob_properties()
        except Exception as exc:  # noqa: BLE001 - normalize to BlobLoadError
            raise BlobLoadError("Unable to read blob properties") from exc

        size = int(props.size or 0)
        metadata = dict(props.metadata or {})
        content_type = (
            props.content_settings.content_type if props.content_settings else None
        )

        if size > self._settings.max_file_bytes:
            logger.info(
                "Blob exceeds inspection size limit",
                extra={"size": size, "limit": self._settings.max_file_bytes},
            )
            return BlobPayload(
                content=b"",
                content_type=content_type,
                metadata=metadata,
                size=size,
                too_large=True,
            )

        try:
            downloader = blob_client.download_blob(
                max_concurrency=2, length=self._settings.max_file_bytes
            )
            content = downloader.readall()
        except Exception as exc:  # noqa: BLE001
            raise BlobLoadError("Unable to download blob content") from exc

        return BlobPayload(
            content=content,
            content_type=content_type,
            metadata=metadata,
            size=size,
        )

    def _parse_blob_url(self, blob_url: str):
        """Return (account_url, container, blob_name) from a URL or path.

        Enforces an SSRF allowlist: an absolute URL must use HTTPS and target a
        permitted blob host (explicit allowlist, then STORAGE_ACCOUNT_URL, then
        trusted Azure blob suffixes). This prevents a caller-supplied blobUrl
        from directing the Managed Identity token to an arbitrary host.
        """
        if not blob_url:
            raise BlobLoadError("Empty blob reference")

        if blob_url.startswith("http://") or blob_url.startswith("https://"):
            parsed = urlparse(blob_url)
            if parsed.scheme != "https":
                raise BlobLoadError("Blob URL must use HTTPS")
            host = host_of(blob_url)
            try:
                validate_blob_host(
                    host,
                    allowed_hosts=self._settings.allowed_blob_hosts,
                    account_host=host_of(self._settings.storage_account_url)
                    if self._settings.storage_account_url
                    else None,
                )
            except ValidationError as exc:
                logger.warning(
                    "Rejected blob URL host", extra={"blobHost": host}
                )
                raise BlobLoadError("Blob host is not permitted") from exc
            account_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path.lstrip("/")
        else:
            # Account-relative "container/blob" path; requires STORAGE_ACCOUNT_URL.
            if not self._settings.storage_account_url:
                raise BlobLoadError(
                    "Relative blob path requires STORAGE_ACCOUNT_URL"
                )
            account_url = self._settings.storage_account_url.rstrip("/")
            path = blob_url.lstrip("/")

        # Reject path traversal in the container/blob portion.
        if ".." in path.split("/"):
            raise BlobLoadError("Blob reference must not contain path traversal")

        parts = path.split("/", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise BlobLoadError("Blob reference must include container and blob name")
        return account_url, parts[0], parts[1]
