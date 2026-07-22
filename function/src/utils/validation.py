"""Input-validation helpers for untrusted identifiers and blob references.

These guard against path/URL injection and SSRF by validating attacker-supplied
values (asset GUIDs, blob URLs) before they are used to build outbound request
URLs that carry a Managed Identity bearer token.
"""

from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import quote, urlparse

# Asset/entity identifiers: conservative allowlist. Purview/Atlas GUIDs are
# UUID-like, but Atlas can use longer opaque IDs, so we allow alphanumerics,
# dash, underscore, colon, and dot up to a bounded length.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,200}$")

# Trusted Azure Blob endpoint suffixes across public and sovereign clouds.
TRUSTED_BLOB_SUFFIXES = (
    ".blob.core.windows.net",
    ".blob.core.usgovcloudapi.net",
    ".blob.core.chinacloudapi.cn",
    ".blob.core.cloudapi.de",
)


class ValidationError(ValueError):
    """Raised when an untrusted input fails validation."""


def safe_identifier(value: str) -> str:
    """Validate an untrusted asset identifier and return a URL-safe segment.

    Raises :class:`ValidationError` if the value contains path-traversal or
    reserved URL characters. The returned value is percent-encoded so it can be
    safely interpolated into a single URL path segment.
    """
    if not value or not _IDENTIFIER_RE.match(value):
        raise ValidationError("Invalid asset identifier")
    if ".." in value:
        raise ValidationError("Invalid asset identifier")
    return quote(value, safe="")


def validate_blob_host(
    host: str,
    *,
    allowed_hosts: Optional[Iterable[str]] = None,
    account_host: Optional[str] = None,
) -> None:
    """Validate a blob URL host against the configured allowlist.

    Order of precedence:
      1. If an explicit ``allowed_hosts`` set is configured, the host must be a
         case-insensitive exact match of one of them.
      2. Else, if ``account_host`` (from STORAGE_ACCOUNT_URL) is set, the host
         must match it exactly.
      3. Else, the host must end with a trusted Azure blob endpoint suffix.

    Raises :class:`ValidationError` when the host is not permitted.
    """
    if not host:
        raise ValidationError("Blob URL is missing a host")
    normalized = host.lower()

    allowed = {h.lower() for h in (allowed_hosts or []) if h}
    if allowed:
        if normalized in allowed:
            return
        raise ValidationError("Blob host is not in the configured allowlist")

    if account_host:
        if normalized == account_host.lower():
            return
        raise ValidationError("Blob host does not match STORAGE_ACCOUNT_URL")

    if normalized.endswith(TRUSTED_BLOB_SUFFIXES):
        return
    raise ValidationError("Blob host is not a trusted Azure Storage endpoint")


def host_of(url: str) -> str:
    """Return the lowercase network location (host[:port]) of a URL."""
    return (urlparse(url).netloc or "").lower()
