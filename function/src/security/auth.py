"""Credential and bearer-token helpers built on Azure Identity.

Uses :class:`DefaultAzureCredential`, which resolves a Managed Identity in
Azure App Service / Functions and falls back to developer credentials locally.
Tokens are cached per-scope and refreshed shortly before expiry.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Common OAuth token scopes.
PURVIEW_SCOPE = "https://purview.azure.net/.default"
STORAGE_SCOPE = "https://storage.azure.com/.default"
COGNITIVE_SCOPE = "https://cognitiveservices.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Refresh a token this many seconds before it actually expires.
_EXPIRY_SKEW_SECONDS = 300

_credential = None
_credential_lock = threading.Lock()
_token_cache: Dict[str, Tuple[str, float]] = {}
_token_lock = threading.Lock()


def get_credential():
    """Return a process-wide cached ``DefaultAzureCredential`` instance."""
    global _credential
    if _credential is None:
        with _credential_lock:
            if _credential is None:
                # Imported lazily so unit tests need not install azure-identity.
                from azure.identity import DefaultAzureCredential

                _credential = DefaultAzureCredential(
                    exclude_interactive_browser_credential=True
                )
    return _credential


def get_bearer_token(scope: str, credential=None) -> str:
    """Return a valid bearer token for ``scope``, using a short-lived cache."""
    now = time.time()
    with _token_lock:
        cached = _token_cache.get(scope)
        if cached and cached[1] - _EXPIRY_SKEW_SECONDS > now:
            return cached[0]

    cred = credential or get_credential()
    access_token = cred.get_token(scope)
    with _token_lock:
        _token_cache[scope] = (access_token.token, float(access_token.expires_on))
    return access_token.token


def auth_header(scope: str, credential=None) -> Dict[str, str]:
    """Return an ``Authorization: Bearer`` header dict for ``scope``."""
    return {"Authorization": f"Bearer {get_bearer_token(scope, credential)}"}


def clear_token_cache(scope: Optional[str] = None) -> None:
    """Clear cached tokens (all scopes, or a single scope)."""
    with _token_lock:
        if scope is None:
            _token_cache.clear()
        else:
            _token_cache.pop(scope, None)
