"""Centralized configuration loaded from environment variables.

All endpoints, tenant/client IDs, feature flags, thresholds, and policy
settings are read from environment variables so nothing tenant-specific is
hard-coded. Access configuration through :func:`get_settings`, which caches a
single immutable :class:`Settings` instance per process.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Dict, Tuple


# --- Enumerated string constants ---------------------------------------------

class FailMode:
    """Behavior when an external inspection dependency fails."""

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    REVIEW = "review"

    ALL = {FAIL_OPEN, FAIL_CLOSED, REVIEW}


# Normalized PII "families". Azure AI Language returns many granular category
# names; we map each to one of these families for policy evaluation.
class PiiFamily:
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    TAX_ID = "tax_id"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    HEALTH_PLAN = "health_plan"
    EMAIL = "email"
    PHONE = "phone"
    ADDRESS = "address"
    PERSON = "person"
    OTHER = "other"


# Substring markers used to classify Azure AI Language PII categories into a
# family. Matching is case-insensitive and order-sensitive (first match wins).
PII_CATEGORY_FAMILY_MARKERS = (
    (PiiFamily.SSN, ("socialsecurity", "ssn")),
    (PiiFamily.CREDIT_CARD, ("creditcard", "creditdebit")),
    (PiiFamily.BANK_ACCOUNT, ("bank", "iban", "aba", "swift", "routing")),
    (PiiFamily.TAX_ID, ("taxpayer", "taxid", "tin", "itin", "vat")),
    (PiiFamily.PASSPORT, ("passport",)),
    (PiiFamily.DRIVER_LICENSE, ("driver", "drivinglicen", "driverslicen")),
    (PiiFamily.HEALTH_PLAN, ("healthplan", "healthinsurance", "medicare", "nhs")),
    (PiiFamily.EMAIL, ("email",)),
    (PiiFamily.PHONE, ("phone",)),
    (PiiFamily.ADDRESS, ("address",)),
    (PiiFamily.PERSON, ("person", "name")),
)


def classify_pii_category(category: str) -> str:
    """Map an Azure AI Language PII category name to a normalized family."""
    if not category:
        return PiiFamily.OTHER
    lowered = category.replace(" ", "").replace("_", "").lower()
    for family, markers in PII_CATEGORY_FAMILY_MARKERS:
        if any(marker in lowered for marker in markers):
            return family
    return PiiFamily.OTHER


# Default per-family confidence thresholds. Overridable via
# PII_THRESHOLD_<FAMILY> environment variables (e.g. PII_THRESHOLD_SSN).
_DEFAULT_PII_THRESHOLDS: Dict[str, float] = {
    PiiFamily.SSN: 0.80,
    PiiFamily.CREDIT_CARD: 0.80,
    PiiFamily.BANK_ACCOUNT: 0.80,
    PiiFamily.TAX_ID: 0.80,
    PiiFamily.PASSPORT: 0.80,
    PiiFamily.DRIVER_LICENSE: 0.80,
    PiiFamily.HEALTH_PLAN: 0.80,
    PiiFamily.EMAIL: 0.70,
    PiiFamily.PHONE: 0.70,
    PiiFamily.ADDRESS: 0.70,
    PiiFamily.PERSON: 0.75,
    PiiFamily.OTHER: 0.85,
}


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_str(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def _get_csv(name: str) -> Tuple[str, ...]:
    raw = os.environ.get(name, "")
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    """Immutable snapshot of environment configuration."""

    # --- Endpoints -----------------------------------------------------------
    language_endpoint: str = ""
    language_api_version: str = "2023-04-01"
    content_safety_endpoint: str = ""
    content_safety_api_version: str = "2024-09-01"
    purview_account_endpoint: str = ""
    graph_endpoint: str = "https://graph.microsoft.com"
    storage_account_url: str = ""

    # --- Policy --------------------------------------------------------------
    policy_version: str = "2026-07-01"
    fail_mode: str = FailMode.FAIL_CLOSED
    default_action_on_error: str = "Review"

    # --- Size / chunking limits ---------------------------------------------
    max_prompt_chars: int = 50_000
    max_chunk_chars: int = 5_000
    chunk_overlap_chars: int = 200
    max_file_bytes: int = 20 * 1024 * 1024
    # Upper bound on the *decompressed* size of an archive-based document
    # (e.g. DOCX) to defend against decompression / zip bombs.
    max_decompressed_bytes: int = 100 * 1024 * 1024

    # --- Blob SSRF allowlist -------------------------------------------------
    # Exact blob hostnames permitted for download. Empty = fall back to the
    # STORAGE_ACCOUNT_URL host, then trusted Azure blob endpoint suffixes.
    allowed_blob_hosts: Tuple[str, ...] = ()

    # --- Feature flags -------------------------------------------------------
    enable_graph_label_lookup: bool = False
    enable_purview_lookup: bool = True
    enable_atlas_lookup: bool = True
    enable_content_safety: bool = True
    enable_pii_detection: bool = True
    log_raw_content: bool = False

    # --- HTTP behavior -------------------------------------------------------
    http_timeout_seconds: float = 10.0
    http_max_retries: int = 3
    http_backoff_base_seconds: float = 0.5

    # --- Content safety severity threshold (0-7 Azure scale) -----------------
    content_safety_severity_threshold: int = 4

    # --- PII thresholds ------------------------------------------------------
    pii_thresholds: Dict[str, float] = field(default_factory=dict)

    def threshold_for(self, family: str) -> float:
        """Return the confidence threshold for a normalized PII family."""
        return self.pii_thresholds.get(
            family, _DEFAULT_PII_THRESHOLDS.get(family, 0.80)
        )


def _load_pii_thresholds() -> Dict[str, float]:
    thresholds: Dict[str, float] = dict(_DEFAULT_PII_THRESHOLDS)
    for family in _DEFAULT_PII_THRESHOLDS:
        env_name = f"PII_THRESHOLD_{family.upper()}"
        thresholds[family] = _get_float(env_name, thresholds[family])
    return thresholds


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load and cache configuration from the process environment."""
    fail_mode = _get_str("FAIL_MODE", FailMode.FAIL_CLOSED).lower()
    if fail_mode not in FailMode.ALL:
        fail_mode = FailMode.FAIL_CLOSED

    return Settings(
        language_endpoint=_get_str("AZURE_LANGUAGE_ENDPOINT"),
        language_api_version=_get_str("AZURE_LANGUAGE_API_VERSION", "2023-04-01"),
        content_safety_endpoint=_get_str("CONTENT_SAFETY_ENDPOINT"),
        content_safety_api_version=_get_str(
            "CONTENT_SAFETY_API_VERSION", "2024-09-01"
        ),
        purview_account_endpoint=_get_str("PURVIEW_ACCOUNT_ENDPOINT"),
        graph_endpoint=_get_str("GRAPH_ENDPOINT", "https://graph.microsoft.com"),
        storage_account_url=_get_str("STORAGE_ACCOUNT_URL"),
        policy_version=_get_str("POLICY_VERSION", "2026-07-01"),
        fail_mode=fail_mode,
        default_action_on_error=_get_str("DEFAULT_ACTION_ON_ERROR", "Review"),
        max_prompt_chars=_get_int("MAX_PROMPT_CHARS", 50_000),
        max_chunk_chars=_get_int("MAX_CHUNK_CHARS", 5_000),
        chunk_overlap_chars=_get_int("CHUNK_OVERLAP_CHARS", 200),
        max_file_bytes=_get_int("MAX_FILE_BYTES", 20 * 1024 * 1024),
        max_decompressed_bytes=_get_int(
            "MAX_DECOMPRESSED_BYTES", 100 * 1024 * 1024
        ),
        allowed_blob_hosts=_get_csv("ALLOWED_BLOB_HOSTS"),
        enable_graph_label_lookup=_get_bool("ENABLE_GRAPH_LABEL_LOOKUP", False),
        enable_purview_lookup=_get_bool("ENABLE_PURVIEW_LOOKUP", True),
        enable_atlas_lookup=_get_bool("ENABLE_ATLAS_LOOKUP", True),
        enable_content_safety=_get_bool("ENABLE_CONTENT_SAFETY", True),
        enable_pii_detection=_get_bool("ENABLE_PII_DETECTION", True),
        log_raw_content=_get_bool("LOG_RAW_CONTENT", False),
        http_timeout_seconds=_get_float("HTTP_TIMEOUT_SECONDS", 10.0),
        http_max_retries=_get_int("HTTP_MAX_RETRIES", 3),
        http_backoff_base_seconds=_get_float("HTTP_BACKOFF_BASE_SECONDS", 0.5),
        content_safety_severity_threshold=_get_int(
            "CONTENT_SAFETY_SEVERITY_THRESHOLD", 4
        ),
        pii_thresholds=_load_pii_thresholds(),
    )


def reset_settings_cache() -> None:
    """Clear the cached settings (used by tests after mutating the env)."""
    get_settings.cache_clear()
