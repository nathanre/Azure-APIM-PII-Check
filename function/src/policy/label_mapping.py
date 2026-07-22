"""Sensitivity-label normalization.

Interprets a sensitivity label supplied via request headers, document metadata,
or a Graph lookup, and normalizes it to the canonical classification model used
by the decision engine. The mapping table is configurable in code and can be
extended via the ``LABEL_MAPPING_OVERRIDES`` environment variable (JSON of
``{"raw label": "Classification"}``).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, Optional

from ..models import Classification

logger = logging.getLogger(__name__)

# Metadata / header keys that may carry a sensitivity label.
LABEL_HEADER_KEYS = (
    "x-ms-sensitivity-label",
    "x-data-classification",
    "x-purview-label-id",
    "sensitivitylabel",
    "classification",
    "dataclassification",
)

# Canonical mapping table (raw label text -> Classification). Keys are matched
# case-insensitively after stripping spaces, hyphens and underscores.
_BASE_LABEL_MAP: Dict[str, Classification] = {
    "public": Classification.PUBLIC,
    "general": Classification.INTERNAL,
    "internal": Classification.INTERNAL,
    "internalonly": Classification.INTERNAL,
    "confidential": Classification.CONFIDENTIAL,
    "companyconfidential": Classification.CONFIDENTIAL,
    "highlyconfidential": Classification.HIGHLY_CONFIDENTIAL,
    "highlyconfidental": Classification.HIGHLY_CONFIDENTIAL,
    "secret": Classification.HIGHLY_CONFIDENTIAL,
    "restricted": Classification.HIGHLY_CONFIDENTIAL,
    "regulated": Classification.REGULATED,
    "regulateddata": Classification.REGULATED,
    "pci": Classification.REGULATED,
    "phi": Classification.REGULATED,
}


def _normalize_key(raw: str) -> str:
    return raw.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


def _load_overrides() -> Dict[str, Classification]:
    overrides_raw = os.environ.get("LABEL_MAPPING_OVERRIDES")
    if not overrides_raw:
        return {}
    try:
        parsed = json.loads(overrides_raw)
    except json.JSONDecodeError:
        logger.warning("LABEL_MAPPING_OVERRIDES is not valid JSON; ignoring")
        return {}
    result: Dict[str, Classification] = {}
    for key, value in parsed.items():
        try:
            result[_normalize_key(key)] = Classification(value)
        except ValueError:
            logger.warning("Unknown classification in overrides: %s", value)
    return result


def normalize_label(raw_label: Optional[str]) -> Classification:
    """Normalize a raw label string to a :class:`Classification`.

    Returns :attr:`Classification.UNKNOWN` for empty or unrecognized input.
    """
    if not raw_label:
        return Classification.UNKNOWN
    key = _normalize_key(raw_label)
    if not key:
        return Classification.UNKNOWN

    overrides = _load_overrides()
    if key in overrides:
        return overrides[key]
    if key in _BASE_LABEL_MAP:
        return _BASE_LABEL_MAP[key]

    # Fall back to substring containment for compound label names. Check the
    # most specific (longest) markers first so "highly confidential" is not
    # shadowed by the shorter "confidential".
    for candidate in sorted(_BASE_LABEL_MAP, key=len, reverse=True):
        if candidate in key:
            return _BASE_LABEL_MAP[candidate]
    return Classification.UNKNOWN


def extract_label_from_metadata(metadata: Dict[str, object]) -> Optional[str]:
    """Return the first recognized label value from a metadata dict."""
    if not metadata:
        return None
    lowered = {str(k).lower(): v for k, v in metadata.items()}
    for key in LABEL_HEADER_KEYS:
        value = lowered.get(key)
        if value:
            return str(value)
    return None
