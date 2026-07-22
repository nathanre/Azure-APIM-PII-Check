"""Modular document text and metadata extraction.

Extracts inspectable text (and any embedded sensitivity metadata) from common
document formats. Extraction is registered per content type / extension so new
formats can be added without touching callers.

Supported: text/plain, JSON, CSV, DOCX, PDF. Extracted content is held only in
memory and is never written to disk unless explicitly configured elsewhere.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    text: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)
    format: str = "unknown"
    extraction_complete: bool = True


def _extract_plain(data: bytes) -> ExtractionResult:
    return ExtractionResult(
        text=_decode(data), format="text/plain"
    )


def _extract_json(data: bytes) -> ExtractionResult:
    raw = _decode(data)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return ExtractionResult(text=raw, format="json", extraction_complete=False)
    # Flatten to a readable string for inspection while preserving values.
    return ExtractionResult(
        text=json.dumps(parsed, ensure_ascii=False), format="json"
    )


def _extract_csv(data: bytes) -> ExtractionResult:
    raw = _decode(data)
    rows = []
    try:
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            rows.append(" ".join(cell for cell in row))
    except csv.Error:
        return ExtractionResult(text=raw, format="csv", extraction_complete=False)
    return ExtractionResult(text="\n".join(rows), format="csv")


def _extract_docx(data: bytes) -> ExtractionResult:
    try:
        import docx  # python-docx
    except ImportError:
        logger.warning("python-docx not installed; cannot extract DOCX")
        return ExtractionResult(format="docx", extraction_complete=False)
    try:
        document = docx.Document(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        logger.warning("DOCX parse failed", exc_info=True)
        return ExtractionResult(format="docx", extraction_complete=False)

    text = "\n".join(p.text for p in document.paragraphs)
    metadata: Dict[str, str] = {}
    try:
        core = document.core_properties
        if core.category:
            metadata["category"] = core.category
        if core.comments:
            metadata["comments"] = core.comments
        # Custom properties frequently hold sensitivity labels (MIP).
        custom = getattr(document.part, "custom_properties", None)
        if custom is not None:
            for name in getattr(custom, "keys", lambda: [])():
                metadata[str(name)] = str(custom[name])
    except Exception:  # noqa: BLE001 - metadata is best-effort
        logger.debug("DOCX metadata extraction incomplete", exc_info=True)
    return ExtractionResult(text=text, metadata=metadata, format="docx")


def _extract_pdf(data: bytes) -> ExtractionResult:
    try:
        from pypdf import PdfReader
    except ImportError:
        logger.warning("pypdf not installed; cannot extract PDF")
        return ExtractionResult(format="pdf", extraction_complete=False)
    try:
        reader = PdfReader(io.BytesIO(data))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:  # noqa: BLE001
        logger.warning("PDF parse failed", exc_info=True)
        return ExtractionResult(format="pdf", extraction_complete=False)

    metadata: Dict[str, str] = {}
    try:
        if reader.metadata:
            for key, value in reader.metadata.items():
                metadata[str(key).lstrip("/")] = str(value)
    except Exception:  # noqa: BLE001
        logger.debug("PDF metadata extraction incomplete", exc_info=True)
    return ExtractionResult(text=text, metadata=metadata, format="pdf")


# Registry of extractors keyed by a normalized format token.
_EXTRACTORS: Dict[str, Callable[[bytes], ExtractionResult]] = {
    "text/plain": _extract_plain,
    "text": _extract_plain,
    "txt": _extract_plain,
    "application/json": _extract_json,
    "json": _extract_json,
    "text/csv": _extract_csv,
    "csv": _extract_csv,
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        _extract_docx,
    "docx": _extract_docx,
    "application/pdf": _extract_pdf,
    "pdf": _extract_pdf,
}


def register_extractor(
    key: str, extractor: Callable[[bytes], ExtractionResult]
) -> None:
    """Register a new extractor for a content type or extension token."""
    _EXTRACTORS[key.lower()] = extractor


def extract(
    data: bytes,
    *,
    content_type: Optional[str] = None,
    file_name: Optional[str] = None,
    max_decompressed_bytes: Optional[int] = None,
    max_text_chars: Optional[int] = None,
) -> ExtractionResult:
    """Extract text/metadata by content type, falling back to extension.

    Unknown formats are treated as plain-text as a best-effort fallback and are
    marked ``extraction_complete=False`` so the policy engine can treat the
    inspection as incomplete.

    ``max_decompressed_bytes`` guards archive-based formats (DOCX) against
    decompression bombs. ``max_text_chars`` bounds the returned text so a
    maliciously large document cannot exhaust memory downstream; when it is
    exceeded the text is truncated and ``extraction_complete`` is set False.
    """
    extractor = None
    if content_type:
        key = content_type.split(";")[0].strip().lower()
        extractor = _EXTRACTORS.get(key)

    if extractor is None and file_name and "." in file_name:
        ext = file_name.rsplit(".", 1)[1].lower()
        extractor = _EXTRACTORS.get(ext)

    if extractor is None:
        logger.info(
            "No registered extractor; using plain-text fallback",
            extra={"contentType": content_type, "fileName": file_name},
        )
        result = _extract_plain(data)
        result.extraction_complete = False
        return _bound_text(result, max_text_chars)

    # Defend archive-based formats against decompression bombs before parsing.
    if extractor is _extract_docx and max_decompressed_bytes is not None:
        if not _zip_within_limit(data, max_decompressed_bytes):
            logger.warning("DOCX rejected: decompressed size exceeds limit")
            return ExtractionResult(format="docx", extraction_complete=False)

    return _bound_text(extractor(data), max_text_chars)


def _bound_text(
    result: ExtractionResult, max_text_chars: Optional[int]
) -> ExtractionResult:
    if max_text_chars is not None and len(result.text) > max_text_chars:
        result.text = result.text[:max_text_chars]
        result.extraction_complete = False
    return result


def _zip_within_limit(data: bytes, limit: int) -> bool:
    """Return True if the total *uncompressed* size of a zip is within limit."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            total = 0
            for info in archive.infolist():
                total += info.file_size
                if total > limit:
                    return False
        return True
    except (zipfile.BadZipFile, OSError):
        # Not a valid archive; let the format extractor report incompleteness.
        return True


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")
