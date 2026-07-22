"""Azure Function: synchronous inspection / DLP decision service for APIM.

APIM calls ``POST /api/evaluate`` before forwarding a request to a model
backend. This function inspects prompt text, request metadata, uploaded
document references, and optional Purview asset identifiers, then returns a
normalized decision (Allow / Warn / Redact / Block / Review).

This service never calls the LLM backend and never stores sensitive content
unless explicitly configured. Raw prompt/document content is not logged by
default.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import List, Optional, Tuple

import azure.functions as func
from pydantic import ValidationError

from src.clients.atlas_client import AtlasClient
from src.clients.azure_language_client import AzureLanguageClient
from src.clients.content_safety_client import ContentSafetyClient
from src.clients.graph_label_client import GraphLabelClient
from src.clients.purview_datamap_client import PurviewDataMapClient
from src.config import get_settings
from src.document.blob_loader import BlobLoader, BlobLoadError
from src.document.document_extractor import extract
from src.models import (
    Action,
    AtlasFindings,
    AuditInfo,
    Classification,
    ContentSafetyFinding,
    ContentType,
    EvaluateRequest,
    EvaluateResponse,
    Findings,
    PiiFinding,
    PurviewFindings,
)
from src.policy.decision_engine import (
    RC_DEPENDENCY_FAILURE,
    Decision,
    DecisionEngine,
    DecisionInput,
)
from src.policy.label_mapping import (
    LABEL_HEADER_KEYS,
    extract_label_from_metadata,
    normalize_label,
)
from src.utils.logging import configure_logging, log_event

configure_logging()
logger = logging.getLogger("inspection.evaluate")

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)


@app.route(route="evaluate", methods=["POST"])
def evaluate(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP entry point for the inspection decision service."""
    settings = get_settings()
    started = time.perf_counter()
    correlation_id: Optional[str] = None

    try:
        body = req.get_json()
    except ValueError:
        return _error_response(settings, correlation_id, started, "INVALID_JSON")

    try:
        request = EvaluateRequest.model_validate(body)
    except ValidationError:
        log_event(
            logger, logging.WARNING, "Request failed schema validation",
            correlation_id=correlation_id,
        )
        return _error_response(settings, correlation_id, started, "SCHEMA_INVALID")

    correlation_id = request.correlationId or str(uuid.uuid4())

    try:
        response = _run_inspection(request, correlation_id, started)
        return func.HttpResponse(
            response.model_dump_json(),
            status_code=200,
            mimetype="application/json",
        )
    except Exception:  # noqa: BLE001 - never leak internal errors to APIM
        logger.exception(
            "Unhandled inspection error", extra={"correlationId": correlation_id}
        )
        return _error_response(settings, correlation_id, started, "INTERNAL_ERROR")


def _run_inspection(
    request: EvaluateRequest,
    correlation_id: str,
    started: float,
) -> EvaluateResponse:
    settings = get_settings()
    options = request.options
    dependency_failure = False
    inspection_complete = True
    file_too_large = False
    content_stored = False

    # --- Resolve inspectable text and document metadata ----------------------
    text = request.content.text or ""
    doc_metadata: dict = dict(request.content.metadata or {})

    if request.content.blobUrl and _wants_document(request):
        text, doc_metadata, file_too_large, extraction_ok = _load_and_extract(
            request, correlation_id, settings, doc_metadata
        )
        if file_too_large:
            inspection_complete = False
        if not extraction_ok:
            inspection_complete = False

    if len(text) > settings.max_prompt_chars:
        # Bound inspection cost/memory: inspect up to the configured maximum and
        # flag the inspection as incomplete so the decision engine escalates to
        # Review rather than silently ignoring the untested remainder.
        log_event(
            logger, logging.INFO, "Text exceeds MAX_PROMPT_CHARS; truncating",
            correlation_id=correlation_id, length=len(text),
        )
        text = text[: settings.max_prompt_chars]
        inspection_complete = False

    # --- PII detection -------------------------------------------------------
    pii_findings: List[PiiFinding] = []
    redacted_text: Optional[str] = None
    if settings.enable_pii_detection and options.runPiiDetection and text:
        pii_findings, redacted_text, ok = _run_pii(
            settings, text, options.returnRedactedText
        )
        dependency_failure = dependency_failure or not ok

    # --- Content safety ------------------------------------------------------
    content_safety_findings: List[ContentSafetyFinding] = []
    if settings.enable_content_safety and options.runContentSafety and text:
        content_safety_findings, ok = _run_content_safety(settings, text)
        dependency_failure = dependency_failure or not ok

    # --- Sensitivity label ---------------------------------------------------
    classification = _resolve_label(settings, request, doc_metadata)

    # --- Purview Data Map ----------------------------------------------------
    purview_findings: Optional[PurviewFindings] = None
    if settings.enable_purview_lookup and options.lookupPurview:
        purview_findings, ok = _run_purview(settings, doc_metadata)
        dependency_failure = dependency_failure or not ok

    # --- Atlas ---------------------------------------------------------------
    atlas_findings: Optional[AtlasFindings] = None
    if settings.enable_atlas_lookup and options.lookupAtlas:
        atlas_findings, ok = _run_atlas(settings, doc_metadata)
        dependency_failure = dependency_failure or not ok

    findings = Findings(
        pii=pii_findings,
        contentSafety=content_safety_findings,
        purview=purview_findings,
        atlas=atlas_findings,
    )

    decision: Decision = DecisionEngine(settings).evaluate(
        DecisionInput(
            findings=findings,
            classification=classification,
            return_redacted_text=options.returnRedactedText,
            redacted_text=redacted_text,
            inspection_complete=inspection_complete,
            file_too_large=file_too_large,
            dependency_failure=dependency_failure,
            source_application=request.source.application,
            user_groups=request.user.groups,
            model=request.source.model,
            request_path=request.source.requestPath,
        )
    )

    latency_ms = int((time.perf_counter() - started) * 1000)
    response = EvaluateResponse(
        correlationId=correlation_id,
        action=decision.action,
        classification=decision.classification,
        riskScore=decision.risk_score,
        policyVersion=settings.policy_version,
        reasonCodes=decision.reason_codes,
        findings=findings,
        redactedText=decision.redacted_text,
        audit=AuditInfo(
            inspected=True,
            inspectionMode="synchronous",
            contentStored=content_stored,
            inspectionComplete=inspection_complete,
            latencyMs=latency_ms,
        ),
    )

    log_event(
        logger, logging.INFO, "Inspection complete",
        correlation_id=correlation_id,
        action=decision.action.value,
        classification=decision.classification.value,
        riskScore=decision.risk_score,
        reasonCodes=decision.reason_codes,
        piiCount=len(pii_findings),
        contentSafetyCount=len(content_safety_findings),
        latencyMs=latency_ms,
        dependencyFailure=dependency_failure,
    )
    return response


# --- Inspection step helpers -------------------------------------------------

def _wants_document(request: EvaluateRequest) -> bool:
    return request.content.type in (
        ContentType.DOCUMENT,
        ContentType.BLOB,
    ) or bool(request.content.blobUrl)


def _load_and_extract(
    request: EvaluateRequest,
    correlation_id: str,
    settings,
    doc_metadata: dict,
) -> Tuple[str, dict, bool, bool]:
    """Download and extract text from a referenced blob. Returns
    (text, merged_metadata, too_large, extraction_ok)."""
    try:
        payload = BlobLoader(settings).load(request.content.blobUrl)
    except BlobLoadError:
        log_event(
            logger, logging.WARNING, "Blob load failed",
            correlation_id=correlation_id,
        )
        return request.content.text or "", doc_metadata, False, False

    merged = dict(payload.metadata or {})
    merged.update(doc_metadata)  # request-supplied metadata wins

    if payload.too_large:
        return request.content.text or "", merged, True, False

    result = extract(
        payload.content,
        content_type=payload.content_type or request.content.contentType,
        file_name=request.content.fileName,
        max_decompressed_bytes=settings.max_decompressed_bytes,
        max_text_chars=settings.max_prompt_chars,
    )
    merged.update(result.metadata or {})
    text = result.text or request.content.text or ""
    return text, merged, False, result.extraction_complete


def _run_pii(
    settings, text: str, want_redacted: bool
) -> Tuple[List[PiiFinding], Optional[str], bool]:
    result = AzureLanguageClient(settings).detect_pii(
        text, want_redacted=want_redacted
    )
    findings = [
        PiiFinding(
            category=e.category,
            family=e.family,
            confidence=e.confidence,
            offset=e.offset,
            length=e.length,
        )
        for e in result.entities
    ]
    return findings, result.redacted_text, result.succeeded


def _run_content_safety(
    settings, text: str
) -> Tuple[List[ContentSafetyFinding], bool]:
    result = ContentSafetyClient(settings).analyze(text)
    findings = [
        ContentSafetyFinding(category=f.category, severity=f.severity)
        for f in result.findings
    ]
    return findings, result.succeeded


def _resolve_label(settings, request: EvaluateRequest, doc_metadata: dict) -> Classification:
    # Prefer explicit label from content metadata / headers, then Graph lookup.
    raw = extract_label_from_metadata(doc_metadata)
    if not raw:
        raw = extract_label_from_metadata(request.content.metadata or {})

    label_id = None
    for key in ("x-purview-label-id", "purviewlabelid"):
        candidate = {str(k).lower(): v for k, v in (doc_metadata or {}).items()}.get(key)
        if candidate:
            label_id = str(candidate)
            break

    if settings.enable_graph_label_lookup and label_id:
        graph = GraphLabelClient(settings)
        label = graph.get_label(label_id)
        if label and label.name:
            raw = label.name

    return normalize_label(raw)


def _run_purview(settings, doc_metadata: dict) -> Tuple[Optional[PurviewFindings], bool]:
    meta = {str(k).lower(): v for k, v in (doc_metadata or {}).items()}
    guid = meta.get("purviewguid") or meta.get("assetguid")
    qualified_name = meta.get("qualifiedname")
    name = meta.get("assetname")
    keyword = meta.get("keyword")

    if not any([guid, qualified_name, name, keyword]):
        return None, True

    result = PurviewDataMapClient(settings).lookup(
        guid=str(guid) if guid else None,
        qualified_name=str(qualified_name) if qualified_name else None,
        name=str(name) if name else None,
        keyword=str(keyword) if keyword else None,
    )
    if not result.succeeded:
        return PurviewFindings(lookupSucceeded=False), False
    if result.asset is None:
        return PurviewFindings(lookupSucceeded=True), True

    asset = result.asset
    return PurviewFindings(
        classifications=asset.classifications,
        labels=asset.labels,
        glossaryTerms=asset.glossary_terms,
        businessMetadata=asset.business_metadata,
        collection=asset.collection,
        owner=asset.owner,
        assetType=asset.asset_type,
        assetGuid=asset.guid,
        qualifiedName=asset.qualified_name,
        lookupSucceeded=True,
    ), True


def _run_atlas(settings, doc_metadata: dict) -> Tuple[Optional[AtlasFindings], bool]:
    meta = {str(k).lower(): v for k, v in (doc_metadata or {}).items()}
    guid = meta.get("purviewguid") or meta.get("assetguid")
    keyword = meta.get("qualifiedname") or meta.get("assetname") or meta.get("keyword")

    if not guid and not keyword:
        return None, True

    client = AtlasClient(settings)
    result = client.get_entity(str(guid)) if guid else client.search(str(keyword))
    if not result.succeeded:
        return AtlasFindings(lookupSucceeded=False), False
    if result.entity is None:
        return AtlasFindings(
            lineageAvailable=result.lineage_available, lookupSucceeded=True
        ), True

    entity = result.entity
    return AtlasFindings(
        classifications=entity.classifications,
        labels=entity.labels,
        businessMetadata=entity.business_metadata,
        lineageAvailable=result.lineage_available,
        lookupSucceeded=True,
    ), True


def _error_response(
    settings,
    correlation_id: Optional[str],
    started: float,
    reason: str,
) -> func.HttpResponse:
    """Return a safe, minimal error response using the configured fail action.

    Never exposes raw exception details to APIM.
    """
    action = _fail_action_for_error(settings)
    latency_ms = int((time.perf_counter() - started) * 1000)
    response = EvaluateResponse(
        correlationId=correlation_id,
        action=action,
        classification=Classification.UNKNOWN,
        riskScore=0,
        policyVersion=settings.policy_version,
        reasonCodes=[RC_DEPENDENCY_FAILURE, reason],
        findings=Findings(),
        redactedText=None,
        audit=AuditInfo(
            inspected=False,
            inspectionMode="synchronous",
            contentStored=False,
            inspectionComplete=False,
            latencyMs=latency_ms,
        ),
    )
    # HTTP 200 with an actionable decision keeps the APIM contract simple;
    # APIM enforces Block/Review based on the returned action.
    return func.HttpResponse(
        response.model_dump_json(),
        status_code=200,
        mimetype="application/json",
    )


def _fail_action_for_error(settings) -> Action:
    configured = (settings.default_action_on_error or "Review").strip()
    try:
        return Action(configured)
    except ValueError:
        return Action.REVIEW
