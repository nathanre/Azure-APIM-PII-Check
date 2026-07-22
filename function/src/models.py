"""Pydantic models for the /api/evaluate request and response contract.

These models validate the JSON contract exchanged with Azure API Management.
They intentionally use ``extra="ignore"`` on inbound models so that additional
fields sent by APIM do not cause validation failures.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# --- Enumerations ------------------------------------------------------------

class Action(str, Enum):
    ALLOW = "Allow"
    WARN = "Warn"
    REDACT = "Redact"
    BLOCK = "Block"
    REVIEW = "Review"


class Classification(str, Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    HIGHLY_CONFIDENTIAL = "HighlyConfidential"
    REGULATED = "Regulated"
    UNKNOWN = "Unknown"


class ContentType(str, Enum):
    PROMPT = "prompt"
    DOCUMENT = "document"
    BLOB = "blob"
    JSON = "json"


# --- Request models ----------------------------------------------------------

class UserContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[str] = None
    upn: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    claims: Dict[str, Any] = Field(default_factory=dict)


class SourceContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    application: Optional[str] = None
    apimSubscriptionId: Optional[str] = None
    operation: Optional[str] = None
    requestPath: Optional[str] = None
    model: Optional[str] = None


class ContentPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    type: ContentType = ContentType.PROMPT
    text: Optional[str] = None
    blobUrl: Optional[str] = None
    fileName: Optional[str] = None
    contentType: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvaluateOptions(BaseModel):
    model_config = ConfigDict(extra="ignore")

    returnRedactedText: bool = False
    lookupPurview: bool = True
    lookupAtlas: bool = True
    runContentSafety: bool = True
    runPiiDetection: bool = True


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    correlationId: Optional[str] = None
    requestId: Optional[str] = None
    user: UserContext = Field(default_factory=UserContext)
    source: SourceContext = Field(default_factory=SourceContext)
    content: ContentPayload = Field(default_factory=ContentPayload)
    options: EvaluateOptions = Field(default_factory=EvaluateOptions)


# --- Finding models ----------------------------------------------------------

class PiiFinding(BaseModel):
    category: str
    family: str
    confidence: float
    offset: Optional[int] = None
    length: Optional[int] = None
    source: str = "AzureAILanguage"


class ContentSafetyFinding(BaseModel):
    category: str
    severity: int
    source: str = "AzureAIContentSafety"


class PurviewFindings(BaseModel):
    classifications: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    glossaryTerms: List[str] = Field(default_factory=list)
    businessMetadata: Dict[str, Any] = Field(default_factory=dict)
    collection: Optional[str] = None
    owner: Optional[str] = None
    assetType: Optional[str] = None
    assetGuid: Optional[str] = None
    qualifiedName: Optional[str] = None
    lookupSucceeded: bool = True


class AtlasFindings(BaseModel):
    classifications: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    businessMetadata: Dict[str, Any] = Field(default_factory=dict)
    lineageAvailable: bool = False
    lookupSucceeded: bool = True


class Findings(BaseModel):
    pii: List[PiiFinding] = Field(default_factory=list)
    contentSafety: List[ContentSafetyFinding] = Field(default_factory=list)
    purview: Optional[PurviewFindings] = None
    atlas: Optional[AtlasFindings] = None


class AuditInfo(BaseModel):
    inspected: bool = False
    inspectionMode: str = "synchronous"
    contentStored: bool = False
    inspectionComplete: bool = True
    latencyMs: int = 0


# --- Response model ----------------------------------------------------------

class EvaluateResponse(BaseModel):
    correlationId: Optional[str] = None
    action: Action = Action.REVIEW
    classification: Classification = Classification.UNKNOWN
    riskScore: int = 0
    policyVersion: str = ""
    reasonCodes: List[str] = Field(default_factory=list)
    findings: Findings = Field(default_factory=Findings)
    redactedText: Optional[str] = None
    audit: AuditInfo = Field(default_factory=AuditInfo)
