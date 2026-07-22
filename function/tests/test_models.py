"""Tests for pydantic request/response models and the API contract."""

import json

from src.models import (
    Action,
    Classification,
    ContentType,
    EvaluateRequest,
    EvaluateResponse,
    Findings,
    PiiFinding,
    PurviewFindings,
)


def test_minimal_request_uses_defaults():
    request = EvaluateRequest.model_validate({"correlationId": "abc"})
    assert request.correlationId == "abc"
    assert request.content.type == ContentType.PROMPT
    assert request.options.lookupPurview is True
    assert request.user.groups == []


def test_full_request_parses():
    payload = {
        "correlationId": "c1",
        "requestId": "r1",
        "user": {"id": "u1", "upn": "u@x.com", "groups": ["g1"], "claims": {"a": 1}},
        "source": {
            "application": "app",
            "apimSubscriptionId": "sub",
            "operation": "op",
            "requestPath": "/chat",
            "model": "gpt-4o",
        },
        "content": {
            "type": "prompt",
            "text": "hello",
            "metadata": {"x-data-classification": "Confidential"},
        },
        "options": {"returnRedactedText": True, "runPiiDetection": True},
    }
    request = EvaluateRequest.model_validate(payload)
    assert request.source.model == "gpt-4o"
    assert request.content.metadata["x-data-classification"] == "Confidential"
    assert request.options.returnRedactedText is True


def test_extra_fields_ignored():
    request = EvaluateRequest.model_validate(
        {"correlationId": "c", "unexpected": "field"}
    )
    assert request.correlationId == "c"


def test_response_serializes_contract():
    response = EvaluateResponse(
        correlationId="c1",
        action=Action.BLOCK,
        classification=Classification.HIGHLY_CONFIDENTIAL,
        riskScore=95,
        policyVersion="2026-07-01",
        reasonCodes=["PII_BLOCK_SSN"],
        findings=Findings(
            pii=[
                PiiFinding(
                    category="USSocialSecurityNumber",
                    family="ssn",
                    confidence=0.98,
                )
            ],
            purview=PurviewFindings(classifications=["Regulated"]),
        ),
    )
    data = json.loads(response.model_dump_json())
    assert data["action"] == "Block"
    assert data["classification"] == "HighlyConfidential"
    assert data["riskScore"] == 95
    assert data["findings"]["pii"][0]["category"] == "USSocialSecurityNumber"
    assert data["findings"]["purview"]["classifications"] == ["Regulated"]
    assert data["redactedText"] is None


def test_response_defaults_are_safe():
    response = EvaluateResponse()
    assert response.action == Action.REVIEW
    assert response.classification == Classification.UNKNOWN
    assert response.riskScore == 0
