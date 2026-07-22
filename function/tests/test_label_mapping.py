"""Tests for sensitivity-label normalization and category mapping."""

import pytest

from src.config import PiiFamily, classify_pii_category
from src.models import Classification
from src.policy.label_mapping import (
    extract_label_from_metadata,
    normalize_label,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Public", Classification.PUBLIC),
        ("public", Classification.PUBLIC),
        ("Internal", Classification.INTERNAL),
        ("General", Classification.INTERNAL),
        ("Confidential", Classification.CONFIDENTIAL),
        ("Company Confidential", Classification.CONFIDENTIAL),
        ("Highly Confidential", Classification.HIGHLY_CONFIDENTIAL),
        ("Highly-Confidential", Classification.HIGHLY_CONFIDENTIAL),
        ("Restricted", Classification.HIGHLY_CONFIDENTIAL),
        ("Regulated", Classification.REGULATED),
        ("PCI", Classification.REGULATED),
        ("PHI", Classification.REGULATED),
    ],
)
def test_normalize_known_labels(raw, expected):
    assert normalize_label(raw) == expected


def test_normalize_unknown_label():
    assert normalize_label("PurpleMonkey") == Classification.UNKNOWN


def test_normalize_empty_label():
    assert normalize_label("") == Classification.UNKNOWN
    assert normalize_label(None) == Classification.UNKNOWN


def test_substring_fallback():
    assert normalize_label("ACME - Highly Confidential") == (
        Classification.HIGHLY_CONFIDENTIAL
    )


def test_extract_label_from_metadata_prefers_known_keys():
    metadata = {
        "irrelevant": "x",
        "x-data-classification": "Confidential",
    }
    assert extract_label_from_metadata(metadata) == "Confidential"


def test_extract_label_from_metadata_case_insensitive():
    metadata = {"X-MS-Sensitivity-Label": "Regulated"}
    assert extract_label_from_metadata(metadata) == "Regulated"


def test_extract_label_from_metadata_none():
    assert extract_label_from_metadata({}) is None
    assert extract_label_from_metadata({"foo": "bar"}) is None


@pytest.mark.parametrize(
    "category,family",
    [
        ("USSocialSecurityNumber", PiiFamily.SSN),
        ("CreditCardNumber", PiiFamily.CREDIT_CARD),
        ("InternationalBankingAccountNumber", PiiFamily.BANK_ACCOUNT),
        ("ABARoutingNumber", PiiFamily.BANK_ACCOUNT),
        ("USIndividualTaxpayerIdentification", PiiFamily.TAX_ID),
        ("USUKPassportNumber", PiiFamily.PASSPORT),
        ("USDriversLicenseNumber", PiiFamily.DRIVER_LICENSE),
        ("Email", PiiFamily.EMAIL),
        ("PhoneNumber", PiiFamily.PHONE),
        ("Address", PiiFamily.ADDRESS),
        ("Person", PiiFamily.PERSON),
        ("Organization", PiiFamily.OTHER),
    ],
)
def test_classify_pii_category(category, family):
    assert classify_pii_category(category) == family
