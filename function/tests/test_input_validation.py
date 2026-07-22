"""Tests for input-validation guards (SSRF allowlist, identifier injection)."""

import pytest

from src.utils.validation import (
    ValidationError,
    host_of,
    safe_identifier,
    validate_blob_host,
)


# --- safe_identifier ---------------------------------------------------------

def test_safe_identifier_accepts_uuid():
    guid = "12345678-1234-1234-1234-123456789abc"
    assert safe_identifier(guid) == guid


def test_safe_identifier_encodes_allowed_chars():
    assert safe_identifier("ns:type.name-1") == "ns%3Atype.name-1"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "../../etc/passwd",
        "abc/def",
        "abc?x=1",
        "abc#frag",
        "abc def",
        "a" * 201,
        "abc%2e%2e",
        "..",
    ],
)
def test_safe_identifier_rejects_injection(bad):
    with pytest.raises(ValidationError):
        safe_identifier(bad)


# --- validate_blob_host ------------------------------------------------------

def test_blob_host_trusted_suffix_allowed():
    validate_blob_host("myacct.blob.core.windows.net")  # no exception


def test_blob_host_untrusted_rejected():
    with pytest.raises(ValidationError):
        validate_blob_host("attacker.example.com")


def test_blob_host_allowlist_exact_match():
    validate_blob_host(
        "only.blob.core.windows.net",
        allowed_hosts=["only.blob.core.windows.net"],
    )


def test_blob_host_allowlist_rejects_others():
    with pytest.raises(ValidationError):
        validate_blob_host(
            "other.blob.core.windows.net",
            allowed_hosts=["only.blob.core.windows.net"],
        )


def test_blob_host_account_host_match():
    validate_blob_host(
        "acct.blob.core.windows.net",
        account_host="acct.blob.core.windows.net",
    )


def test_blob_host_account_host_mismatch_rejected():
    with pytest.raises(ValidationError):
        validate_blob_host(
            "evil.blob.core.windows.net",
            account_host="acct.blob.core.windows.net",
        )


def test_blob_host_empty_rejected():
    with pytest.raises(ValidationError):
        validate_blob_host("")


def test_host_of_extracts_netloc():
    assert host_of("https://acct.blob.core.windows.net/c/b.pdf") == (
        "acct.blob.core.windows.net"
    )
