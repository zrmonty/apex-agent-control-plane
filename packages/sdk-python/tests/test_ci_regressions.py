"""Small, deterministic tests for CI-only defensive branches.

These cases exercise malformed operator material and boundary values that are
rare in normal SDK usage but important for the coverage and fail-closed gates.
"""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from apex_sdk.bundle import (
    BundleError,
    BundleSignatureError,
    _deep_canonicalize,
    _parse_utc,
    generate_bundle_signing_key,
    load_bundle,
    load_trust_pins,
    load_trust_public_keys,
    sign_bundle,
    validate_bundle,
    verify_bundle_signature,
)
from apex_sdk.template import gold_standard_manifest


def _doc() -> dict[str, object]:
    return {
        "bundle_version": "apex-agent-bundle.v1",
        "profile": "staging",
        "agent_code": "ci-agent",
        "scope": {"workspace_id": "acme", "namespace_id": "ci"},
        "ingest_endpoint": "https://ingest.example",
        "template": gold_standard_manifest("ci-agent"),
    }


def test_canonicalizer_supports_scalars_and_rejects_objects() -> None:
    assert _deep_canonicalize({"z": [1, True, None, "x"]}) == {
        "z": [1, True, None, "x"]
    }
    with pytest.raises(BundleError, match="non-JSON"):
        _deep_canonicalize(object())


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("not-a-timestamp", "ISO-8601"),
        ("2024-02-30T00:00:00Z", "valid timestamp"),
    ],
)
def test_parse_utc_rejects_malformed_values(value: str, message: str) -> None:
    with pytest.raises(BundleSignatureError, match=message):
        _parse_utc(value, "issued_at")


def test_trust_pin_inputs_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(BundleSignatureError, match="64 lowercase"):
        load_trust_pins({"ops": "not-a-fingerprint"})
    bad = tmp_path / "bad.pins"
    bad.write_text("one-field-only\n", encoding="utf-8")
    with pytest.raises(BundleSignatureError, match="invalid line"):
        load_trust_pins(pins_file=bad)
    monkeypatch.setenv("APEX_BUNDLE_TRUST_PINS", "ops-no-colon")
    with pytest.raises(BundleSignatureError, match="key_id:fingerprint"):
        load_trust_pins()
    monkeypatch.delenv("APEX_BUNDLE_TRUST_PINS")
    monkeypatch.setenv("APEX_BUNDLE_TRUST_PINS_FILE", str(tmp_path / "missing"))
    with pytest.raises(BundleSignatureError, match="could not be read"):
        load_trust_pins()
    monkeypatch.delenv("APEX_BUNDLE_TRUST_PINS_FILE")


def test_sign_and_verify_reject_invalid_serial_and_metadata() -> None:
    keys = generate_bundle_signing_key(key_id="ops")
    with pytest.raises(BundleSignatureError, match="bundle_serial"):
        sign_bundle(_doc(), private_key_pem=keys["private_pem"], key_id="ops", bundle_serial="bad serial")
    signed = sign_bundle(_doc(), private_key_pem=keys["private_pem"], key_id="ops")
    trust = {"ops": keys["public_pem"]}
    cases = [
        ({"signing_key_fingerprint": "x" * 64}, "64 hex"),
        ({"issuer": "bad issuer"}, "safe identifier"),
        ({"bundle_serial": "bad serial"}, "bundle_serial"),
    ]
    for changes, message in cases:
        with pytest.raises(BundleSignatureError, match=message):
            verify_bundle_signature({**signed, **changes}, trust)
    with pytest.raises(BundleSignatureError, match="verification failed"):
        verify_bundle_signature(
            {
                **signed,
                "signature": base64.b64encode(b"x" * 64).decode(),
            },
            trust,
        )

    with pytest.raises(BundleSignatureError, match="not listed"):
        verify_bundle_signature(signed, trust, trust_pins={"other": signed["signing_key_fingerprint"]})
    equal_time = {**signed, "not_after": signed["issued_at"]}
    with pytest.raises(BundleSignatureError, match="after"):
        verify_bundle_signature(equal_time, trust)
    long_window = {**signed, "not_after": "2030-01-01T00:00:00Z", "issued_at": "2024-01-01T00:00:00Z"}
    with pytest.raises(BundleSignatureError, match="maximum"):
        verify_bundle_signature(long_window, trust)


def test_bundle_validation_rejects_bounded_fields_and_signature_shapes() -> None:
    for value in ("", "x" * 513, "password=secret"):
        with pytest.raises(BundleError):
            validate_bundle({**_doc(), "identity_ref": value}, require_signature=False)
    with pytest.raises(BundleError, match="fingerprint"):
        validate_bundle({**_doc(), "signing_key_fingerprint": "bad"}, require_signature=False)
    keys = generate_bundle_signing_key(key_id="ops")
    signed = sign_bundle(_doc(), private_key_pem=keys["private_pem"], key_id="ops")
    with pytest.raises(BundleError, match="bounded base64"):
        validate_bundle({**signed, "signature": ""}, require_signature=False)
    with pytest.raises(BundleError, match="control"):
        validate_bundle({**signed, "signature": "ok\x01"}, require_signature=False)


def test_load_bundle_rejects_bad_json_and_oversized_document(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(BundleError, match="valid JSON"):
        load_bundle(malformed)
    oversized = tmp_path / "large.json"
    oversized.write_text("x" * (64 * 1024 + 1), encoding="utf-8")
    with pytest.raises(BundleError, match="64 KiB"):
        load_bundle(oversized)


def test_trust_directory_rejects_unreadable_key(tmp_path: Path) -> None:
    trust = tmp_path / "trust"
    trust.mkdir()
    (trust / "ops.pem").write_bytes(b"\xff")
    with pytest.raises(BundleSignatureError, match="could not read trust key"):
        load_trust_public_keys(trust)


def test_explicit_trust_pins_can_require_only_pinned_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    keys = generate_bundle_signing_key(key_id="ops")
    monkeypatch.setenv("APEX_BUNDLE_REQUIRE_TRUST_PINS", "1")
    from apex_sdk.bundle import resolve_trust_public_keys

    assert resolve_trust_public_keys({"ops": keys["public_pem"]}, trust_pins={"other": "0" * 64}) is None
    monkeypatch.delenv("APEX_BUNDLE_REQUIRE_TRUST_PINS")
