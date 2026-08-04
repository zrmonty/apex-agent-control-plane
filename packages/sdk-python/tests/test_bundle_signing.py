"""Ed25519 signed agent bundles — anti-spoof verification before SPIFFE."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from apex_sdk.bundle import (
    BundleError,
    BundleSignatureError,
    fingerprint_public_key,
    generate_bundle_signing_key,
    load_bundle,
    load_trust_pins,
    load_trust_public_keys,
    local_development_bundle,
    sign_bundle,
    signing_transcript,
    validate_bundle,
    verify_bundle_signature,
    write_signed_bundle,
)
from apex_sdk.connect import Apex, PreflightError
from apex_sdk.template import gold_standard_manifest


def _staging_doc(**overrides):
    base = {
        "bundle_version": "apex-agent-bundle.v1",
        "profile": "staging",
        "agent_code": "staging-agent",
        "scope": {"workspace_id": "acme", "namespace_id": "stage"},
        "ingest_endpoint": "https://ingest.example.internal:8443",
        "tool_allowlist": ["reference_tool"],
        "egress_allowlist": [],
        "template": gold_standard_manifest("staging-agent"),
    }
    base.update(overrides)
    return base


def test_sign_and_verify_round_trip() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id=keys["key_id"])
    assert signed["signature_alg"] == "ed25519"
    assert signed["signing_key_id"] == "ops-1"
    assert signed["signing_key_fingerprint"] == keys["fingerprint"]
    assert signed["issuer"]
    assert signed["issued_at"]
    assert signed["not_after"]
    assert signed["bundle_serial"]
    assert signed["signature"]
    trust = {keys["key_id"]: keys["public_pem"]}
    verify_bundle_signature(signed, trust, trust_pins={keys["key_id"]: keys["fingerprint"]})
    validated = validate_bundle(
        signed, trust_public_keys=trust, trust_pins={keys["key_id"]: keys["fingerprint"]}
    )
    assert validated["agent_code"] == "staging-agent"


def test_tampered_payload_fails_verify() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    signed["agent_code"] = "evil-agent"
    with pytest.raises(BundleSignatureError, match="verification failed|signature"):
        verify_bundle_signature(signed, {"ops-1": keys["public_pem"]})


def test_fingerprint_mismatch_blocks_key_substitution() -> None:
    """Attacker with a second trusted key cannot re-bind an existing signature."""
    a = generate_bundle_signing_key(key_id="a")
    b = generate_bundle_signing_key(key_id="b")
    signed = sign_bundle(_staging_doc(), private_key_pem=a["private_pem"], key_id="a")
    # Swap trust PEM under same key_id — fingerprint binding must fail.
    with pytest.raises(BundleSignatureError, match="fingerprint|trusted"):
        verify_bundle_signature(signed, {"a": b["public_pem"]})
    # Change key_id to b without re-signing — fingerprint won't match b either
    # once we point trust at b, and signature fails with a's key if we keep a.
    spoofed = {**signed, "signing_key_id": "b"}
    with pytest.raises(BundleSignatureError):
        verify_bundle_signature(spoofed, {"a": a["public_pem"], "b": b["public_pem"]})


def test_attacker_signed_bundle_rejected_without_trust() -> None:
    attacker = generate_bundle_signing_key(key_id="ops-1")  # same key_id, different key
    operator = generate_bundle_signing_key(key_id="ops-1")
    forged = sign_bundle(_staging_doc(), private_key_pem=attacker["private_pem"], key_id="ops-1")
    with pytest.raises(BundleSignatureError):
        verify_bundle_signature(forged, {"ops-1": operator["public_pem"]})


def test_trust_pins_ignore_dropped_pem(tmp_path: Path) -> None:
    """Extra PEMs in the trust dir must not expand the trust set when pins exist."""
    operator = generate_bundle_signing_key(key_id="ops-1")
    attacker = generate_bundle_signing_key(key_id="attacker")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(operator["public_pem"], encoding="ascii")
    (trust_dir / "attacker.pem").write_text(attacker["public_pem"], encoding="ascii")
    (trust_dir / "trust.pins").write_text(f"ops-1 {operator['fingerprint']}\n", encoding="utf-8")
    loaded = load_trust_public_keys(trust_dir)
    assert set(loaded) == {"ops-1"}
    forged = sign_bundle(_staging_doc(), private_key_pem=attacker["private_pem"], key_id="attacker")
    with pytest.raises(BundleSignatureError, match="not in the trust|pins"):
        validate_bundle(forged, trust_public_keys=loaded)


def test_trust_pin_mismatch_rejects_substituted_pem(tmp_path: Path) -> None:
    operator = generate_bundle_signing_key(key_id="ops-1")
    attacker = generate_bundle_signing_key(key_id="ops-1")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(attacker["public_pem"], encoding="ascii")
    (trust_dir / "trust.pins").write_text(f"ops-1:{operator['fingerprint']}\n", encoding="utf-8")
    with pytest.raises(BundleSignatureError, match="pin|does not match"):
        load_trust_public_keys(trust_dir)


def test_expired_bundle_rejected() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    past = datetime(2020, 1, 1, tzinfo=UTC)
    signed = sign_bundle(
        _staging_doc(),
        private_key_pem=keys["private_pem"],
        key_id="ops-1",
        issued_at=past,
        validity=timedelta(days=1),
    )
    with pytest.raises(BundleSignatureError, match="expired"):
        verify_bundle_signature(
            signed,
            {"ops-1": keys["public_pem"]},
            now=datetime(2020, 1, 10, tzinfo=UTC),
        )


def test_canonical_reorder_does_not_break_signature() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    # Re-serialize with different key order
    reordered = json.loads(json.dumps(signed, sort_keys=False))
    verify_bundle_signature(reordered, {"ops-1": keys["public_pem"]})


def test_domain_separation_transcript_differs_from_raw_json() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    transcript = signing_transcript(signed)
    assert transcript.startswith(b"APEX-AGENT-BUNDLE-V1\ned25519\n")
    assert len(transcript) == len(b"APEX-AGENT-BUNDLE-V1\ned25519\n") + 32


def test_partial_signature_metadata_rejected() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    incomplete = {**signed}
    del incomplete["not_after"]
    with pytest.raises(BundleSignatureError, match="incomplete"):
        validate_bundle(incomplete, trust_public_keys={"ops-1": keys["public_pem"]})


def test_production_cannot_disable_signature() -> None:
    doc = {
        **_staging_doc(),
        "profile": "production",
        "trust_bundle_path": "/etc/apex/ca.pem",
    }
    with pytest.raises(BundleSignatureError, match="cannot disable"):
        validate_bundle(doc, require_signature=False)


def test_staging_requires_signature_and_trust_keys() -> None:
    with pytest.raises(BundleSignatureError):
        validate_bundle(_staging_doc())
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    with pytest.raises(BundleSignatureError, match="trust"):
        validate_bundle(signed)


def test_wrong_key_rejected() -> None:
    a = generate_bundle_signing_key(key_id="a")
    b = generate_bundle_signing_key(key_id="b")
    signed = sign_bundle(_staging_doc(), private_key_pem=a["private_pem"], key_id="a")
    with pytest.raises(BundleSignatureError):
        verify_bundle_signature(signed, {"a": b["public_pem"]})


def test_load_bundle_with_trust_dir(tmp_path: Path) -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(keys["public_pem"], encoding="ascii")
    (trust_dir / "trust.pins").write_text(f"ops-1={keys['fingerprint']}\n", encoding="utf-8")
    path = tmp_path / "apex-agent.yaml"
    write_signed_bundle(
        path,
        _staging_doc(),
        private_key_pem=keys["private_pem"],
        key_id="ops-1",
    )
    loaded = load_bundle(path, base_dir=tmp_path, trust_keys_dir=trust_dir)
    assert loaded["signature"]
    assert loaded["signing_key_fingerprint"] == keys["fingerprint"]
    assert load_trust_public_keys(trust_dir)["ops-1"].startswith("-----BEGIN")


def test_connect_signed_staging(tmp_path: Path) -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(keys["public_pem"], encoding="ascii")
    path = tmp_path / "bundle.json"
    write_signed_bundle(
        path,
        _staging_doc(),
        private_key_pem=keys["private_pem"],
        key_id="ops-1",
    )
    client = Apex.connect(
        bundle_path=path,
        base_dir=tmp_path,
        allow_local_profile=False,
        bundle_trust_keys_dir=trust_dir,
        bundle_trust_pins={keys["key_id"]: keys["fingerprint"]},
        trace_dir=tmp_path / "trace",
    )
    assert client.preflight.ready
    assert client.bundle["signing_key_id"] == "ops-1"
    assert client.bundle["signing_key_fingerprint"] == keys["fingerprint"]


def test_connect_unsigned_staging_fails(tmp_path: Path) -> None:
    path = tmp_path / "unsigned.json"
    path.write_text(json.dumps(_staging_doc()), encoding="utf-8")
    with pytest.raises((BundleSignatureError, BundleError, PreflightError)):
        Apex.connect(bundle_path=path, base_dir=tmp_path, allow_local_profile=False)


def test_local_development_unsigned_ok() -> None:
    bundle = local_development_bundle(agent_code="home")
    assert "signature" not in bundle or bundle.get("signature") is None
    assert validate_bundle(bundle, require_signature=False)["profile"] == "local-development"


def test_signed_local_optional_verify(tmp_path: Path) -> None:
    keys = generate_bundle_signing_key(key_id="dev")
    local = local_development_bundle(agent_code="home")
    signed = sign_bundle(local, private_key_pem=keys["private_pem"], key_id="dev")
    validate_bundle(signed, require_signature=False, trust_public_keys={"dev": keys["public_pem"]})


def test_signature_field_validation_errors() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    trust = {"ops-1": keys["public_pem"]}
    bad = {**signed, "signature_alg": "rsa"}
    with pytest.raises((BundleError, BundleSignatureError), match="ed25519"):
        validate_bundle(bad, require_signature=False, trust_public_keys=trust)
    with pytest.raises(BundleSignatureError):
        verify_bundle_signature({**signed, "signature_alg": "rsa"}, trust)
    with pytest.raises(BundleSignatureError, match="incomplete|required"):
        verify_bundle_signature(local_development_bundle(agent_code="x"), trust)
    with pytest.raises(BundleSignatureError, match="safe identifier|signing_key"):
        verify_bundle_signature({**signed, "signing_key_id": "bad id"}, trust)
    with pytest.raises(BundleSignatureError, match="base64|non-empty|incomplete"):
        verify_bundle_signature({**signed, "signature": ""}, trust)
    with pytest.raises(BundleSignatureError, match="not in the trust"):
        verify_bundle_signature(signed, {"other": keys["public_pem"]})
    with pytest.raises(BundleSignatureError, match="base64"):
        verify_bundle_signature({**signed, "signature": "@@@not-b64!!!"}, trust)
    with pytest.raises(BundleSignatureError, match="length"):
        verify_bundle_signature(
            {**signed, "signature": base64.b64encode(b"short").decode("ascii")},
            trust,
        )


def test_trust_dir_edge_cases(tmp_path: Path) -> None:
    with pytest.raises(BundleSignatureError, match="not available"):
        load_trust_public_keys(tmp_path / "missing")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(BundleSignatureError, match="no usable"):
        load_trust_public_keys(empty)
    keys = generate_bundle_signing_key(key_id="ops-1")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "not-safe id.pem").write_text(keys["public_pem"], encoding="ascii")
    (trust_dir / "ops-1.pem").write_text(keys["public_pem"], encoding="ascii")
    (trust_dir / "readme.txt").write_text("ignore", encoding="utf-8")
    loaded = load_trust_public_keys(trust_dir)
    assert "ops-1" in loaded
    from apex_sdk.bundle import resolve_trust_public_keys

    assert len(fingerprint_public_key(keys["public_pem"])) == 64
    merged = resolve_trust_public_keys({"extra": keys["public_pem"]}, trust_keys_dir=trust_dir)
    assert "ops-1" in merged and "extra" in merged
    pins = load_trust_pins({"ops-1": keys["fingerprint"]})
    assert pins["ops-1"] == keys["fingerprint"]


def test_env_trust_keys_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = generate_bundle_signing_key(key_id="env-key")
    trust_dir = tmp_path / "env-trust"
    trust_dir.mkdir()
    (trust_dir / "env-key.pem").write_text(keys["public_pem"], encoding="ascii")
    monkeypatch.setenv("APEX_BUNDLE_TRUST_KEYS_DIR", str(trust_dir))
    monkeypatch.setenv("APEX_BUNDLE_TRUST_PINS", f"env-key:{keys['fingerprint']}")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="env-key")
    path = tmp_path / "b.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    loaded = load_bundle(path, base_dir=tmp_path)
    assert loaded["signing_key_id"] == "env-key"


def test_reject_non_ed25519_keys() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from apex_sdk.bundle import _load_private_key, _load_public_key

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(BundleSignatureError, match="Ed25519"):
        _load_private_key(priv_pem)
    with pytest.raises(BundleSignatureError, match="Ed25519"):
        _load_public_key(pub_pem)


def test_connect_signed_production_requires_trust_bundle_path(tmp_path: Path) -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(keys["public_pem"], encoding="ascii")
    (trust_dir / "trust.pins").write_text(
        f"ops-1={keys['fingerprint']}\n", encoding="ascii"
    )
    doc = {
        **_staging_doc(),
        "profile": "production",
        "agent_code": "prod-agent",
        "template": gold_standard_manifest("prod-agent"),
    }
    path = tmp_path / "prod.json"
    write_signed_bundle(path, doc, private_key_pem=keys["private_pem"], key_id="ops-1")
    with pytest.raises(PreflightError, match="blocked|trust bundle"):
        Apex.connect(
            bundle_path=path,
            base_dir=tmp_path,
            allow_local_profile=False,
            bundle_trust_keys_dir=trust_dir,
        )


def test_connect_signed_staging_missing_endpoint(tmp_path: Path) -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    trust = {keys["key_id"]: keys["public_pem"]}
    doc = _staging_doc()
    del doc["ingest_endpoint"]
    signed = sign_bundle(doc, private_key_pem=keys["private_pem"], key_id="ops-1")
    path = tmp_path / "stage.json"
    path.write_text(json.dumps(signed), encoding="utf-8")
    with pytest.raises(PreflightError, match="blocked|ingest"):
        Apex.connect(
            bundle_path=path,
            base_dir=tmp_path,
            allow_local_profile=False,
            bundle_trust_keys=trust,
        )


def test_signature_over_detached_only_covers_key_id() -> None:
    """Mutating signing_key_id (now inside signed payload) invalidates signature."""
    keys = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=keys["private_pem"], key_id="ops-1")
    # Even with same fingerprint, changing key_id without resigning fails.
    other = generate_bundle_signing_key(key_id="ops-2")
    # Force same fingerprint into wrong key_id path is impossible without private key;
    # just flip key_id string.
    mutated = {**signed, "signing_key_id": "ops-2"}
    with pytest.raises(BundleSignatureError):
        verify_bundle_signature(
            mutated,
            {"ops-1": keys["public_pem"], "ops-2": other["public_pem"]},
        )


def test_pins_file_and_env_require_pins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    pins_file = tmp_path / "pins.txt"
    pins_file.write_text(f"# comment\nops-1:sha256:{keys['fingerprint']}\n", encoding="utf-8")
    assert load_trust_pins(pins_file=pins_file)["ops-1"] == keys["fingerprint"]
    with pytest.raises(BundleSignatureError):
        load_trust_pins(pins_file=tmp_path / "missing.pins")
    monkeypatch.setenv("APEX_BUNDLE_REQUIRE_TRUST_PINS", "true")
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "ops-1.pem").write_text(keys["public_pem"], encoding="ascii")
    with pytest.raises(BundleSignatureError, match="pins are required"):
        load_trust_public_keys(trust_dir)
    monkeypatch.delenv("APEX_BUNDLE_REQUIRE_TRUST_PINS", raising=False)


def test_invalid_validity_and_future_issued() -> None:
    keys = generate_bundle_signing_key(key_id="ops-1")
    with pytest.raises(BundleSignatureError, match="validity|not_after"):
        sign_bundle(
            _staging_doc(),
            private_key_pem=keys["private_pem"],
            key_id="ops-1",
            validity=timedelta(days=0),
        )
    with pytest.raises(BundleSignatureError, match="validity"):
        sign_bundle(
            _staging_doc(),
            private_key_pem=keys["private_pem"],
            key_id="ops-1",
            validity=timedelta(days=500),
        )
    # Sign with a future clock (allowed at sign time), then verify with present clock.
    future = datetime.now(UTC) + timedelta(days=30)
    future_signed = sign_bundle(
        _staging_doc(),
        private_key_pem=keys["private_pem"],
        key_id="ops-1",
        issued_at=future,
        validity=timedelta(days=1),
    )
    with pytest.raises(BundleSignatureError, match="future"):
        verify_bundle_signature(
            future_signed,
            {"ops-1": keys["public_pem"]},
            now=datetime.now(UTC),
        )


def test_fingerprint_helpers() -> None:
    from apex_sdk.bundle import fingerprint_private_key

    keys = generate_bundle_signing_key(key_id="ops-1")
    assert fingerprint_private_key(keys["private_pem"]) == keys["fingerprint"]
    assert fingerprint_public_key(keys["public_pem"]) == keys["fingerprint"]


def test_pin_mismatch_on_explicit_keys() -> None:
    a = generate_bundle_signing_key(key_id="ops-1")
    b = generate_bundle_signing_key(key_id="ops-1")
    signed = sign_bundle(_staging_doc(), private_key_pem=a["private_pem"], key_id="ops-1")
    with pytest.raises(BundleSignatureError, match="pin"):
        from apex_sdk.bundle import resolve_trust_public_keys

        resolve_trust_public_keys(
            {"ops-1": a["public_pem"]},
            trust_pins={"ops-1": b["fingerprint"]},
        )
    with pytest.raises(BundleSignatureError, match="pin"):
        verify_bundle_signature(
            signed,
            {"ops-1": a["public_pem"]},
            trust_pins={"ops-1": b["fingerprint"]},
        )
