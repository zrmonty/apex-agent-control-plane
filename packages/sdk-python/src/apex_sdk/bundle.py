"""Local enrollment / integration bundle loading (non-secret material only).

Anti-spoofing model
-------------------
Staging/production bundles are operator-issued artifacts. Spoofing is resisted by:

1. **Ed25519 only** — no algorithm agility / confusion.
2. **Domain-separated signatures** — sign a fixed context string plus SHA-256 of
   the canonical JSON payload (not bare JSON), so signatures cannot be replayed
   across protocols or formats.
3. **Detached signature only** — solely ``signature`` is outside the signed
   payload; ``signing_key_id``, algorithm, fingerprint, issuer, times, and serial
   are all covered by the signature.
4. **Key fingerprint binding** — the signed payload embeds the SHA-256 of the
   Ed25519 raw public key; verification requires the trust-store key's fingerprint
   to match (constant-time), so a wrong/replaced PEM cannot validate even if
   ``signing_key_id`` collides.
5. **Trust store is operator-provisioned only** — public keys never come from the
   bundle. Optional **trust pins** (key_id → fingerprint) reject unexpected PEMs
   even if someone can drop files into the trust directory.
6. **Validity window** — ``issued_at`` / ``not_after`` bound reuse of a stolen
   signed file.
7. **Fail closed** — production never skips verification; any present signature
   must verify; incomplete signature metadata is rejected.

Private signing keys never appear in bundles. Trust is established out-of-band
(APEX_BUNDLE_TRUST_KEYS_DIR, trust pins, or explicit PEMs in process config).

Ed25519 key handling, the signing transcript, trust-pin/trust-directory
loading, and ``verify_bundle_signature`` itself live in ``_bundle_trust.py``
-- the cryptographic and trust-store layer this module's ``validate_bundle``,
``sign_bundle``, and ``load_bundle`` build on. That module has no dependency
on the document-shape validation or file I/O here, so it was split out on its
own; everything this module needs from it is re-imported below, so
``apex_sdk.bundle.X`` continues to resolve exactly as it did before the split.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from ._bundle_trust import (
    SIGNATURE_ALG,
    BundleError,
    BundleSignatureError,
    _cryptography,
    _deep_canonicalize,
    _FINGERPRINT_HEX,
    _format_utc,
    _load_private_key,
    _load_public_key,
    _MAX_VALIDITY,
    _parse_utc,
    _require_id,
    _DETACHED_FIELDS,
    fingerprint_private_key,
    fingerprint_public_key,
    generate_bundle_signing_key,
    load_trust_pins,
    load_trust_public_keys,
    resolve_trust_public_keys,
    signing_transcript,
    verify_bundle_signature,
)
from .validation import SAFE_IDENTIFIER

BUNDLE_VERSION = "apex-agent-bundle.v1"
_SIGNATURE_META_FIELDS = frozenset(
    {
        "signature",
        "signature_alg",
        "signing_key_id",
        "signing_key_fingerprint",
        "issuer",
        "issued_at",
        "not_after",
        "bundle_serial",
    }
)
_ALLOWED_FIELDS = frozenset(
    {
        "bundle_version",
        "profile",
        "agent_code",
        "scope",
        "ingest_endpoint",
        "trust_bundle_path",
        "identity_ref",
        "template",
        "policy_revision",
        "tool_allowlist",
        "egress_allowlist",
        "signature",
        "signature_alg",
        "signing_key_id",
        "signing_key_fingerprint",
        "issuer",
        "issued_at",
        "not_after",
        "bundle_serial",
    }
)
_PROFILES = frozenset({"local-development", "staging", "production"})
# Default validity for newly signed bundles.
_DEFAULT_VALIDITY = timedelta(days=90)


def sign_bundle(
    document: Mapping[str, Any],
    *,
    private_key_pem: str | bytes,
    key_id: str,
    issuer: str = "apex-operator",
    validity: timedelta | None = None,
    issued_at: datetime | None = None,
    bundle_serial: str | None = None,
) -> dict[str, Any]:
    """Validate, bind anti-spoofing metadata, sign, and return the full document."""
    _require_id(key_id, "signing_key_id")
    _require_id(issuer, "issuer")
    if validity is None:
        validity = _DEFAULT_VALIDITY
    if validity <= timedelta(0) or validity > _MAX_VALIDITY:
        raise BundleSignatureError("bundle validity window is out of allowed range")

    unsigned = {k: v for k, v in document.items() if k not in _SIGNATURE_META_FIELDS}
    # Content-only validation (no signature yet).
    validated = validate_bundle(
        unsigned,
        require_signature=False,
        trust_public_keys=None,
        allow_unsigned_local=True,
    )
    private = _load_private_key(private_key_pem)
    fp = hashlib.sha256(private.public_key().public_bytes_raw()).hexdigest()
    now = (issued_at or datetime.now(UTC)).astimezone(UTC)
    serial = bundle_serial or secrets.token_hex(16)
    if not SAFE_IDENTIFIER.fullmatch(serial) and not re.fullmatch(r"[0-9a-f]{16,64}", serial):
        raise BundleSignatureError("bundle_serial must be a safe identifier or hex token")

    to_sign = {
        **{k: v for k, v in validated.items() if k not in _DETACHED_FIELDS and v is not None},
        "signature_alg": SIGNATURE_ALG,
        "signing_key_id": key_id,
        "signing_key_fingerprint": fp,
        "issuer": issuer,
        "issued_at": _format_utc(now),
        "not_after": _format_utc(now + validity),
        "bundle_serial": serial,
    }
    transcript = signing_transcript(to_sign)
    signature = private.sign(transcript)
    signed = {
        **to_sign,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    # Return with verification against the issuing public key (self-check).
    pub = (
        private.public_key()
        .public_bytes(
            encoding=_cryptography()[0].Encoding.PEM,
            format=_cryptography()[0].PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return validate_bundle(
        signed,
        require_signature=True,
        trust_public_keys={key_id: pub},
        trust_pins={key_id: fp},
        now=now,
    )


def validate_bundle(
    document: Mapping[str, Any],
    *,
    require_signature: bool | None = None,
    trust_public_keys: Mapping[str, str | bytes] | None = None,
    trust_pins: Mapping[str, str] | None = None,
    now: datetime | None = None,
    allow_unsigned_local: bool = False,
) -> dict[str, Any]:
    """Validate a non-secret integration bundle and return a normalized copy.

    Staging/production always require a verified signature unless
    ``allow_unsigned_local`` is used only for intermediate signing of content
    fields. Production refuses ``require_signature=False``.
    """
    if not isinstance(document, Mapping):
        raise BundleError("bundle must be an object")
    unknown = set(document) - _ALLOWED_FIELDS
    if unknown:
        raise BundleError("bundle contains unsupported fields")
    if document.get("bundle_version") != BUNDLE_VERSION:
        raise BundleError("bundle requires the supported bundle_version")
    profile = document.get("profile")
    if profile not in _PROFILES:
        raise BundleError("bundle profile must be local-development, staging, or production")
    agent_code = _require_id(document.get("agent_code"), "agent_code")
    scope = document.get("scope")
    if not isinstance(scope, Mapping):
        raise BundleError("bundle scope must be an object")
    if set(scope) != {"workspace_id", "namespace_id"}:
        raise BundleError("bundle scope requires workspace_id and namespace_id only")
    workspace_id = _require_id(scope.get("workspace_id"), "scope.workspace_id")
    namespace_id = _require_id(scope.get("namespace_id"), "scope.namespace_id")

    for optional in ("ingest_endpoint", "trust_bundle_path", "identity_ref", "policy_revision"):
        value = document.get(optional)
        if value is None:
            continue
        if not isinstance(value, str) or not value or len(value) > 512:
            raise BundleError(f"{optional} must be a bounded string")
        if any(ord(character) < 32 for character in value):
            raise BundleError(f"{optional} contains control characters")
        lowered = value.lower()
        if any(token in lowered for token in ("bearer ", "-----begin", "password=", "api_key=")):
            raise BundleError(f"{optional} must not contain credential material")

    tools = document.get("tool_allowlist", [])
    egress = document.get("egress_allowlist", [])
    for name, values in (("tool_allowlist", tools), ("egress_allowlist", egress)):
        if not isinstance(values, list) or len(values) > 128:
            raise BundleError(f"{name} must be a list of at most 128 identifiers")
        for item in values:
            _require_id(item, name)

    template = document.get("template")
    if template is not None and not isinstance(template, Mapping):
        raise BundleError("bundle template must be an object when present")

    # Signature-related fields
    signature = document.get("signature")
    signature_alg = document.get("signature_alg")
    signing_key_id = document.get("signing_key_id")
    signing_key_fingerprint = document.get("signing_key_fingerprint")
    issuer = document.get("issuer")
    issued_at = document.get("issued_at")
    not_after = document.get("not_after")
    bundle_serial = document.get("bundle_serial")
    meta_present = {
        "signature": signature,
        "signature_alg": signature_alg,
        "signing_key_id": signing_key_id,
        "signing_key_fingerprint": signing_key_fingerprint,
        "issuer": issuer,
        "issued_at": issued_at,
        "not_after": not_after,
        "bundle_serial": bundle_serial,
    }
    has_any_sig = any(v is not None for v in meta_present.values())
    if has_any_sig:
        # Partial signature metadata is a spoofing vector — require all or none
        # for profiles that will verify; still reject partial for any profile.
        missing = [k for k, v in meta_present.items() if v is None]
        if missing and signature is not None:
            raise BundleSignatureError(
                "bundle signature binding fields are incomplete",
                cause=f"Missing: {', '.join(missing)}",
            )
        if signature_alg is not None and signature_alg != SIGNATURE_ALG:
            raise BundleError("signature_alg must be ed25519 when present")
        if signing_key_id is not None:
            _require_id(signing_key_id, "signing_key_id")
        if signing_key_fingerprint is not None:
            if not isinstance(signing_key_fingerprint, str) or not _FINGERPRINT_HEX.fullmatch(
                signing_key_fingerprint.lower()
            ):
                raise BundleError("signing_key_fingerprint must be 64 hex characters")
        if issuer is not None:
            _require_id(issuer, "issuer")
        if signature is not None:
            if not isinstance(signature, str) or not signature or len(signature) > 512:
                raise BundleError("signature must be a bounded base64 string")
            if any(ord(character) < 32 for character in signature):
                raise BundleError("signature contains control characters")

    normalized: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "profile": profile,
        "agent_code": agent_code,
        "scope": {"workspace_id": workspace_id, "namespace_id": namespace_id},
        "ingest_endpoint": document.get("ingest_endpoint"),
        "trust_bundle_path": document.get("trust_bundle_path"),
        "identity_ref": document.get("identity_ref"),
        "policy_revision": document.get("policy_revision"),
        "tool_allowlist": list(tools),
        "egress_allowlist": list(egress),
        "template": _deep_canonicalize(dict(template)) if isinstance(template, Mapping) else None,
    }
    if has_any_sig and all(v is not None for v in meta_present.values()):
        normalized["signature_alg"] = signature_alg
        normalized["signing_key_id"] = signing_key_id
        normalized["signing_key_fingerprint"] = str(signing_key_fingerprint).lower()
        normalized["issuer"] = issuer
        normalized["issued_at"] = issued_at
        normalized["not_after"] = not_after
        normalized["bundle_serial"] = bundle_serial
        normalized["signature"] = signature

    if profile == "production" and require_signature is False and not allow_unsigned_local:
        raise BundleSignatureError("production bundles cannot disable signature verification")

    must_verify = require_signature
    if must_verify is None:
        must_verify = profile in {"staging", "production"}
    # Any attached signature must always be verified (fail closed).
    if has_any_sig and all(v is not None for v in meta_present.values()):
        must_verify = True
    if allow_unsigned_local and not has_any_sig:
        must_verify = False

    if must_verify:
        keys = trust_public_keys
        pins = load_trust_pins(trust_pins)
        if keys is None:
            keys = resolve_trust_public_keys(None, trust_pins=pins or None)
        if not keys:
            raise BundleSignatureError(
                "signed bundle verification requires trust public keys",
                cause="Provide trust_public_keys or set APEX_BUNDLE_TRUST_KEYS_DIR.",
            )
        verify_bundle_signature(normalized, keys, trust_pins=pins or None, now=now)
    elif has_any_sig and not all(v is not None for v in meta_present.values()):
        raise BundleSignatureError("partial signature metadata is not allowed")

    return normalized


def load_bundle(
    path: str | Path,
    *,
    base_dir: str | Path | None = None,
    trust_public_keys: Mapping[str, str | bytes] | None = None,
    trust_keys_dir: str | Path | None = None,
    trust_pins: Mapping[str, str] | None = None,
    require_signature: bool | None = None,
) -> dict[str, Any]:
    """Load and validate a JSON integration bundle within an optional trusted base."""
    requested = Path(path)
    if requested.is_symlink():
        raise BundleError("bundle path must not be a symbolic link")
    if base_dir is not None:
        base = Path(base_dir).resolve(strict=True)
        resolved = requested.resolve(strict=False)
        if resolved != base and base not in resolved.parents:
            raise BundleError("bundle path must remain within the configured base directory")
        path_to_read = resolved
    else:
        path_to_read = requested
    try:
        raw = path_to_read.read_text(encoding="utf-8")
    except OSError as exc:
        raise BundleError("bundle file could not be read") from exc
    if len(raw.encode("utf-8")) > 64 * 1024:
        raise BundleError("bundle file exceeds the 64 KiB limit")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BundleError("bundle file must be valid JSON") from exc
    profile = document.get("profile") if isinstance(document, Mapping) else None
    if profile in {"staging", "production"} and base_dir is None:
        raise BundleError(
            "staging and production bundle loading requires an explicit trusted base_dir"
        )
    pins = load_trust_pins(trust_pins)
    configured_trust_dir = trust_keys_dir or os.environ.get("APEX_BUNDLE_TRUST_KEYS_DIR", "").strip()
    if configured_trust_dir:
        default_pins = Path(configured_trust_dir) / "trust.pins"
        if default_pins.is_file() and not default_pins.is_symlink():
            pins = {**load_trust_pins(pins_file=default_pins), **pins}
    if profile in {"staging", "production"} and configured_trust_dir and not pins:
        raise BundleSignatureError(
            "staging and production trust directories require fingerprint pins",
            cause="A dropped PEM must not expand the bundle trust set.",
        )
    keys = resolve_trust_public_keys(
        trust_public_keys, trust_keys_dir=trust_keys_dir, trust_pins=pins or None
    )
    return validate_bundle(
        document,
        require_signature=require_signature,
        trust_public_keys=keys,
        trust_pins=pins or None,
    )


def write_signed_bundle(
    path: str | Path,
    document: Mapping[str, Any],
    *,
    private_key_pem: str | bytes,
    key_id: str,
    issuer: str = "apex-operator",
    validity: timedelta | None = None,
) -> dict[str, Any]:
    """Sign a bundle and write JSON to ``path`` (typically apex-agent.yaml as JSON)."""
    signed = sign_bundle(
        document,
        private_key_pem=private_key_pem,
        key_id=key_id,
        issuer=issuer,
        validity=validity,
    )
    Path(path).write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signed


def local_development_bundle(
    *,
    agent_code: str,
    workspace_id: str = "local",
    namespace_id: str = "demo",
    tool_allowlist: list[str] | None = None,
) -> dict[str, Any]:
    """Create a validated local-development bundle without network endpoints."""
    return validate_bundle(
        {
            "bundle_version": BUNDLE_VERSION,
            "profile": "local-development",
            "agent_code": agent_code,
            "scope": {"workspace_id": workspace_id, "namespace_id": namespace_id},
            "tool_allowlist": tool_allowlist or ["reference_tool"],
            "egress_allowlist": [],
        },
        require_signature=False,
        allow_unsigned_local=True,
    )
