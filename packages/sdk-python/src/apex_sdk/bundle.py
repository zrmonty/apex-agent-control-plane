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
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from .errors import ConfigurationError
from .validation import SAFE_IDENTIFIER

BUNDLE_VERSION = "apex-agent-bundle.v1"
SIGNATURE_ALG = "ed25519"
# Domain separation: v1 signing transcript (never change for BUNDLE_VERSION).
_SIGNING_CONTEXT = b"APEX-AGENT-BUNDLE-V1\ned25519\n"
_ED25519_SIG_LEN = 64
_FINGERPRINT_HEX = re.compile(r"^[0-9a-f]{64}$")
_ISO_Z = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

# Only the raw signature is detached. Everything else is covered by the signature.
_DETACHED_FIELDS = frozenset({"signature"})
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
# Max clock skew when checking issued_at (future issue rejection).
_MAX_ISSUED_FUTURE_SKEW = timedelta(minutes=5)
# Default validity for newly signed bundles.
_DEFAULT_VALIDITY = timedelta(days=90)
_MAX_VALIDITY = timedelta(days=366)


class BundleError(ConfigurationError):
    code = "AGENT_BUNDLE_INVALID"
    safe_message = "The Apex agent integration bundle is not valid."
    cause = "The generated bundle must contain only non-secret endpoint, scope, and profile references."
    recommended_next_steps = (
        "Regenerate the integration bundle from the operator console.",
        "Do not paste credentials, private keys, or prompts into apex-agent.yaml.",
    )


class BundleSignatureError(BundleError):
    code = "AGENT_BUNDLE_SIGNATURE_INVALID"
    safe_message = "The Apex agent integration bundle signature is missing or invalid."
    cause = (
        "Staging and production bundles must be signed with an operator-trusted "
        "Ed25519 key, fingerprint-bound, and within their validity window before "
        "workload identity is used."
    )
    recommended_next_steps = (
        "Obtain a freshly signed apex-agent.yaml from the operator console.",
        "Configure APEX_BUNDLE_TRUST_KEYS_DIR and APEX_BUNDLE_TRUST_PINS with operator keys only.",
        "Never place private keys or untrusted PEMs in the agent trust store.",
        "Do not disable signature verification for production profiles.",
    )


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise BundleError(f"{name} must be a safe identifier")
    return value


def _cryptography():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - exercised when optional dep missing
        raise BundleSignatureError(
            "bundle signing requires the 'cryptography' package",
            cause="pip install cryptography",
        ) from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def _deep_canonicalize(value: Any) -> Any:
    """Recursively normalize for stable JSON (sorted object keys, list order kept)."""
    if isinstance(value, Mapping):
        return {str(k): _deep_canonicalize(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, list):
        return [_deep_canonicalize(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    raise BundleError("bundle payload contains non-JSON-canonical types")


def canonical_bundle_payload(document: Mapping[str, Any]) -> bytes:
    """Stable UTF-8 JSON of all fields except the detached signature."""
    payload = {
        key: document[key]
        for key in sorted(document)
        if key not in _DETACHED_FIELDS and document[key] is not None
    }
    canonical = _deep_canonicalize(payload)
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def signing_transcript(document: Mapping[str, Any]) -> bytes:
    """Domain-separated message that is actually signed/verified."""
    body = canonical_bundle_payload(document)
    digest = hashlib.sha256(body).digest()
    return _SIGNING_CONTEXT + digest


def fingerprint_public_key(public_key_pem: str | bytes) -> str:
    """SHA-256 (hex) of the raw 32-byte Ed25519 public key (not PEM text)."""
    key = _load_public_key(public_key_pem)
    raw = key.public_bytes_raw()
    return hashlib.sha256(raw).hexdigest()


def fingerprint_private_key(private_key_pem: str | bytes) -> str:
    """Fingerprint of the corresponding public key."""
    private = _load_private_key(private_key_pem)
    raw = private.public_key().public_bytes_raw()
    return hashlib.sha256(raw).hexdigest()


def generate_bundle_signing_key(*, key_id: str = "operator-1") -> dict[str, str]:
    """Generate an Ed25519 keypair for operator signing of agent bundles."""
    _require_id(key_id, "key_id")
    serialization, Ed25519PrivateKey, _ = _cryptography()
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    fp = hashlib.sha256(private.public_key().public_bytes_raw()).hexdigest()
    return {
        "key_id": key_id,
        "private_pem": private_pem,
        "public_pem": public_pem,
        "fingerprint": fp,
    }


def _load_private_key(private_key_pem: str | bytes):
    serialization, Ed25519PrivateKey, _ = _cryptography()
    raw = private_key_pem.encode("ascii") if isinstance(private_key_pem, str) else private_key_pem
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BundleSignatureError("bundle signing key must be Ed25519")
    return key


def _load_public_key(public_key_pem: str | bytes):
    serialization, _, Ed25519PublicKey = _cryptography()
    raw = public_key_pem.encode("ascii") if isinstance(public_key_pem, str) else public_key_pem
    key = serialization.load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise BundleSignatureError("bundle trust key must be Ed25519")
    return key


def _parse_utc(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not _ISO_Z.fullmatch(value):
        raise BundleSignatureError(f"{name} must be an ISO-8601 UTC timestamp ending in Z")
    # fromisoformat does not accept trailing Z on all versions — normalize.
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BundleSignatureError(f"{name} is not a valid timestamp") from exc
    if parsed.tzinfo is None:
        raise BundleSignatureError(f"{name} must be timezone-aware UTC")
    return parsed.astimezone(UTC)


def _format_utc(moment: datetime) -> str:
    moment = moment.astimezone(UTC).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _assert_trust_dir_hardening(base: Path) -> None:
    """Reject symlinked or world-writable trust directories (POSIX mode bits)."""
    if base.is_symlink():
        raise BundleSignatureError("trust keys directory must not be a symbolic link")
    try:
        mode = base.stat().st_mode
    except OSError as exc:
        raise BundleSignatureError("trust keys directory is not available") from exc
    # Windows ACL model does not map cleanly to S_IWOTH; enforce on POSIX only.
    if os.name == "posix" and mode & stat.S_IWOTH:
        raise BundleSignatureError(
            "trust keys directory must not be world-writable",
            cause="An attacker who can write trust PEMs can spoof signed bundles.",
        )


def load_trust_pins(
    pins: Mapping[str, str] | None = None,
    *,
    pins_file: str | Path | None = None,
) -> dict[str, str]:
    """Load key_id → fingerprint pins from mapping, file, and/or env.

    File format (one per line, ``#`` comments)::

        ops-1  abcd...64 hex chars...
        ops-1:abcd...
        ops-1=abcd...

    Env ``APEX_BUNDLE_TRUST_PINS``: ``ops-1:hex,ops-2:hex``.
    """
    result: dict[str, str] = {}
    if pins:
        for key_id, fp in pins.items():
            _require_id(key_id, "pin key_id")
            digest = fp.lower().removeprefix("sha256:")
            if not _FINGERPRINT_HEX.fullmatch(digest):
                raise BundleSignatureError("trust pin fingerprint must be 64 lowercase hex chars")
            result[key_id] = digest

    path = pins_file
    if path is None:
        env_file = os.environ.get("APEX_BUNDLE_TRUST_PINS_FILE", "").strip()
        path = env_file or None
    if path is not None:
        pin_path = Path(path)
        if pin_path.is_symlink():
            raise BundleSignatureError("trust pins file must not be a symbolic link")
        try:
            text = pin_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise BundleSignatureError("trust pins file could not be read") from exc
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" in stripped:
                key_id, fp = stripped.split(":", 1)
            elif "=" in stripped:
                key_id, fp = stripped.split("=", 1)
            else:
                parts = stripped.split()
                if len(parts) != 2:
                    raise BundleSignatureError("trust pins file has an invalid line")
                key_id, fp = parts
            key_id = key_id.strip()
            digest = fp.strip().lower().removeprefix("sha256:")
            _require_id(key_id, "pin key_id")
            if not _FINGERPRINT_HEX.fullmatch(digest):
                raise BundleSignatureError("trust pin fingerprint must be 64 lowercase hex chars")
            result[key_id] = digest

    env_pins = os.environ.get("APEX_BUNDLE_TRUST_PINS", "").strip()
    if env_pins:
        for item in env_pins.split(","):
            item = item.strip()
            if not item:
                continue
            if ":" not in item:
                raise BundleSignatureError("APEX_BUNDLE_TRUST_PINS entries must be key_id:fingerprint")
            key_id, fp = item.split(":", 1)
            key_id = key_id.strip()
            digest = fp.strip().lower().removeprefix("sha256:")
            _require_id(key_id, "pin key_id")
            if not _FINGERPRINT_HEX.fullmatch(digest):
                raise BundleSignatureError("trust pin fingerprint must be 64 lowercase hex chars")
            result[key_id] = digest
    return result


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


def verify_bundle_signature(
    document: Mapping[str, Any],
    trust_public_keys: Mapping[str, str | bytes],
    *,
    trust_pins: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> None:
    """Verify domain-separated Ed25519 signature + fingerprint + validity window."""
    alg = document.get("signature_alg")
    key_id = document.get("signing_key_id")
    signature_b64 = document.get("signature")
    fingerprint = document.get("signing_key_fingerprint")
    issuer = document.get("issuer")
    issued_at = document.get("issued_at")
    not_after = document.get("not_after")
    serial = document.get("bundle_serial")

    if any(
        v is None
        for v in (alg, key_id, signature_b64, fingerprint, issuer, issued_at, not_after, serial)
    ):
        raise BundleSignatureError("bundle signature binding fields are incomplete")
    if alg != SIGNATURE_ALG:
        raise BundleSignatureError("bundle signature_alg must be ed25519")
    if not isinstance(key_id, str) or not SAFE_IDENTIFIER.fullmatch(key_id):
        raise BundleSignatureError("signing_key_id must be a safe identifier")
    if not isinstance(fingerprint, str) or not _FINGERPRINT_HEX.fullmatch(fingerprint.lower()):
        raise BundleSignatureError("signing_key_fingerprint must be 64 hex characters")
    fingerprint = fingerprint.lower()
    if not isinstance(issuer, str) or not SAFE_IDENTIFIER.fullmatch(issuer):
        raise BundleSignatureError("issuer must be a safe identifier")
    if not isinstance(serial, str) or not (
        SAFE_IDENTIFIER.fullmatch(serial) or re.fullmatch(r"[0-9a-f]{16,64}", serial)
    ):
        raise BundleSignatureError("bundle_serial is invalid")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise BundleSignatureError("signature must be a non-empty base64 string")
    if key_id not in trust_public_keys:
        raise BundleSignatureError("signing_key_id is not in the trust set")

    trusted_pem = trust_public_keys[key_id]
    trusted_fp = fingerprint_public_key(trusted_pem)
    if not hmac.compare_digest(trusted_fp, fingerprint):
        raise BundleSignatureError(
            "signing_key_fingerprint does not match the trusted public key",
            cause="Possible key substitution or spoofed key_id.",
        )
    if trust_pins:
        if key_id not in trust_pins:
            raise BundleSignatureError("signing_key_id is not listed in trust pins")
        if not hmac.compare_digest(trust_pins[key_id].lower(), fingerprint):
            raise BundleSignatureError("signing_key_fingerprint does not match trust pin")

    issued = _parse_utc(str(issued_at), "issued_at")
    expires = _parse_utc(str(not_after), "not_after")
    if expires <= issued:
        raise BundleSignatureError("not_after must be after issued_at")
    if expires - issued > _MAX_VALIDITY:
        raise BundleSignatureError("bundle validity window exceeds the maximum allowed")
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    if issued > moment + _MAX_ISSUED_FUTURE_SKEW:
        raise BundleSignatureError("bundle issued_at is too far in the future")
    if moment > expires:
        raise BundleSignatureError("bundle signature has expired")

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise BundleSignatureError("signature is not valid base64") from exc
    if len(signature) != _ED25519_SIG_LEN:
        raise BundleSignatureError("signature length is invalid for Ed25519")

    transcript = signing_transcript(document)
    try:
        _load_public_key(trusted_pem).verify(signature, transcript)
    except BundleSignatureError:
        raise
    except Exception as exc:
        raise BundleSignatureError("bundle signature verification failed") from exc


def load_trust_public_keys(
    directory: str | Path,
    *,
    trust_pins: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Load `{key_id}.pem` public keys; enforce pins and directory hardening."""
    base = Path(directory)
    if not base.is_dir():
        raise BundleSignatureError("trust keys directory is not available")
    _assert_trust_dir_hardening(base)

    pins = dict(trust_pins or {})
    # Auto-load pins file beside the directory when present.
    default_pins = base / "trust.pins"
    if default_pins.is_file() and not default_pins.is_symlink():
        pins = {**load_trust_pins(pins_file=default_pins), **pins}

    require_pins = os.environ.get("APEX_BUNDLE_REQUIRE_TRUST_PINS", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if require_pins and not pins:
        raise BundleSignatureError(
            "trust pins are required but none were configured",
            cause="Set APEX_BUNDLE_TRUST_PINS or place trust.pins in the trust directory.",
        )

    keys: dict[str, str] = {}
    for path in sorted(base.iterdir()):
        if path.name == "trust.pins":
            continue
        if path.suffix.lower() != ".pem" or path.is_symlink():
            continue
        key_id = path.stem
        if not SAFE_IDENTIFIER.fullmatch(key_id):
            continue
        try:
            pem = path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise BundleSignatureError(f"could not read trust key {key_id}") from exc
        _load_public_key(pem)
        fp = fingerprint_public_key(pem)
        if pins:
            if key_id not in pins:
                # Ignore unpinned PEMs rather than trusting them (anti-spoof drop-in).
                continue
            if not hmac.compare_digest(pins[key_id].lower(), fp):
                raise BundleSignatureError(
                    f"trust key {key_id} does not match its pin",
                    cause="PEM may have been substituted.",
                )
        keys[key_id] = pem
    if not keys:
        raise BundleSignatureError("trust keys directory contains no usable *.pem public keys")
    return keys


def resolve_trust_public_keys(
    trust_public_keys: Mapping[str, str | bytes] | None = None,
    *,
    trust_keys_dir: str | Path | None = None,
    trust_pins: Mapping[str, str] | None = None,
) -> dict[str, str | bytes] | None:
    """Merge explicit keys with optional directory / env; apply pins to explicit keys."""
    pins = load_trust_pins(trust_pins)
    merged: dict[str, str | bytes] = {}
    if trust_public_keys:
        for key_id, pem in trust_public_keys.items():
            _require_id(key_id, "trust key_id")
            fp = fingerprint_public_key(pem)
            if pins and key_id in pins and not hmac.compare_digest(pins[key_id], fp):
                raise BundleSignatureError(f"explicit trust key {key_id} does not match pin")
            if pins and key_id not in pins and os.environ.get(
                "APEX_BUNDLE_REQUIRE_TRUST_PINS", ""
            ).strip().lower() in {"1", "true", "yes"}:
                continue
            merged[key_id] = pem
    directory = trust_keys_dir
    if directory is None:
        env_dir = os.environ.get("APEX_BUNDLE_TRUST_KEYS_DIR", "").strip()
        directory = env_dir or None
    if directory is not None:
        merged.update(load_trust_public_keys(directory, trust_pins=pins or None))
    return merged or None


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
