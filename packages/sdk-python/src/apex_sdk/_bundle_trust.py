"""Ed25519 signing primitives, trust-store loading, and signature verification.

Split out of ``bundle.py``: this half is everything cryptographic --
key loading/fingerprinting, the domain-separated signing transcript, trust
pin/trust directory loading, and ``verify_bundle_signature`` itself -- with no
dependency on the bundle *document* validation (``validate_bundle``) or file
I/O (``load_bundle`` / ``write_signed_bundle``) that module still owns.

``BundleError``/``BundleSignatureError`` and the tiny ``_require_id`` helper
move with it because nearly every function here raises one; keeping them next
to the code that constructs them avoids a circular import with ``bundle.py``,
which imports this module's signing/trust/verify surface back. Everything
``bundle.py`` (and its tests) import by name from here is re-imported there,
so ``apex_sdk.bundle.X`` continues to resolve exactly as it did before the
split -- including the handful of "private" helpers (``_load_private_key``,
``_load_public_key``, ``_deep_canonicalize``, ``_parse_utc``) tests reach into
directly.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from .errors import ConfigurationError
from .validation import SAFE_IDENTIFIER

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
# Max clock skew when checking issued_at (future issue rejection).
_MAX_ISSUED_FUTURE_SKEW = timedelta(minutes=5)
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
