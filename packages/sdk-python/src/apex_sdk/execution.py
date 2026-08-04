"""Model execution attribution for truthful Cost Lens metadata.

Builds and validates the optional ``execution`` object on ``llm`` events.
Requested, effective, usage, and evidence fields never carry prompt or
completion content.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Mapping

from .validation import EventValidationError, SAFE_IDENTIFIER

_EVIDENCE_SOURCES = frozenset({"provider_receipt", "sdk_observed", "configured", "estimated"})
_ROUTING_REASONS = frozenset({"configured", "fallback", "capacity", "policy", "user_override"})
_SERVICE_TIERS = frozenset({"standard", "priority", "batch"})
_USAGE_KEYS = frozenset(
    {
        "input_tokens",
        "cached_input_tokens",
        "cache_write_tokens",
        "output_tokens",
        "reasoning_tokens",
        "image_units",
        "audio_units",
        "embedding_tokens",
        "tool_units",
    }
)
_REQUESTED_KEYS = frozenset(
    {"provider", "model", "reasoning_effort", "service_tier", "region", "max_output_tokens"}
)
_EFFECTIVE_KEYS = frozenset(
    {
        "provider",
        "model",
        "model_revision",
        "reasoning_effort",
        "service_tier",
        "region",
        "routing_reason",
    }
)
_EVIDENCE_KEYS = frozenset({"source", "receipt_id_hash", "observed_at", "currency"})
_HASH = __import__("re").compile(r"^[0-9a-f]{64}$")


def _require_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise EventValidationError(f"execution.{name} must be a safe identifier")
    return value


def _optional_id(value: Any, name: str) -> str | None:
    if value is None:
        return None
    return _require_id(value, name)


def _non_negative_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EventValidationError(f"execution.{name} must be a non-negative integer")
    return value


def build_execution(
    *,
    requested_provider: str,
    requested_model: str,
    effective_provider: str | None = None,
    effective_model: str | None = None,
    routing_reason: str | None = None,
    requested_reasoning_effort: str | None = None,
    effective_reasoning_effort: str | None = None,
    requested_service_tier: str | None = None,
    effective_service_tier: str | None = None,
    region: str | None = None,
    max_output_tokens: int | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    cached_input_tokens: int | None = None,
    cache_write_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    evidence_source: str = "sdk_observed",
    receipt_id_hash: str | None = None,
    currency: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a truthful, content-free execution attribution object."""
    requested: dict[str, Any] = {
        "provider": _require_id(requested_provider, "requested.provider"),
        "model": _require_id(requested_model, "requested.model"),
    }
    if requested_reasoning_effort is not None:
        requested["reasoning_effort"] = _require_id(
            requested_reasoning_effort, "requested.reasoning_effort"
        )
    if requested_service_tier is not None:
        if requested_service_tier not in _SERVICE_TIERS and not SAFE_IDENTIFIER.fullmatch(
            requested_service_tier
        ):
            raise EventValidationError("execution.requested.service_tier is invalid")
        requested["service_tier"] = requested_service_tier
    if region is not None:
        requested["region"] = _require_id(region, "requested.region")
    if max_output_tokens is not None:
        requested["max_output_tokens"] = _non_negative_int(
            max_output_tokens, "requested.max_output_tokens"
        )

    effective: dict[str, Any] = {}
    if effective_provider is not None:
        effective["provider"] = _require_id(effective_provider, "effective.provider")
    if effective_model is not None:
        effective["model"] = _require_id(effective_model, "effective.model")
    if effective_reasoning_effort is not None:
        effective["reasoning_effort"] = _require_id(
            effective_reasoning_effort, "effective.reasoning_effort"
        )
    if effective_service_tier is not None:
        if effective_service_tier not in _SERVICE_TIERS and not SAFE_IDENTIFIER.fullmatch(
            effective_service_tier
        ):
            raise EventValidationError("execution.effective.service_tier is invalid")
        effective["service_tier"] = effective_service_tier
    if region is not None and effective:
        effective.setdefault("region", _require_id(region, "effective.region"))
    if routing_reason is not None:
        if routing_reason not in _ROUTING_REASONS:
            raise EventValidationError("execution.effective.routing_reason is invalid")
        effective["routing_reason"] = routing_reason

    usage: dict[str, int] = {}
    for key, value in (
        ("input_tokens", input_tokens),
        ("output_tokens", output_tokens),
        ("cached_input_tokens", cached_input_tokens),
        ("cache_write_tokens", cache_write_tokens),
        ("reasoning_tokens", reasoning_tokens),
    ):
        if value is not None:
            usage[key] = _non_negative_int(value, f"usage.{key}")

    if evidence_source not in _EVIDENCE_SOURCES:
        raise EventValidationError("execution.evidence.source is invalid")
    observed = observed_at or datetime.now(UTC)
    if observed.tzinfo is None:
        raise EventValidationError("execution.evidence.observed_at must be timezone-aware")
    evidence: dict[str, Any] = {
        "source": evidence_source,
        "observed_at": observed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"),
    }
    if receipt_id_hash is not None:
        if not isinstance(receipt_id_hash, str) or not _HASH.fullmatch(receipt_id_hash):
            raise EventValidationError("execution.evidence.receipt_id_hash must be SHA-256 hex")
        evidence["receipt_id_hash"] = receipt_id_hash
    if currency is not None:
        evidence["currency"] = _require_id(currency, "evidence.currency")

    payload: dict[str, Any] = {"requested": requested, "evidence": evidence}
    if effective:
        payload["effective"] = effective
    if usage:
        payload["usage"] = usage
    validate_execution(payload)
    return payload


def validate_execution(execution: Mapping[str, Any]) -> None:
    """Validate an optional llm.execution object fail-closed."""
    if not isinstance(execution, Mapping):
        raise EventValidationError("execution must be an object")
    allowed = {"requested", "effective", "usage", "evidence"}
    unknown = set(execution) - allowed
    if unknown:
        raise EventValidationError("execution has unsupported fields")
    if "requested" not in execution or "evidence" not in execution:
        raise EventValidationError("execution requires requested and evidence")

    requested = execution["requested"]
    if not isinstance(requested, Mapping):
        raise EventValidationError("execution.requested must be an object")
    if set(requested) - _REQUESTED_KEYS:
        raise EventValidationError("execution.requested has unsupported fields")
    _require_id(requested.get("provider"), "requested.provider")
    _require_id(requested.get("model"), "requested.model")
    _optional_id(requested.get("reasoning_effort"), "requested.reasoning_effort")
    _optional_id(requested.get("region"), "requested.region")
    if "service_tier" in requested:
        tier = requested["service_tier"]
        if tier not in _SERVICE_TIERS and (
            not isinstance(tier, str) or not SAFE_IDENTIFIER.fullmatch(tier)
        ):
            raise EventValidationError("execution.requested.service_tier is invalid")
    if "max_output_tokens" in requested:
        _non_negative_int(requested["max_output_tokens"], "requested.max_output_tokens")

    if "effective" in execution:
        effective = execution["effective"]
        if not isinstance(effective, Mapping):
            raise EventValidationError("execution.effective must be an object")
        if set(effective) - _EFFECTIVE_KEYS:
            raise EventValidationError("execution.effective has unsupported fields")
        for key in ("provider", "model", "model_revision", "reasoning_effort", "region"):
            if key in effective:
                _require_id(effective[key], f"effective.{key}")
        if "service_tier" in effective:
            tier = effective["service_tier"]
            if tier not in _SERVICE_TIERS and (
                not isinstance(tier, str) or not SAFE_IDENTIFIER.fullmatch(tier)
            ):
                raise EventValidationError("execution.effective.service_tier is invalid")
        if "routing_reason" in effective and effective["routing_reason"] not in _ROUTING_REASONS:
            raise EventValidationError("execution.effective.routing_reason is invalid")

    if "usage" in execution:
        usage = execution["usage"]
        if not isinstance(usage, Mapping):
            raise EventValidationError("execution.usage must be an object")
        if set(usage) - _USAGE_KEYS:
            raise EventValidationError("execution.usage has unsupported fields")
        for key, value in usage.items():
            _non_negative_int(value, f"usage.{key}")

    evidence = execution["evidence"]
    if not isinstance(evidence, Mapping):
        raise EventValidationError("execution.evidence must be an object")
    if set(evidence) - _EVIDENCE_KEYS:
        raise EventValidationError("execution.evidence has unsupported fields")
    if evidence.get("source") not in _EVIDENCE_SOURCES:
        raise EventValidationError("execution.evidence.source is invalid")
    observed_at = evidence.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.endswith("Z"):
        raise EventValidationError("execution.evidence.observed_at must be UTC RFC 3339")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventValidationError("execution.evidence.observed_at must be RFC 3339") from exc
    if "receipt_id_hash" in evidence:
        receipt = evidence["receipt_id_hash"]
        if not isinstance(receipt, str) or not _HASH.fullmatch(receipt):
            raise EventValidationError("execution.evidence.receipt_id_hash must be SHA-256 hex")
    if "currency" in evidence:
        _require_id(evidence["currency"], "evidence.currency")
