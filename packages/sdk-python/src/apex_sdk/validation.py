"""Dependency-light validation for the stable v1 envelope boundary."""

from __future__ import annotations

import copy
import hashlib
import hmac
import math
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from .errors import ApexError
import rfc8785

EVENT_TYPES = frozenset({"turn_start", "llm", "tool", "message", "memory", "decision", "workflow", "agent_spawn", "control", "score", "turn_end", "error"})
ACTOR_TYPES = frozenset({"user", "agent", "system", "schedule"})
HASH = re.compile(r"^[0-9a-f]{64}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
CONTROL_ACTIONS = frozenset({"stop", "pause", "resume", "inject", "set_budget"})
MAX_UNTRUSTED_CONTROL_CONTENT_BYTES = 32 * 1024


class EventValidationError(ApexError):
    code = "EVENT_VALIDATION_FAILED"
    category = "contract"
    safe_message = "The event does not match the Apex contract."


def _id(value: Any, name: str) -> None:
    if not isinstance(value, str) or not SAFE_IDENTIFIER.fullmatch(value):
        raise EventValidationError(f"{name} must be a 1–256 character string")


def _require_exact_fields(value: Mapping[str, Any], expected: set[str], name: str) -> None:
    """Reject schema drift before individual fields are consumed."""
    unknown = value.keys() - expected
    if unknown:
        raise EventValidationError(f"{name} has unsupported fields: {', '.join(sorted(unknown))}")
    missing = expected - value.keys()
    if missing:
        raise EventValidationError(f"{name} is missing required fields: {', '.join(sorted(missing))}")


def _validate_control_data(data: Mapping[str, Any]) -> None:
    if set(data) != {"action", "enforcement", "reason_code", "parameters"}:
        raise EventValidationError("control data has unsupported fields")
    action = data["action"]
    if not isinstance(action, str) or action not in CONTROL_ACTIONS:
        raise EventValidationError("unsupported control action")
    if data["enforcement"] != "cooperative":
        raise EventValidationError("v1 controls are cooperative")
    if data["reason_code"] is not None:
        _id(data["reason_code"], "control reason_code")
    parameters = data["parameters"]
    if not isinstance(parameters, Mapping):
        raise EventValidationError("control parameters must be an object")
    if action in {"stop", "pause", "resume"}:
        if parameters:
            raise EventValidationError(f"{action} does not accept parameters")
        return
    if action == "inject":
        if set(parameters) != {"content", "content_classification"} or not isinstance(parameters["content"], str) or not parameters["content"] or parameters["content_classification"] != "untrusted":
            raise EventValidationError("inject requires untrusted content and content_classification")
        try:
            encoded_content = parameters["content"].encode("utf-8")
        except UnicodeEncodeError as exc:
            raise EventValidationError("inject content must be valid UTF-8") from exc
        if len(encoded_content) > MAX_UNTRUSTED_CONTROL_CONTENT_BYTES:
            raise EventValidationError("inject content must not exceed 32 KiB")
        return
    if set(parameters) != {"budget_kind", "limit"} or parameters["budget_kind"] not in {"tokens", "cost"}:
        raise EventValidationError("set_budget requires budget_kind of tokens or cost")
    limit = parameters["limit"]
    if not isinstance(limit, (int, float)) or isinstance(limit, bool) or not math.isfinite(limit) or limit <= 0:
        raise EventValidationError("set_budget requires a positive limit that is finite")


def validate_event(event: Mapping[str, Any]) -> None:
    if not isinstance(event, Mapping):
        raise EventValidationError("event must be an object")
    required = {"event_id", "timestamp", "type", "agent_id", "run_id", "trace_id", "scope", "actor", "version", "data", "integrity", "schema_version"}
    missing = required - event.keys()
    if missing:
        raise EventValidationError(f"missing required fields: {', '.join(sorted(missing))}")
    unknown = event.keys() - required - {"parent_run_id"}
    if unknown:
        raise EventValidationError(f"unknown envelope fields: {', '.join(sorted(unknown))}")
    if event["schema_version"] != 1 or not isinstance(event["type"], str) or event["type"] not in EVENT_TYPES:
        raise EventValidationError("unsupported schema version or event type")
    try:
        if UUID(str(event["event_id"])).version != 7:
            raise ValueError
    except ValueError as exc:
        raise EventValidationError("event_id must be UUIDv7") from exc
    for name in ("agent_id", "run_id", "trace_id"):
        _id(event[name], name)
    if event.get("parent_run_id") is not None:
        _id(event["parent_run_id"], "parent_run_id")
    if not isinstance(event["timestamp"], str) or not event["timestamp"].endswith("Z"):
        raise EventValidationError("timestamp must be UTC RFC 3339")
    try:
        datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise EventValidationError("timestamp must be RFC 3339") from exc
    scope, actor, version, integrity = (event[name] for name in ("scope", "actor", "version", "integrity"))
    if not all(isinstance(value, Mapping) for value in (scope, actor, version, integrity)):
        raise EventValidationError("scope, actor, version, and integrity must be objects")
    _require_exact_fields(scope, {"workspace_id", "namespace_id", "agent_group_ids"}, "scope")
    _require_exact_fields(actor, {"type", "id"}, "actor")
    _require_exact_fields(version, {"agent_code", "prompt", "model"}, "version")
    _require_exact_fields(integrity, {"prev_hash", "event_hash"}, "integrity")
    for name in ("workspace_id", "namespace_id"):
        _id(scope.get(name), f"scope.{name}")
    groups = scope.get("agent_group_ids")
    if not isinstance(groups, list) or len(groups) > 128:
        raise EventValidationError("scope.agent_group_ids must contain at most 128 IDs")
    for group in groups:
        _id(group, "scope.agent_group_ids[]")
    if not isinstance(actor.get("type"), str) or actor.get("type") not in ACTOR_TYPES:
        raise EventValidationError("unsupported actor type")
    _id(actor.get("id"), "actor.id")
    for name in ("agent_code", "prompt", "model"):
        _id(version.get(name), f"version.{name}")
    if not isinstance(event["data"], Mapping):
        raise EventValidationError("data must be an object")
    if event["type"] == "control":
        _validate_control_data(event["data"])
    if integrity.get("prev_hash") is not None and not HASH.fullmatch(str(integrity["prev_hash"])):
        raise EventValidationError("integrity.prev_hash must be lowercase SHA-256 hex or null")
    if not HASH.fullmatch(str(integrity.get("event_hash", ""))):
        raise EventValidationError("integrity.event_hash must be lowercase SHA-256 hex")
    unsigned = copy.deepcopy(dict(event))
    unsigned["integrity"].pop("event_hash", None)
    try:
        expected_hash = hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise EventValidationError("event cannot be canonically encoded for integrity verification") from exc
    if not hmac.compare_digest(integrity["event_hash"], expected_hash):
        raise EventValidationError("integrity.event_hash does not match the canonical event")
