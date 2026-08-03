"""Event construction and RFC 8785 integrity helpers."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import rfc8785

from .validation import EventValidationError, validate_event
from .errors import EventIntegrityError


def canonical_event_bytes(event: Mapping[str, Any]) -> bytes:
    """Return the exact bytes hashed and archived for an event."""
    try:
        unsigned = copy.deepcopy(dict(event))
        integrity = unsigned.get("integrity")
        if not isinstance(integrity, dict):
            raise TypeError("integrity must be an object")
        integrity.pop("event_hash", None)
        return rfc8785.dumps(unsigned)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise EventIntegrityError() from exc


def event_hash(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()


class EventBuilder:
    """Creates validated, hash-chained v1 envelopes for one agent run."""

    def __init__(self, *, agent_id: str, run_id: str, trace_id: str, scope: Mapping[str, Any], actor: Mapping[str, str], version: Mapping[str, str], parent_run_id: str | None = None) -> None:
        if not all(isinstance(value, Mapping) for value in (scope, actor, version)):
            raise EventValidationError("event builder identity configuration must use mapping objects")
        self._identity = copy.deepcopy({"agent_id": agent_id, "run_id": run_id, "trace_id": trace_id, "scope": dict(scope), "actor": dict(actor), "version": dict(version), "parent_run_id": parent_run_id})
        self._previous_hash: str | None = None

    def build(self, event_type: str, data: Mapping[str, Any], *, event_id: str, timestamp: datetime | None = None) -> dict[str, Any]:
        try:
            if UUID(event_id).version != 7:
                raise ValueError
        except ValueError as exc:
            raise EventValidationError("event_id must be UUIDv7") from exc
        instant = timestamp or datetime.now(UTC)
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise EventValidationError("timestamp must be timezone-aware")
        if not isinstance(data, Mapping):
            raise EventValidationError("event data must be a mapping object")
        event = {**copy.deepcopy(self._identity), "event_id": event_id, "timestamp": instant.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z"), "type": event_type, "data": copy.deepcopy(dict(data)), "integrity": {"prev_hash": self._previous_hash, "event_hash": "0" * 64}, "schema_version": 1}
        event["integrity"]["event_hash"] = event_hash(event)
        validate_event(event)
        self._previous_hash = event["integrity"]["event_hash"]
        return event
