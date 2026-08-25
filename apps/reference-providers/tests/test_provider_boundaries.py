from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

import rfc8785

PROVIDER_ROOT = Path(__file__).resolve().parents[1]
if str(PROVIDER_ROOT) not in sys.path:
    sys.path.insert(0, str(PROVIDER_ROOT))

from apex_reference_providers.backends.local import LocalArchiveBackend  # noqa: E402
from apex_reference_providers.clickhouse_projection import Store  # noqa: E402
from apex_reference_providers.event_validation import (  # noqa: E402
    EnvelopeValidationError,
    event_envelope_class,
    validate_event_envelope,
)


EVENT_ID = "018f5c91-2d88-7c00-8000-000000000001"


def _event_dict(*, event_id: str = EVENT_ID, workspace: str = "acme") -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2024-02-29T23:59:59.000000Z",
        "type": "turn_start",
        "agent_id": "agent",
        "run_id": "run-1",
        "parent_run_id": None,
        "trace_id": "trace-1",
        "scope": {
            "workspace_id": workspace,
            "namespace_id": "prod",
            "agent_group_ids": [],
        },
        "actor": {"type": "agent", "id": "agent"},
        "version": {"agent_code": "code", "prompt": "prompt", "model": "model"},
        "data": {"note": "hello"},
        "integrity": {"prev_hash": None, "event_hash": "0" * 64},
        "schema_version": 1,
    }


def _envelope(*, workspace: str = "acme") -> tuple[bytes, dict]:
    event = _event_dict(workspace=workspace)
    unsigned = {**event, "integrity": {"prev_hash": None}}
    event["integrity"]["event_hash"] = hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest()
    message = event_envelope_class()()
    message.event_id = event["event_id"]
    message.timestamp = event["timestamp"]
    message.type = 1
    message.agent_id = event["agent_id"]
    message.run_id = event["run_id"]
    message.trace_id = event["trace_id"]
    message.scope.workspace_id = event["scope"]["workspace_id"]
    message.scope.namespace_id = event["scope"]["namespace_id"]
    message.actor.type = 2
    message.actor.id = event["actor"]["id"]
    message.version.agent_code = event["version"]["agent_code"]
    message.version.prompt = event["version"]["prompt"]
    message.version.model = event["version"]["model"]
    message.data.update(event["data"])
    message.integrity.event_hash = event["integrity"]["event_hash"]
    message.schema_version = 1
    return message.SerializeToString(deterministic=True), event


class ProviderBoundaryTests(unittest.TestCase):
    def test_valid_envelope_is_decoded_and_scoped(self) -> None:
        body, event = _envelope()

        result = validate_event_envelope(body, EVENT_ID, event["integrity"]["event_hash"])

        self.assertEqual(result.event_id, EVENT_ID)
        self.assertEqual(result.workspace_id, "acme")
        self.assertEqual(result.namespace_id, "prod")

    def test_malformed_protobuf_is_terminal_validation_error(self) -> None:
        with self.assertRaises(EnvelopeValidationError):
            validate_event_envelope(b"\x0a", EVENT_ID, "0" * 64)

    def test_header_identity_and_recomputed_hash_are_required(self) -> None:
        body, event = _envelope()

        with self.assertRaises(EnvelopeValidationError):
            validate_event_envelope(body, "018f5c91-2d88-7c00-8000-000000000002", event["integrity"]["event_hash"])

        message = event_envelope_class()()
        message.ParseFromString(body)
        message.integrity.event_hash = "0" * 64
        tampered = message.SerializeToString(deterministic=True)
        with self.assertRaises(EnvelopeValidationError):
            validate_event_envelope(tampered, EVENT_ID, "0" * 64)

    def test_same_event_id_is_independent_per_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "events.sqlite3")
            first_body, first_event = _envelope(workspace="acme")
            second_body, second_event = _envelope(workspace="other")

            self.assertEqual(
                store.put("acme", "prod", EVENT_ID, first_event["integrity"]["event_hash"], first_body),
                "created",
            )
            self.assertEqual(
                store.put("other", "prod", EVENT_ID, second_event["integrity"]["event_hash"], second_body),
                "created",
            )

    def test_archive_replay_requires_the_same_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            backend = LocalArchiveBackend(directory)
            body, event = _envelope()
            event_hash = event["integrity"]["event_hash"]

            self.assertEqual(backend.put(EVENT_ID, event_hash, body).status, "created")
            self.assertEqual(backend.put(EVENT_ID, event_hash, body).status, "replay")
            self.assertEqual(backend.put(EVENT_ID, event_hash, body + b"x").status, "conflict")


if __name__ == "__main__":
    unittest.main()
