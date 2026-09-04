#!/usr/bin/env python3
"""Verify the MCP TOOL event in the server-side projection.

The MCP client proof only observes the response returned to the caller. This
check reads the reference projection's durable SQLite store, decodes the
stored protobuf with the provider's own validator, and verifies the event is a
TOOL event with the expected trace, policy, and redaction evidence.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time

from apex_reference_providers.event_validation import (
    _struct_to_json,
    event_envelope_class,
    validate_event_envelope,
)


def find_event(database: str, trace_id: str, workspace: str, namespace: str):
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """
            SELECT event_id, event_hash, envelope
            FROM events
            WHERE workspace_id = ? AND namespace_id = ?
            ORDER BY rowid DESC
            """,
            (workspace, namespace),
        ).fetchall()
    finally:
        connection.close()

    for event_id, event_hash, body in rows:
        try:
            validate_event_envelope(body, event_id, event_hash)
            envelope = event_envelope_class()()
            envelope.ParseFromString(body)
        except Exception:
            continue
        if envelope.trace_id == trace_id:
            return envelope
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", default="/var/lib/apex/events.sqlite3")
    parser.add_argument("--trace-id", required=True)
    parser.add_argument("--workspace", default="acme")
    parser.add_argument("--namespace", default="prod")
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--sleep", type=float, default=2.0)
    args = parser.parse_args()

    for attempt in range(1, args.attempts + 1):
        envelope = find_event(args.database, args.trace_id, args.workspace, args.namespace)
        if envelope is None:
            print(f"verify_mcp_projection: attempt {attempt}: event not projected yet")
            time.sleep(args.sleep)
            continue

        data = _struct_to_json(envelope.data)
        serialized = json.dumps(data, sort_keys=True)
        if envelope.type != 3 or envelope.actor.type != 2:
            print("verify_mcp_projection: wrong event or actor type", file=sys.stderr)
            return 1
        if data.get("tool") != "portfolio.read" or data.get("status") != "succeeded":
            print("verify_mcp_projection: missing tool success evidence", file=sys.stderr)
            return 1
        if data.get("policy", {}).get("outcome") != "allowed":
            print("verify_mcp_projection: missing allowed policy evidence", file=sys.stderr)
            return 1
        for forbidden in ("client-record-raw", "tax-record-raw", "costBasis"):
            if forbidden in serialized:
                print("verify_mcp_projection: restricted data was projected", file=sys.stderr)
                return 1
        print(
            "MCP_OPERATOR_EVIDENCE "
            f"event_id={envelope.event_id} trace={envelope.trace_id} "
            f"type=TOOL status=succeeded projected=true"
        )
        return 0

    print("verify_mcp_projection: event never reached the durable projection", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
