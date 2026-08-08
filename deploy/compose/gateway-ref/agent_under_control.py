#!/usr/bin/env python3
"""A real agent process that obeys the operator commands an operator sends it.

This is the *agent* half of the live end-to-end proof. It is a genuine Python
process using the product SDK -- ``apex_sdk.GrpcControlTransport`` over real
mTLS and ``apex_sdk.ReferenceReasonActLoop`` -- not a stand-in client written
in Rust for the occasion, and not a mock returning a canned response.

It loops: each iteration runs one reason-act turn, and the loop polls the
control gateway immediately before the turn's tool call. A ``stop`` ends the
turn *and* this process (exit 0). A ``pause`` ends the turn without running its
tool and leaves this loop iterating -- which is the whole point: a paused agent
keeps polling, so a later ``resume`` can reach it. If it completes
``--max-iterations`` without ever halting it exits 3, which is a *failure* of a
stop or budget proof: an agent that halts on its own schedule proves nothing
about the kill switch. A pause/resume proof does not wait for exit at all.

Stdout is a machine-readable transcript so the orchestrating test can assert on
the ordering of real events rather than on this script's own opinion:

    READY <iso8601>                     first poll completed, agent is live
    ITERATION <n> <iso8601>             a turn is starting
    COMPLETED <n> <iso8601>             the turn ran its tool and finished
    STOPPED <command_id> <iso8601>      a stop was retrieved and enacted
    PAUSED <command_id> <n> <iso8601>   the turn did not run its tool
    RESUMED <command_id> <n> <iso8601>  a resume was enacted; the tool then ran
    BUDGET_SET <command_id> <kind> <limit> <n> <iso8601>
                                        a ceiling took effect on turn n
    BUDGET_EXCEEDED <command_id> <n> <kind> <used> <limit> <iso8601>
                                        the ceiling was reached; the tool did
                                        not run and this process exits 0
    INJECTED <command_id> <n> <sha256> <iso8601>
                                        untrusted content was surfaced into
                                        the trace; the turn continues. The
                                        content is reported as a hash, never
                                        echoed into this transcript
    NO_STOP <iso8601>                   ran out of iterations; proof failed

Nothing here is production code. It is the harness that makes the claim
"an operator's command changes what the agent does" checkable.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_SRC = REPO_ROOT / "packages" / "sdk-python" / "src"
if SDK_SRC.is_dir():
    sys.path.insert(0, str(SDK_SRC))

from apex_sdk import (  # noqa: E402
    AgentControlCredentials,
    BoundedObserver,
    GrpcControlTransport,
    JsonlSink,
    ReferenceReasonActLoop,
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _say(line: str) -> None:
    print(line, flush=True)


def _token_from_table(path: Path) -> str:
    """Reads the bearer credential out of an agent credential table entry.

    The table is ``token|cert_sha256|agent_id|scopes``. Split from the right
    three times, exactly as the gateway's own parser does, so a token
    containing the separator still round-trips whole.
    """
    entry = next(
        part.strip()
        for part in path.read_text(encoding="ascii").split(";")
        if part.strip()
    )
    return entry.rsplit("|", 3)[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="control gateway host:port")
    parser.add_argument("--secrets", required=True, type=Path, help="host-side live-mTLS fixture directory")
    parser.add_argument("--agent-id", default="reference-agent")
    parser.add_argument("--certificate-basename", default="agent-workload-client")
    parser.add_argument("--token-file", default="control-agent-tokens-a")
    parser.add_argument("--server-hostname", default="localhost")
    parser.add_argument("--workspace-id", default="acme")
    parser.add_argument("--namespace-id", default="prod")
    parser.add_argument("--max-iterations", type=int, default=120)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    # Synthetic per-turn usage. Zero by default, which is what the stop and
    # pause proofs use. A budget proof needs a non-zero value or the ceiling
    # can never be reached and "the agent halted on its budget" is
    # unfalsifiable -- the loop's synthetic `llm` event otherwise reports
    # `input_tokens: 0, output_tokens: 0`.
    parser.add_argument("--synthetic-input-tokens", type=int, default=0)
    parser.add_argument("--synthetic-output-tokens", type=int, default=0)
    parser.add_argument("--synthetic-cost-per-turn", type=float, default=0.0)
    parser.add_argument("--trace", type=Path, required=True, help="JSONL trace output path")
    args = parser.parse_args()

    secrets: Path = args.secrets
    credentials = AgentControlCredentials.from_files(
        ca_file=secrets / "ca.pem",
        client_certificate_file=secrets / f"{args.certificate_basename}.pem",
        client_key_file=secrets / f"{args.certificate_basename}.key",
        token=_token_from_table(secrets / args.token_file),
    )
    transport = GrpcControlTransport(
        args.endpoint,
        credentials,
        server_hostname=args.server_hostname,
        timeout_seconds=10.0,
    )

    trace_path: Path = args.trace
    trace_path.parent.mkdir(parents=True, exist_ok=True)
    sink = JsonlSink(trace_path, base_dir=trace_path.parent)
    observer = BoundedObserver(sink)
    loop = ReferenceReasonActLoop(
        observer,
        agent_id=args.agent_id,
        scope={
            "workspace_id": args.workspace_id,
            "namespace_id": args.namespace_id,
            "agent_group_ids": [],
        },
        version={"agent_code": "live-proof", "prompt": "p1", "model": "reference"},
        control=transport,
        synthetic_input_tokens=args.synthetic_input_tokens,
        synthetic_output_tokens=args.synthetic_output_tokens,
        synthetic_cost_per_turn=args.synthetic_cost_per_turn,
    )

    exit_code = 3
    try:
        # Prove the credential works before announcing readiness. An
        # orchestrator that submitted a command against an agent whose
        # credential was rejected would time out with no idea why.
        first = transport.poll()
        if first.agent_id != args.agent_id:
            _say(f"IDENTITY_MISMATCH gateway={first.agent_id} local={args.agent_id} {_now()}")
            return 4
        _say(f"READY {_now()}")

        budget_command_id: str | None = None
        for iteration in range(1, args.max_iterations + 1):
            _say(f"ITERATION {iteration} {_now()}")
            events = loop.run(
                f"live-proof-iteration-{iteration}",
                # A tool with a real (small) cost, so "the loop halted before
                # executing the tool" is a statement about ordering rather
                # than about an instantaneous no-op.
                tool=lambda value: (time.sleep(0.05), f"result:{value}")[1],
            )
            terminal = events[-1] if events else {}
            data = terminal.get("data", {}) if isinstance(terminal, dict) else {}
            status = data.get("status")
            command_id = data.get("control_command_id", "")
            # Injected content is reported by `command_id` and by the SHA-256
            # of the content, never by echoing the content itself: this
            # transcript is a proof artefact that lands in CI logs, and
            # operator-supplied free text does not belong there. The hash is
            # enough for an orchestrating test to assert the content arrived
            # byte-identically. The two lists pair up in order because the
            # loop emits one `control` event per id, in that order.
            injected_content = [
                event["data"]["parameters"]["content"]
                for event in events
                if event.get("type") == "control" and event["data"].get("action") == "inject"
            ]
            for position, injected in enumerate(data.get("injected_command_ids", ())):
                digest = hashlib.sha256(
                    injected_content[position].encode("utf-8")
                ).hexdigest()
                _say(f"INJECTED {injected} {iteration} {digest} {_now()}")
            # Announce a newly-installed ceiling *before* reporting the turn,
            # so a transcript shows which turn the budget took effect on. That
            # is what makes "halted exactly at turn N" checkable arithmetic
            # rather than a claim about eventual behaviour.
            if loop.budget_command_id != budget_command_id:
                budget_command_id = loop.budget_command_id
                _say(
                    f"BUDGET_SET {budget_command_id} {loop.budget_kind} "
                    f"{loop.budget_limit} {iteration} {_now()}"
                )
            if status == "stopped":
                _say(f"STOPPED {command_id} {_now()}")
                exit_code = 0
                break
            if status == "budget_exceeded":
                # Terminal like `stopped`: the ceiling is a property of the
                # run, so every later turn would breach it too. The used/limit
                # figures are in the line so the arithmetic is checkable from
                # the transcript alone.
                used = loop.used_tokens if loop.budget_kind == "tokens" else loop.used_cost
                _say(
                    f"BUDGET_EXCEEDED {command_id} {iteration} {loop.budget_kind} "
                    f"{used} {loop.budget_limit} {_now()}"
                )
                exit_code = 0
                break
            if status == "paused":
                # Deliberately no COMPLETED line and no break: the turn ran no
                # tool, and the process keeps polling so a later `resume` can
                # reach it. The outer loop needed no new machinery for this --
                # a paused turn is just a turn that ended early.
                _say(f"PAUSED {command_id} {iteration} {_now()}")
                time.sleep(args.interval_seconds)
                continue
            if status == "resumed":
                # The turn *did* run its tool, so a COMPLETED line follows.
                _say(f"RESUMED {command_id} {iteration} {_now()}")
            _say(f"COMPLETED {iteration} {_now()}")
            time.sleep(args.interval_seconds)
        else:
            _say(f"NO_STOP {_now()}")
    finally:
        observer.close(timeout=5)
        try:
            transport.close()
        except Exception:  # noqa: BLE001 - shutdown must not mask the outcome
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
