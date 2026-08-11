#!/usr/bin/env python3
"""Repeatable load-test harness for ``apex-event-ingest``'s real mTLS gRPC interface.

Phase 0.6 work item 1. Two jobs, one tool:

1. **Baseline mode** (``--baseline``): ramps the submission rate until the
   gateway starts answering ``RESOURCE_EXHAUSTED`` (``RateLimited`` /
   ``AdmissionBusy``), to find the CURRENT synchronous-fanout gateway's real
   sustainable ceiling -- replacing the Phase 0.6 plan's code-reading estimate
   of ~40-160 events/sec/instance with a measured number.
2. **Regression gate** (default, fixed-rate mode): submits at a configured
   ``--rate`` for ``--duration`` seconds and prints PASS/FAIL against
   ``--target-rate`` and ``--max-reject-pct``, exiting non-zero on FAIL, so it
   can be re-run after every later Phase 0.6 change.

Drives load through ``apex_sdk.GrpcEventIngestTransport`` -- the SDK's actual
production ingest transport, the same one ``gateway-ref/agent_submits_events.py``
uses for its live proof -- rather than a bespoke gRPC client, so the harness
exercises the real client contract (mTLS, canonical-hash round-trip, the
generated ``apex.v1.EventEnvelope`` stub). It calls
``GrpcEventIngestTransport.ingest`` directly rather than going through
``apex_sdk.BoundedGrpcExporter``: the exporter's retry/backoff and circuit
breaker are delivery *policy*, and wrapping every submission in them would
retry exactly the RESOURCE_EXHAUSTED responses this harness exists to count,
hiding the gateway's raw per-attempt admission behavior under load.

Rate scheduling, latency percentiles, and the pass/fail verdict are pure
functions in ``loadtest_core.py``, unit-tested there without a live gateway.
This module is the effectful shell: real clocks, real threads, a real (or, in
``--dry-run``, fake) transport.

Usage
-----
See ``README.md`` next to this file for the full walkthrough. Quick reference::

    # Regression gate at the Phase 0.6 target scale (~231/s average).
    python loadtest.py --endpoint localhost:18445 --secrets ../live-mtls/secrets \\
        --rate 231 --duration 60 --target-rate 231 --max-reject-pct 1.0

    # Baseline / ceiling discovery.
    python loadtest.py --endpoint localhost:18445 --secrets ../live-mtls/secrets \\
        --baseline

    # Exercise the harness itself with no gateway at all.
    python loadtest.py --dry-run --rate 50 --duration 5
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_SRC = REPO_ROOT / "packages" / "sdk-python" / "src"
if SDK_SRC.is_dir():
    sys.path.insert(0, str(SDK_SRC))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from apex_sdk import (  # noqa: E402
    AgentIngestCredentials,
    EventBuilder,
    GrpcEventIngestTransport,
)
from apex_sdk.exporter import GrpcStatusError  # noqa: E402

from loadtest_core import (  # noqa: E402
    LatencyStats,
    Outcome,
    RampStepResult,
    VerdictResult,
    classify_grpc_status,
    compute_latency_stats,
    evaluate_verdict,
    schedule_offsets,
    select_sustainable_ceiling,
)


# --------------------------------------------------------------------------
# event_id generation (mirrors gateway-ref/agent_submits_events.py exactly --
# see that file's docstring for why this is written out rather than imported
# from a library or from apex_sdk's private _reference_helpers._uuid7: this
# harness needs nothing the SDK itself does not already need)
# --------------------------------------------------------------------------


def _uuid7() -> str:
    milliseconds = int(datetime.now(UTC).timestamp() * 1000)
    raw = bytearray(uuid.uuid4().bytes)
    raw[0:6] = milliseconds.to_bytes(6, "big")
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(raw)))


# --------------------------------------------------------------------------
# Transport protocol + dry-run fake
# --------------------------------------------------------------------------


class Ingestor(Protocol):
    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool: ...

    def close(self) -> None: ...


class DryRunTransport:
    """Stands in for :class:`GrpcEventIngestTransport` with no network at all.

    Exercises the exact call shape (``ingest(event, event_id=...) -> bool``,
    raising :class:`GrpcStatusError` on rejection) the harness drives against a
    real gateway, so ``--dry-run`` proves the harness's own event
    construction, rate scheduling, concurrency, and metrics/verdict pipeline
    end to end. It is never a substitute for a real baseline number -- nothing
    it reports should be quoted as gateway performance.
    """

    def __init__(
        self,
        *,
        min_latency_s: float = 0.001,
        max_latency_s: float = 0.008,
        reject_pct: float = 0.0,
        seed: int = 0,
    ) -> None:
        self._min = min_latency_s
        self._max = max_latency_s
        self._reject_pct = reject_pct
        self._rng = random.Random(seed)
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool:
        time.sleep(self._rng.uniform(self._min, self._max))
        if self._rng.uniform(0, 100) < self._reject_pct:
            raise GrpcStatusError("RESOURCE_EXHAUSTED", "dry-run simulated backpressure")
        with self._lock:
            if event_id in self._seen:
                return False
            self._seen.add(event_id)
            return True

    def close(self) -> None:
        return


# --------------------------------------------------------------------------
# Postgres outbox backlog sampling (optional; see README "Backlog sampling")
# --------------------------------------------------------------------------

#: The exact query this harness runs when given ``--postgres-dsn``. Restated
#: here as a literal so it is legible without reading the function below, per
#: the Phase 0.6 item-1 brief: this is the fallback documentation if no DSN is
#: available in the environment the harness runs in.
OUTBOX_BACKLOG_QUERY = "SELECT count(*) FROM apex_event_outbox WHERE state = 'pending'"


def _postgres_driver() -> Any:
    try:
        import psycopg  # noqa: PLC0415

        return psycopg
    except ImportError:
        pass
    try:
        import psycopg2  # noqa: PLC0415

        return psycopg2
    except ImportError as exc:
        raise RuntimeError(
            "backlog sampling needs a Postgres driver on this machine: "
            "pip install 'psycopg[binary]' (or psycopg2-binary), or omit --postgres-dsn "
            f"and read backlog manually with: {OUTBOX_BACKLOG_QUERY}"
        ) from exc


def sample_outbox_pending(dsn: str) -> int:
    """Returns the current pending-row count of ``apex_event_outbox``.

    A plain ``count(*)`` rather than the gateway's own ``n_live_tup`` estimate
    (``apps/event-ingest/src/outbox/postgres.rs::capacity_decision``): that
    estimate exists to make the gateway's *hot admission path* O(1) under
    load, which matters once per enqueue; this sampler runs at most once every
    ``--backlog-sample-interval`` seconds from a harness process, where an
    exact count is cheap and the accuracy is worth it.

    Requires the caller to supply a read-capable DSN: this repository's
    default ``compose.gateway-ref.yaml`` profile runs the gateway against a
    JSONL file outbox (``APEX_OUTBOX_FILE``), not Postgres, so there is no
    DSN to sample by default. See README.md "Backlog sampling" for exactly
    what wiring a Postgres-backed gateway for this purpose requires.
    """
    driver = _postgres_driver()
    conn = driver.connect(dsn, connect_timeout=5)
    try:
        with conn.cursor() as cursor:
            cursor.execute(OUTBOX_BACKLOG_QUERY)
            row = cursor.fetchone()
            return int(row[0])
    finally:
        conn.close()


@dataclass
class BacklogSampler:
    """Background thread sampling outbox depth on a fixed interval during a run."""

    dsn: str | None
    interval_s: float
    _samples: list[tuple[float, int]] = field(default_factory=list)
    _errors: list[str] = field(default_factory=list)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _clock_start: float = 0.0

    def start(self, clock_start: float) -> None:
        if not self.dsn:
            return
        self._clock_start = clock_start
        self._thread = threading.Thread(target=self._loop, name="loadtest-backlog-sampler", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                count = sample_outbox_pending(self.dsn)  # type: ignore[arg-type]
                self._samples.append((time.monotonic() - self._clock_start, count))
            except Exception as exc:  # noqa: BLE001 - a sampling fault must not kill the run
                self._errors.append(f"{type(exc).__name__}: {exc}")
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_s + 5)

    @property
    def counts(self) -> list[int]:
        return [count for _, count in self._samples]

    @property
    def samples(self) -> list[tuple[float, int]]:
        return list(self._samples)

    @property
    def errors(self) -> list[str]:
        return list(self._errors)


# --------------------------------------------------------------------------
# Run context + submission
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SubmissionResult:
    outcome: Outcome
    latency_s: float
    event_id: str
    detail: str | None = None


class RunContext:
    """Everything a worker thread needs, built once and shared read-only.

    One :class:`GrpcEventIngestTransport` (one mTLS channel) and one
    :class:`EventBuilder` (one hash chain) per *worker thread*, lazily
    created on that thread's first submission and cached in thread-local
    storage. ``EventBuilder`` mutates ``_previous_hash`` on every ``build()``
    call and is not safe to share across threads; giving each worker its own
    instance -- with its own ``run_id``/``trace_id`` -- also models what a
    load of independent concurrent agents actually looks like, rather than one
    shared connection serializing everything.
    """

    def __init__(self, args: argparse.Namespace, credentials: AgentIngestCredentials | None) -> None:
        self.args = args
        self.credentials = credentials
        self.run_tag = f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self._local = threading.local()
        self._worker_index = 0
        self._worker_index_lock = threading.Lock()

    def _next_worker_index(self) -> int:
        with self._worker_index_lock:
            self._worker_index += 1
            return self._worker_index

    def _make_transport(self) -> Ingestor:
        args = self.args
        if args.dry_run:
            return DryRunTransport(reject_pct=args.dry_run_reject_pct, seed=args.dry_run_seed)
        assert self.credentials is not None
        return GrpcEventIngestTransport(
            args.endpoint,
            self.credentials,
            server_hostname=args.server_hostname,
            timeout_seconds=args.timeout,
        )

    def worker(self) -> tuple[Ingestor, EventBuilder]:
        cached = getattr(self._local, "worker", None)
        if cached is not None:
            return cached
        index = self._next_worker_index()
        transport = self._make_transport()
        builder = EventBuilder(
            agent_id=self.args.agent_id,
            run_id=f"loadtest-{self.run_tag}-{index}",
            trace_id=f"loadtest-{self.run_tag}-{index}",
            scope={
                "workspace_id": self.args.workspace_id,
                "namespace_id": self.args.namespace_id,
                "agent_group_ids": [],
            },
            actor={"type": "agent", "id": self.args.agent_id},
            version={"agent_code": "loadtest-harness", "prompt": "loadtest", "model": "loadtest"},
        )
        cached = (transport, builder)
        self._local.worker = cached
        return cached

    def close_all(self) -> None:
        # Only the calling thread's own cached transport is reachable from
        # thread-local storage; each worker thread closes its own on exit via
        # the ThreadPoolExecutor shutdown path in run_fixed_rate below.
        pass


def _make_payload(sequence: int) -> dict[str, Any]:
    return {
        "provider": "loadtest",
        "model": "loadtest-harness",
        "input_tokens": sequence % 512,
        "output_tokens": (sequence * 7) % 512,
        "sequence": sequence,
    }


def _submit_one(ctx: RunContext, ideal_offset: float, start_monotonic: float, sequence: int) -> SubmissionResult:
    transport, builder = ctx.worker()
    event_id = _uuid7()
    event = builder.build("llm", _make_payload(sequence), event_id=event_id)
    try:
        inserted = transport.ingest(event, event_id=event_id)
    except GrpcStatusError as exc:
        latency_s = (time.monotonic() - start_monotonic) - ideal_offset
        return SubmissionResult(classify_grpc_status(exc.status), max(latency_s, 0.0), event_id, exc.status)
    except Exception as exc:  # noqa: BLE001 - any local/transport fault must still be counted
        latency_s = (time.monotonic() - start_monotonic) - ideal_offset
        return SubmissionResult(Outcome.OTHER_ERROR, max(latency_s, 0.0), event_id, f"{type(exc).__name__}: {exc}")
    latency_s = (time.monotonic() - start_monotonic) - ideal_offset
    outcome = Outcome.ACCEPTED if inserted else Outcome.DUPLICATE
    return SubmissionResult(outcome, max(latency_s, 0.0), event_id, None)


# --------------------------------------------------------------------------
# Fixed-rate run
# --------------------------------------------------------------------------


@dataclass
class RunResult:
    rate: float
    duration: float
    wall_seconds: float
    results: list[SubmissionResult]
    backlog_samples: list[tuple[float, int]]
    backlog_errors: list[str]

    @property
    def outcome_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.outcome.value] = counts.get(result.outcome.value, 0) + 1
        return counts

    @property
    def achieved_rate(self) -> float:
        return len(self.results) / self.wall_seconds if self.wall_seconds > 0 else 0.0

    @property
    def latency_stats(self) -> LatencyStats:
        return compute_latency_stats([r.latency_s for r in self.results])


def run_fixed_rate(
    ctx: RunContext,
    rate: float,
    duration: float,
    *,
    concurrency: int,
    backlog_dsn: str | None,
    backlog_interval: float,
    progress: bool = True,
) -> RunResult:
    offsets = schedule_offsets(rate, duration)
    sampler = BacklogSampler(dsn=backlog_dsn, interval_s=backlog_interval)
    results: list[SubmissionResult] = []
    results_lock = threading.Lock()

    def _record(future_result: SubmissionResult) -> None:
        with results_lock:
            results.append(future_result)

    start_monotonic = time.monotonic()
    sampler.start(start_monotonic)
    next_report = start_monotonic + 5.0
    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="loadtest-worker") as executor:
        futures = []
        for sequence, offset in enumerate(offsets):
            target = start_monotonic + offset
            now = time.monotonic()
            if target > now:
                time.sleep(target - now)
            futures.append(executor.submit(_submit_one, ctx, offset, start_monotonic, sequence))
            if progress and time.monotonic() >= next_report:
                done = sum(1 for f in futures if f.done())
                print(
                    f"  ... issued {len(futures)}/{len(offsets)}, {done} completed, "
                    f"elapsed {time.monotonic() - start_monotonic:.1f}s",
                    file=sys.stderr,
                )
                next_report = time.monotonic() + 5.0
        for future in futures:
            _record(future.result())
    wall_seconds = time.monotonic() - start_monotonic
    sampler.stop()
    return RunResult(
        rate=rate,
        duration=duration,
        wall_seconds=wall_seconds,
        results=results,
        backlog_samples=sampler.samples,
        backlog_errors=sampler.errors,
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _print_run_report(run: RunResult, *, target_rate: float, max_reject_pct: float, backlog_max_pending: int | None) -> VerdictResult:
    counts = run.outcome_counts
    total = len(run.results)
    stats = run.latency_stats
    print()
    print(f"RATE       target={run.rate:.1f}/s achieved={run.achieved_rate:.1f}/s wall={run.wall_seconds:.2f}s attempted={total}")
    print("OUTCOMES   " + " ".join(f"{name}={counts.get(name, 0)}" for name in [o.value for o in Outcome]))
    print(
        "LATENCY_MS "
        f"p50={stats.p50_ms:.2f} p95={stats.p95_ms:.2f} p99={stats.p99_ms:.2f} "
        f"max={stats.max_ms:.2f} mean={stats.mean_ms:.2f} min={stats.min_ms:.2f}"
    )
    if run.backlog_samples:
        depths = [c for _, c in run.backlog_samples]
        print(f"BACKLOG    samples={len(depths)} first={depths[0]} peak={max(depths)} last={depths[-1]}")
    elif backlog_max_pending is not None:
        print("BACKLOG    no samples collected (postgres-dsn sampling failed every attempt -- see errors below)")
    else:
        print(f"BACKLOG    TODO: no --postgres-dsn given. Exact query this harness would run: {OUTBOX_BACKLOG_QUERY}")
    for error in run.backlog_errors[:3]:
        print(f"BACKLOG_ERROR {error}")

    verdict = evaluate_verdict(
        target_rate=target_rate,
        achieved_rate=run.achieved_rate,
        total_attempted=total,
        outcome_counts=counts,
        max_reject_pct=max_reject_pct,
        backlog_samples=[c for _, c in run.backlog_samples] or None,
        backlog_max_pending=backlog_max_pending,
    )
    print()
    print(f"VERDICT    {verdict.summary}")
    for reason in verdict.reasons:
        print(f"  - {reason}")
    return verdict


# --------------------------------------------------------------------------
# Baseline / ramp mode
# --------------------------------------------------------------------------


def run_baseline(ctx: RunContext, args: argparse.Namespace) -> int:
    print(
        f"BASELINE   start={args.ramp_start:.1f}/s step={args.ramp_step:.1f}/s "
        f"step_duration={args.ramp_step_duration:.1f}s max={args.ramp_max_rate:.1f}/s "
        f"reject_threshold={args.ramp_reject_threshold_pct:.2f}%"
    )
    steps: list[RampStepResult] = []
    rate = args.ramp_start
    while rate <= args.ramp_max_rate:
        print(f"\n--- ramp step: {rate:.1f}/s for {args.ramp_step_duration:.1f}s ---")
        run = run_fixed_rate(
            ctx,
            rate,
            args.ramp_step_duration,
            concurrency=args.concurrency,
            backlog_dsn=args.postgres_dsn,
            backlog_interval=args.backlog_sample_interval,
            progress=False,
        )
        counts = run.outcome_counts
        total = len(run.results)
        admitted = counts.get(Outcome.ACCEPTED.value, 0) + counts.get(Outcome.DUPLICATE.value, 0)
        reject_pct = ((total - admitted) / total * 100.0) if total else 100.0
        step = RampStepResult(
            rate=rate,
            achieved_rate=run.achieved_rate,
            total_attempted=total,
            reject_pct=reject_pct,
            outcome_counts=counts,
        )
        steps.append(step)
        stats = run.latency_stats
        print(
            f"  achieved={run.achieved_rate:.1f}/s reject={reject_pct:.2f}% "
            f"p50={stats.p50_ms:.2f}ms p99={stats.p99_ms:.2f}ms outcomes={counts}"
        )
        if reject_pct > args.ramp_reject_threshold_pct:
            print(f"  -> exceeded reject threshold at {rate:.1f}/s, stopping ramp")
            break
        rate += args.ramp_step

    ceiling = select_sustainable_ceiling(steps, args.ramp_reject_threshold_pct)
    print()
    print("BASELINE_STEPS rate,achieved_rate,attempted,reject_pct")
    for step in steps:
        print(f"  {step.rate:.1f},{step.achieved_rate:.1f},{step.total_attempted},{step.reject_pct:.2f}")
    print()
    if ceiling is None:
        print(f"BASELINE_RESULT no rate at or under {args.ramp_start:.1f}/s stayed within the reject threshold")
    else:
        print(f"BASELINE_RESULT sustainable ceiling ~= {ceiling:.1f} events/sec (single gateway instance, this environment)")
    print(
        "NOTE       this is a measurement of THIS run's environment (container CPU limits, host, "
        "network), not a portable constant -- re-run before quoting a number in a design doc."
    )
    if args.json_report:
        payload = {
            "mode": "baseline",
            "generated_at": datetime.now(UTC).isoformat(),
            "steps": [
                {
                    "rate": s.rate,
                    "achieved_rate": s.achieved_rate,
                    "attempted": s.total_attempted,
                    "reject_pct": s.reject_pct,
                    "outcome_counts": dict(s.outcome_counts),
                }
                for s in steps
            ],
            "sustainable_ceiling_events_per_sec": ceiling,
        }
        args.json_report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"JSON_REPORT {args.json_report}")
    # Baseline mode is discovery, not a gate: it always exits 0 once it
    # produces a number (or explicitly reports that it could not).
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target = parser.add_argument_group("gateway target + credentials")
    target.add_argument("--endpoint", help="ingest gateway host:port, e.g. localhost:18445")
    target.add_argument("--secrets", type=Path, help="live-mTLS fixture directory (see README)")
    target.add_argument("--agent-id", default="reference-agent")
    target.add_argument("--certificate-basename", default="ingest-http-client")
    target.add_argument("--token-file", default="ingest-bearer-token")
    target.add_argument("--server-hostname", default="localhost")
    target.add_argument("--workspace-id", default="acme")
    target.add_argument("--namespace-id", default="prod")
    target.add_argument("--timeout", type=float, default=10.0, help="per-submission RPC timeout, seconds")

    load = parser.add_argument_group("fixed-rate run (the regression gate)")
    load.add_argument("--rate", type=float, default=50.0, help="target events/sec (open-loop)")
    load.add_argument("--duration", type=float, default=30.0, help="run duration, seconds")
    load.add_argument("--concurrency", type=int, default=32, help="max in-flight submissions (worker threads)")

    verdict = parser.add_argument_group("pass/fail verdict")
    verdict.add_argument("--target-rate", type=float, default=None, help="defaults to --rate")
    verdict.add_argument("--max-reject-pct", type=float, default=1.0)
    verdict.add_argument("--min-rate-ratio", type=float, default=0.95, help="achieved/target floor to pass")

    backlog = parser.add_argument_group("outbox backlog sampling (optional)")
    backlog.add_argument("--postgres-dsn", default=None, help="read-only DSN for apex_event_outbox; see README")
    backlog.add_argument("--backlog-sample-interval", type=float, default=2.0)
    backlog.add_argument("--backlog-max-pending", type=int, default=None, help="fail if peak backlog exceeds this")

    baseline = parser.add_argument_group("baseline / ceiling-discovery mode")
    baseline.add_argument("--baseline", action="store_true", help="ramp --rate instead of running one fixed rate")
    baseline.add_argument("--ramp-start", type=float, default=20.0)
    baseline.add_argument("--ramp-step", type=float, default=40.0)
    baseline.add_argument("--ramp-step-duration", type=float, default=10.0)
    baseline.add_argument("--ramp-max-rate", type=float, default=3000.0)
    baseline.add_argument("--ramp-reject-threshold-pct", type=float, default=1.0)

    output = parser.add_argument_group("output")
    output.add_argument("--json-report", type=Path, default=None)

    dry_run = parser.add_argument_group("dry-run (no gateway, no network)")
    dry_run.add_argument("--dry-run", action="store_true", help="drive a fake transport instead of the real gateway")
    dry_run.add_argument("--dry-run-reject-pct", type=float, default=0.0)
    dry_run.add_argument("--dry-run-seed", type=int, default=1234)
    return parser


def _load_credentials(args: argparse.Namespace) -> AgentIngestCredentials:
    secrets: Path = args.secrets
    return AgentIngestCredentials.from_files(
        ca_file=secrets / "ca.pem",
        client_certificate_file=secrets / f"{args.certificate_basename}.pem",
        client_key_file=secrets / f"{args.certificate_basename}.key",
        token_file=secrets / args.token_file,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.dry_run:
        missing = [name for name, value in (("--endpoint", args.endpoint), ("--secrets", args.secrets)) if not value]
        if missing:
            parser.error(f"{', '.join(missing)} required unless --dry-run is given")

    credentials = None if args.dry_run else _load_credentials(args)
    ctx = RunContext(args, credentials)

    if args.baseline:
        return run_baseline(ctx, args)

    target_rate = args.target_rate if args.target_rate is not None else args.rate
    print(f"READY mode=fixed-rate endpoint={'DRY-RUN' if args.dry_run else args.endpoint} rate={args.rate:.1f}/s duration={args.duration:.1f}s concurrency={args.concurrency}")
    run = run_fixed_rate(
        ctx,
        args.rate,
        args.duration,
        concurrency=args.concurrency,
        backlog_dsn=args.postgres_dsn,
        backlog_interval=args.backlog_sample_interval,
    )
    verdict = _print_run_report(
        run,
        target_rate=target_rate,
        max_reject_pct=args.max_reject_pct,
        backlog_max_pending=args.backlog_max_pending,
    )
    if args.json_report:
        payload = {
            "mode": "fixed-rate",
            "generated_at": datetime.now(UTC).isoformat(),
            "target_rate": target_rate,
            "rate": run.rate,
            "achieved_rate": run.achieved_rate,
            "duration": run.duration,
            "wall_seconds": run.wall_seconds,
            "attempted": len(run.results),
            "outcome_counts": run.outcome_counts,
            "latency_ms": run.latency_stats.as_dict(),
            "backlog_samples": run.backlog_samples,
            "backlog_errors": run.backlog_errors,
            "verdict": {"passed": verdict.passed, "reasons": list(verdict.reasons)},
        }
        args.json_report.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"JSON_REPORT {args.json_report}")
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
