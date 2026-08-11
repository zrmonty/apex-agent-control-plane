"""Pure logic for the ``event-ingest`` load-test harness: no network, no gRPC,
no filesystem, no clock reads of its own.

Everything here is a function of its arguments, which is what lets
``test_loadtest_core.py`` exercise rate scheduling, percentile computation, and
the pass/fail verdict without a live gateway, a live Postgres, or even
``grpc`` installed. ``loadtest.py`` is the thin, effectful shell that reads
real clocks, opens real sockets, and calls into this module for every decision
that has a right answer independent of the environment it runs in.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

# --------------------------------------------------------------------------
# Outcome classification
# --------------------------------------------------------------------------


class Outcome(str, Enum):
    """What happened to one submitted event, as observed by this client.

    ``RESOURCE_EXHAUSTED`` deliberately does not split into ``RateLimited``
    and ``AdmissionBusy``. Both are ``apps/event-ingest/src/errors/code.rs``
    gateway error codes that map to the *same* gRPC status
    (``RESOURCE_EXHAUSTED``, see ``errors/gateway.rs``), and this client -- like
    ``apex_sdk.ingest_transport.GrpcEventIngestTransport._status_name`` -- never
    reads ``details()`` on a server error, by design (a server-supplied string
    is attacker-influenced from the client's point of view). So the two codes
    are genuinely indistinguishable at this boundary without inventing a
    channel the production SDK does not have. Reporting them as one honest
    bucket is more useful than a fabricated split.
    """

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    RESOURCE_EXHAUSTED = "resource_exhausted"  # RateLimited or AdmissionBusy
    UNAVAILABLE = "unavailable"  # UNAVAILABLE or DEADLINE_EXCEEDED
    AUTH_ERROR = "auth_error"  # UNAUTHENTICATED or PERMISSION_DENIED
    OTHER_ERROR = "other_error"


#: Outcomes that count as "the gateway durably admitted this event" for
#: throughput purposes. A duplicate is a successful idempotent replay, not a
#: rejection -- exactly the distinction ``GrpcEventIngestTransport.ingest``
#: already encodes in its boolean return.
ADMITTED_OUTCOMES = frozenset({Outcome.ACCEPTED, Outcome.DUPLICATE})


def classify_grpc_status(status: str) -> Outcome:
    """Maps a gRPC status name (never a server detail string) to an :class:`Outcome`."""
    name = (status or "").upper()
    if name == "RESOURCE_EXHAUSTED":
        return Outcome.RESOURCE_EXHAUSTED
    if name in {"UNAVAILABLE", "DEADLINE_EXCEEDED"}:
        return Outcome.UNAVAILABLE
    if name in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
        return Outcome.AUTH_ERROR
    return Outcome.OTHER_ERROR


# --------------------------------------------------------------------------
# Rate scheduling
# --------------------------------------------------------------------------


def schedule_offsets(rate: float, duration: float) -> list[float]:
    """Ideal send offsets (seconds from run start) for an open-loop, constant-rate load.

    Evenly spaced ``1/rate`` apart, starting at ``0.0``. "Open-loop" means the
    schedule does not wait for one submission to finish before the next is
    due -- exactly what a fleet of independent agents emitting events at a
    steady rate would do, and the only way to find the gateway's real ceiling
    rather than the ceiling of "one request at a time". Deterministic and pure
    so it is unit-testable without a clock.
    """
    if rate <= 0:
        raise ValueError("rate must be positive")
    if duration <= 0:
        raise ValueError("duration must be positive")
    count = max(1, round(rate * duration))
    interval = 1.0 / rate
    return [i * interval for i in range(count)]


# --------------------------------------------------------------------------
# Latency percentiles
# --------------------------------------------------------------------------


def percentile(sorted_values: Sequence[float], pct: float) -> float:
    """Linear-interpolation percentile over an already-sorted sequence.

    Standard "R-7" method (the one NumPy's ``interpolation="linear"`` and most
    load-test tooling use): interpolates between the two nearest ranks rather
    than picking a single nearest sample, so p50 of an even-length list is the
    mean of the two middle values instead of an arbitrary pick.
    """
    if not sorted_values:
        return 0.0
    if not 0 <= pct <= 100:
        raise ValueError("pct must be within 0..100")
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return sorted_values[int(rank)]
    fraction = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * fraction


@dataclass(frozen=True)
class LatencyStats:
    count: int
    min_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float

    def as_dict(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "min_ms": round(self.min_ms, 3),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "max_ms": round(self.max_ms, 3),
            "mean_ms": round(self.mean_ms, 3),
        }


def compute_latency_stats(latency_seconds: Sequence[float]) -> LatencyStats:
    if not latency_seconds:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    values_ms = sorted(value * 1000.0 for value in latency_seconds)
    return LatencyStats(
        count=len(values_ms),
        min_ms=values_ms[0],
        p50_ms=percentile(values_ms, 50),
        p95_ms=percentile(values_ms, 95),
        p99_ms=percentile(values_ms, 99),
        max_ms=values_ms[-1],
        mean_ms=sum(values_ms) / len(values_ms),
    )


# --------------------------------------------------------------------------
# Pass/fail verdict
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class VerdictResult:
    passed: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def summary(self) -> str:
        return "PASS" if self.passed else "FAIL"


def evaluate_verdict(
    *,
    target_rate: float,
    achieved_rate: float,
    total_attempted: int,
    outcome_counts: Mapping[str, int],
    max_reject_pct: float,
    min_rate_ratio: float = 0.95,
    backlog_samples: Sequence[int] | None = None,
    backlog_max_pending: int | None = None,
) -> VerdictResult:
    """Decides PASS/FAIL for one fixed-rate run against a target.

    Three independent gates, each optional except the first two:

    1. Achieved throughput must reach ``min_rate_ratio`` of the target rate.
       A harness that quietly fell behind its own schedule (client-side
       bottleneck, not gateway saturation) must not pass by accident.
    2. The reject percentage (everything that is not Accepted or Duplicate)
       must not exceed ``max_reject_pct``.
    3. If backlog samples and a bound are supplied, the observed peak must not
       exceed the bound, and the backlog must not still be growing at the end
       of the run (a queue that never drains fails a regression gate even if
       every individual submission was accepted).

    Pure: takes already-computed numbers, decides, returns a reason list. No
    side effects, so every branch is directly unit-testable.
    """
    if total_attempted <= 0:
        return VerdictResult(False, ("no submissions were attempted",))

    reasons: list[str] = []
    accepted = sum(outcome_counts.get(outcome.value, 0) for outcome in ADMITTED_OUTCOMES)
    rejected = total_attempted - accepted
    reject_pct = (rejected / total_attempted) * 100.0

    min_acceptable_rate = target_rate * min_rate_ratio
    if achieved_rate < min_acceptable_rate:
        reasons.append(
            f"achieved rate {achieved_rate:.1f}/s is below {min_rate_ratio:.0%} of "
            f"target {target_rate:.1f}/s (minimum {min_acceptable_rate:.1f}/s)"
        )

    if reject_pct > max_reject_pct:
        reasons.append(
            f"reject rate {reject_pct:.2f}% ({rejected}/{total_attempted}) exceeds "
            f"the {max_reject_pct:.2f}% threshold"
        )

    if backlog_max_pending is not None:
        if not backlog_samples:
            reasons.append("backlog bound was set but no backlog samples were collected")
        else:
            peak = max(backlog_samples)
            if peak > backlog_max_pending:
                reasons.append(f"peak outbox backlog {peak} exceeds the bound {backlog_max_pending}")
            if (
                len(backlog_samples) >= 2
                and backlog_samples[-1] >= peak
                and backlog_samples[-1] > backlog_samples[0]
            ):
                reasons.append(
                    f"outbox backlog is still growing at the end of the run "
                    f"(first={backlog_samples[0]}, last={backlog_samples[-1]}, peak={peak})"
                )

    return VerdictResult(passed=not reasons, reasons=tuple(reasons))


# --------------------------------------------------------------------------
# Baseline / ramp mode
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RampStepResult:
    rate: float
    achieved_rate: float
    total_attempted: int
    reject_pct: float
    outcome_counts: Mapping[str, int]


def select_sustainable_ceiling(steps: Sequence[RampStepResult], reject_threshold_pct: float) -> float | None:
    """Finds the highest ramp rate that stayed under ``reject_threshold_pct``.

    ``steps`` must be in ascending-rate order (the order the ramp actually ran
    in). Returns the rate of the last step at or below the threshold, stopping
    at the first step that exceeds it -- once the gateway starts shedding load
    at a given target rate, a later, less-loaded window recovering briefly
    does not un-find the ceiling. Returns ``None`` if every step, including the
    first, already exceeded the threshold (the ceiling is below the ramp's
    starting rate).
    """
    ceiling: float | None = None
    for step in steps:
        if step.reject_pct <= reject_threshold_pct:
            ceiling = step.rate
        else:
            break
    return ceiling
