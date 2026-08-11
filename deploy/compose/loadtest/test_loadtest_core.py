"""Unit tests for the load-test harness's pure logic and its ``--dry-run`` path.

Run with: ``python -m pytest deploy/compose/loadtest/test_loadtest_core.py -v``

Everything in ``TestScheduleOffsets`` through ``TestSelectSustainableCeiling``
exercises ``loadtest_core.py`` directly: no network, no gRPC, no clock reads,
no gateway. ``TestDryRunIntegration`` drives ``loadtest.main()`` end to end
against ``DryRunTransport`` -- still no network -- to prove the CLI, event
construction (real ``apex_sdk.EventBuilder``, real UUIDv7 ``event_id``
generation, real canonical hashing), threaded rate scheduling, and the
PASS/FAIL verdict all wire together correctly. It does not and cannot prove
anything about the real gateway's performance; see README.md for the commands
that do.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from loadtest_core import (
    ADMITTED_OUTCOMES,
    Outcome,
    RampStepResult,
    classify_grpc_status,
    compute_latency_stats,
    evaluate_verdict,
    percentile,
    schedule_offsets,
    select_sustainable_ceiling,
)


class TestScheduleOffsets:
    def test_count_matches_rate_times_duration(self) -> None:
        offsets = schedule_offsets(rate=10.0, duration=2.0)
        assert len(offsets) == 20

    def test_starts_at_zero_and_evenly_spaced(self) -> None:
        offsets = schedule_offsets(rate=4.0, duration=1.0)
        assert offsets[0] == 0.0
        spacings = [b - a for a, b in zip(offsets, offsets[1:])]
        assert all(abs(s - 0.25) < 1e-9 for s in spacings)

    def test_high_rate_short_duration(self) -> None:
        offsets = schedule_offsets(rate=2315.0, duration=0.1)
        assert len(offsets) == round(2315.0 * 0.1)
        assert offsets == sorted(offsets)

    @pytest.mark.parametrize("rate,duration", [(0, 10), (-5, 10), (10, 0), (10, -1)])
    def test_rejects_nonpositive_inputs(self, rate: float, duration: float) -> None:
        with pytest.raises(ValueError):
            schedule_offsets(rate=rate, duration=duration)

    def test_sub_one_event_duration_still_schedules_one(self) -> None:
        # rate * duration < 1 must still produce a schedulable event, not an
        # empty run that silently reports zero attempts.
        offsets = schedule_offsets(rate=0.5, duration=1.0)
        assert len(offsets) == 1


class TestPercentile:
    def test_known_values_p50(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert percentile(values, 50) == 3.0

    def test_p0_and_p100_are_endpoints(self) -> None:
        values = [1.0, 2.0, 3.0, 10.0]
        assert percentile(values, 0) == 1.0
        assert percentile(values, 100) == 10.0

    def test_interpolates_between_ranks(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        # rank = 0.95 * 3 = 2.85 -> interpolate between values[2]=3 and values[3]=4
        assert percentile(values, 95) == pytest.approx(3.85)

    def test_empty_sequence_is_zero(self) -> None:
        assert percentile([], 50) == 0.0

    def test_single_value(self) -> None:
        assert percentile([7.5], 99) == 7.5

    def test_rejects_out_of_range_pct(self) -> None:
        with pytest.raises(ValueError):
            percentile([1.0, 2.0], 101)


class TestComputeLatencyStats:
    def test_empty_is_all_zero(self) -> None:
        stats = compute_latency_stats([])
        assert stats.count == 0
        assert stats.p50_ms == 0.0
        assert stats.max_ms == 0.0

    def test_converts_seconds_to_milliseconds(self) -> None:
        stats = compute_latency_stats([0.001, 0.002, 0.003])
        assert stats.count == 3
        assert stats.min_ms == pytest.approx(1.0)
        assert stats.max_ms == pytest.approx(3.0)
        assert stats.mean_ms == pytest.approx(2.0)

    def test_percentiles_are_ordered(self) -> None:
        import random

        rng = random.Random(42)
        samples = [rng.uniform(0.001, 0.5) for _ in range(500)]
        stats = compute_latency_stats(samples)
        assert stats.min_ms <= stats.p50_ms <= stats.p95_ms <= stats.p99_ms <= stats.max_ms


class TestClassifyGrpcStatus:
    @pytest.mark.parametrize(
        "status,expected",
        [
            ("RESOURCE_EXHAUSTED", Outcome.RESOURCE_EXHAUSTED),
            ("resource_exhausted", Outcome.RESOURCE_EXHAUSTED),
            ("UNAVAILABLE", Outcome.UNAVAILABLE),
            ("DEADLINE_EXCEEDED", Outcome.UNAVAILABLE),
            ("UNAUTHENTICATED", Outcome.AUTH_ERROR),
            ("PERMISSION_DENIED", Outcome.AUTH_ERROR),
            ("INVALID_ARGUMENT", Outcome.OTHER_ERROR),
            ("UNKNOWN", Outcome.OTHER_ERROR),
            ("", Outcome.OTHER_ERROR),
        ],
    )
    def test_mapping(self, status: str, expected: Outcome) -> None:
        assert classify_grpc_status(status) is expected

    def test_resource_exhausted_covers_both_ratelimited_and_admissionbusy(self) -> None:
        # apps/event-ingest/src/errors/code.rs maps both GatewayErrorCode::
        # RateLimited and GatewayErrorCode::AdmissionBusy to gRPC
        # RESOURCE_EXHAUSTED (see errors/gateway.rs). This client -- like the
        # SDK it is built on -- never reads server detail strings, so the two
        # are indistinguishable here by construction. This test documents
        # that as intentional rather than an oversight.
        assert classify_grpc_status("RESOURCE_EXHAUSTED") is Outcome.RESOURCE_EXHAUSTED


class TestAdmittedOutcomes:
    def test_only_accepted_and_duplicate_are_admitted(self) -> None:
        assert ADMITTED_OUTCOMES == {Outcome.ACCEPTED, Outcome.DUPLICATE}


class TestEvaluateVerdict:
    def _base_kwargs(self, **overrides):
        kwargs = dict(
            target_rate=100.0,
            achieved_rate=100.0,
            total_attempted=1000,
            outcome_counts={"accepted": 995, "duplicate": 0, "resource_exhausted": 5},
            max_reject_pct=1.0,
        )
        kwargs.update(overrides)
        return kwargs

    def test_passes_within_thresholds(self) -> None:
        verdict = evaluate_verdict(**self._base_kwargs())
        assert verdict.passed
        assert verdict.reasons == ()
        assert verdict.summary == "PASS"

    def test_duplicates_count_as_admitted(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(outcome_counts={"accepted": 500, "duplicate": 500, "resource_exhausted": 0})
        )
        assert verdict.passed

    def test_fails_on_low_achieved_rate(self) -> None:
        verdict = evaluate_verdict(**self._base_kwargs(achieved_rate=80.0))
        assert not verdict.passed
        assert any("achieved rate" in reason for reason in verdict.reasons)

    def test_fails_on_reject_pct(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(outcome_counts={"accepted": 900, "duplicate": 0, "resource_exhausted": 100})
        )
        assert not verdict.passed
        assert any("reject rate" in reason for reason in verdict.reasons)

    def test_no_attempts_fails_outright(self) -> None:
        verdict = evaluate_verdict(**self._base_kwargs(total_attempted=0, outcome_counts={}))
        assert not verdict.passed
        assert "no submissions were attempted" in verdict.reasons

    def test_backlog_within_bound_passes(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(backlog_samples=[10, 20, 15, 5], backlog_max_pending=100)
        )
        assert verdict.passed

    def test_backlog_exceeding_bound_fails(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(backlog_samples=[10, 50, 150], backlog_max_pending=100)
        )
        assert not verdict.passed
        assert any("peak outbox backlog" in reason for reason in verdict.reasons)

    def test_backlog_still_growing_at_end_fails(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(backlog_samples=[5, 20, 40, 60], backlog_max_pending=1000)
        )
        assert not verdict.passed
        assert any("still growing" in reason for reason in verdict.reasons)

    def test_backlog_draining_after_peak_passes(self) -> None:
        verdict = evaluate_verdict(
            **self._base_kwargs(backlog_samples=[5, 60, 40, 10], backlog_max_pending=1000)
        )
        assert verdict.passed

    def test_backlog_bound_without_samples_fails(self) -> None:
        verdict = evaluate_verdict(**self._base_kwargs(backlog_samples=None, backlog_max_pending=100))
        assert not verdict.passed
        assert any("no backlog samples" in reason for reason in verdict.reasons)


class TestSelectSustainableCeiling:
    def test_all_steps_within_threshold_returns_last(self) -> None:
        steps = [
            RampStepResult(rate=r, achieved_rate=r, total_attempted=100, reject_pct=0.0, outcome_counts={})
            for r in (100.0, 200.0, 300.0)
        ]
        assert select_sustainable_ceiling(steps, reject_threshold_pct=1.0) == 300.0

    def test_stops_at_first_exceedance(self) -> None:
        steps = [
            RampStepResult(rate=100.0, achieved_rate=100.0, total_attempted=100, reject_pct=0.0, outcome_counts={}),
            RampStepResult(rate=200.0, achieved_rate=200.0, total_attempted=100, reject_pct=0.5, outcome_counts={}),
            RampStepResult(rate=300.0, achieved_rate=300.0, total_attempted=100, reject_pct=5.0, outcome_counts={}),
            # A recovered step after the ceiling must not resurrect a higher ceiling.
            RampStepResult(rate=400.0, achieved_rate=400.0, total_attempted=100, reject_pct=0.0, outcome_counts={}),
        ]
        assert select_sustainable_ceiling(steps, reject_threshold_pct=1.0) == 200.0

    def test_first_step_already_over_threshold_returns_none(self) -> None:
        steps = [
            RampStepResult(rate=100.0, achieved_rate=100.0, total_attempted=100, reject_pct=50.0, outcome_counts={}),
        ]
        assert select_sustainable_ceiling(steps, reject_threshold_pct=1.0) is None

    def test_empty_steps_returns_none(self) -> None:
        assert select_sustainable_ceiling([], reject_threshold_pct=1.0) is None


class TestUuid7Helper:
    def test_generates_valid_uuidv7(self) -> None:
        import loadtest

        for _ in range(20):
            value = loadtest._uuid7()
            assert uuid.UUID(value).version == 7

    def test_generates_distinct_ids(self) -> None:
        import loadtest

        ids = {loadtest._uuid7() for _ in range(200)}
        assert len(ids) == 200


class TestDryRunIntegration:
    """End-to-end through loadtest.main() with no network at all."""

    def test_fixed_rate_dry_run_passes_and_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        import loadtest

        exit_code = loadtest.main(
            [
                "--dry-run",
                "--rate",
                "100",
                "--duration",
                "1",
                "--concurrency",
                "16",
                "--max-reject-pct",
                "5",
            ]
        )
        out = capsys.readouterr().out
        assert exit_code == 0
        assert "VERDICT    PASS" in out
        assert "OUTCOMES" in out
        assert "accepted=" in out

    def test_fixed_rate_dry_run_fails_when_rejects_forced(self, capsys: pytest.CaptureFixture[str]) -> None:
        import loadtest

        exit_code = loadtest.main(
            [
                "--dry-run",
                "--rate",
                "50",
                "--duration",
                "1",
                "--concurrency",
                "8",
                "--dry-run-reject-pct",
                "100",
                "--max-reject-pct",
                "1",
            ]
        )
        out = capsys.readouterr().out
        assert exit_code == 1
        assert "VERDICT    FAIL" in out
        assert "reject rate" in out

    def test_baseline_dry_run_finds_a_ceiling(self, capsys: pytest.CaptureFixture[str]) -> None:
        import loadtest

        exit_code = loadtest.main(
            [
                "--dry-run",
                "--baseline",
                "--ramp-start",
                "100",
                "--ramp-step",
                "100",
                "--ramp-step-duration",
                "0.3",
                "--ramp-max-rate",
                "100",
                "--concurrency",
                "16",
            ]
        )
        out = capsys.readouterr().out
        # Baseline mode always exits 0: it is discovery, not a gate.
        assert exit_code == 0
        assert "BASELINE_RESULT sustainable ceiling" in out

    def test_missing_endpoint_without_dry_run_errors(self) -> None:
        import loadtest

        with pytest.raises(SystemExit) as excinfo:
            loadtest.main(["--rate", "10", "--duration", "1"])
        assert excinfo.value.code == 2  # argparse usage-error exit code

    def test_help_does_not_crash(self) -> None:
        import loadtest

        with pytest.raises(SystemExit) as excinfo:
            loadtest.main(["--help"])
        assert excinfo.value.code == 0


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
