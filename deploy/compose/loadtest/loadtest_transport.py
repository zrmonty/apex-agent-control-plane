"""Transport and optional outbox sampling for the load-test harness."""

from __future__ import annotations

import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from apex_sdk.exporter import GrpcStatusError

OUTBOX_BACKLOG_QUERY = "SELECT count(*) FROM apex_event_outbox WHERE state = 'pending'"


def _uuid7() -> str:
    milliseconds = int(datetime.now(UTC).timestamp() * 1000)
    raw = bytearray(uuid.uuid4().bytes)
    raw[0:6] = milliseconds.to_bytes(6, "big")
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(raw)))


class Ingestor(Protocol):
    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool: ...

    def close(self) -> None: ...


class DryRunTransport:
    """Exercise the transport call shape without a network."""

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


def sample_outbox_pending(dsn: str) -> int:
    """Return the pending-row count from a read-capable Postgres DSN."""
    try:
        import psycopg  # noqa: PLC0415
    except ImportError:
        try:
            import psycopg2 as psycopg  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError(
                "backlog sampling needs psycopg or psycopg2; "
                f"otherwise inspect manually with: {OUTBOX_BACKLOG_QUERY}"
            ) from exc
    conn = psycopg.connect(dsn, connect_timeout=5)
    try:
        with conn.cursor() as cursor:
            cursor.execute(OUTBOX_BACKLOG_QUERY)
            row = cursor.fetchone()
            return int(row[0])
    finally:
        conn.close()


@dataclass
class BacklogSampler:
    """Sample outbox depth on a daemon thread during a load run."""

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
            except Exception as exc:  # noqa: BLE001 - sampling must not kill a run
                self._errors.append(f"{type(exc).__name__}: {exc}")
            self._stop.wait(self.interval_s)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_s + 5)

    @property
    def samples(self) -> list[tuple[float, int]]:
        return list(self._samples)

    @property
    def errors(self) -> list[str]:
        return list(self._errors)
