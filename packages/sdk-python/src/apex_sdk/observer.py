"""Non-blocking event observation with bounded background delivery."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Lock, Thread
from typing import Any, Callable, Protocol

from .diagnostics import DiagnosticReporter, EmergencySpool
from .errors import ApexError, ConfigurationError, ObserverExportError
from .validation import validate_event

MAX_JSONL_RECORD_BYTES = 1 * 1024 * 1024
MAX_JSONL_FILE_BYTES = 256 * 1024 * 1024


class EventSink(Protocol):
    def write(self, event: dict[str, Any]) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class ObserverStats:
    accepted: int
    dropped: int
    exported: int
    failed: int


class JsonlSink:
    """Append events as compact, deterministic JSON Lines."""

    def __init__(self, path: str | Path, *, base_dir: str | Path) -> None:
        try:
            requested_path = Path(path)
            if requested_path.is_symlink():
                raise ConfigurationError("JSONL sink path must not be a symbolic link")
            base_path = Path(base_dir).resolve(strict=True)
            resolved_path = requested_path.resolve(strict=False)
        except OSError as exc:
            raise ConfigurationError("JSONL sink paths must resolve within an existing configured base directory") from exc
        if resolved_path != base_path and base_path not in resolved_path.parents:
            raise ConfigurationError("JSONL sink path must remain within the configured base directory")
        try:
            self._file = resolved_path.open("a", encoding="utf-8", newline="\n")
        except OSError as exc:
            raise ConfigurationError("JSONL sink storage could not be opened within the configured base directory") from exc
        try:
            if self._file.seek(0, 2) > MAX_JSONL_FILE_BYTES:
                self._file.close()
                raise ConfigurationError("JSONL sink file exceeds the configured storage limit; rotate it before retrying")
        except OSError as exc:
            self._file.close()
            raise ConfigurationError("JSONL sink size could not be verified") from exc

    def write(self, event: dict[str, Any]) -> None:
        validate_event(event)
        line = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
        encoded_size = len(line.encode("utf-8"))
        if encoded_size > MAX_JSONL_RECORD_BYTES:
            raise ObserverExportError("JSONL event exceeds the per-record storage limit")
        try:
            current_size = self._file.seek(0, 2)
        except OSError as exc:
            raise ObserverExportError("JSONL sink size could not be checked") from exc
        if current_size + encoded_size > MAX_JSONL_FILE_BYTES:
            raise ObserverExportError("JSONL sink reached its storage limit; rotate it before retrying")
        self._file.write(line)
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class BoundedObserver:
    """Queues export work without ever blocking an instrumented agent."""

    def __init__(self, sink: EventSink, *, capacity: int = 1_024, diagnostic_reporter: DiagnosticReporter | None = None, emergency_spool: EmergencySpool | None = None, drop_reporter: Callable[[str], None] | None = None) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ConfigurationError("observer capacity must be at least one")
        self._sink = sink
        self._queue: Queue[dict[str, Any]] = Queue(maxsize=capacity)
        self._lock = Lock()
        self._closed = False
        self._accepted = 0
        self._dropped = 0
        self._exported = 0
        self._failed = 0
        self._diagnostic_reporter = diagnostic_reporter
        self._emergency_spool = emergency_spool
        self._drop_reporter = drop_reporter
        self._worker = Thread(target=self._run, name="apex-observer", daemon=True)
        self._worker.start()

    @property
    def stats(self) -> ObserverStats:
        with self._lock:
            return ObserverStats(self._accepted, self._dropped, self._exported, self._failed)

    def emit(self, event: dict[str, Any]) -> bool:
        """Accept an event if space is available; otherwise drop the newest one."""
        with self._lock:
            if self._closed:
                self._record_drop("closed")
                return False
        try:
            validate_event(event)
            snapshot = copy.deepcopy(event)
        except ApexError as error:
            with self._lock:
                self._record_drop("validation")
            self._report_error(error, event if isinstance(event, dict) else {})
            return False
        except Exception:
            with self._lock:
                self._record_drop("snapshot")
            self._report_error(ObserverExportError(), event if isinstance(event, dict) else {})
            return False
        with self._lock:
            if self._closed:
                self._record_drop("closed")
                return False
            try:
                self._queue.put_nowait(snapshot)
            except Full:
                self._record_drop("queue_full")
                return False
            self._accepted += 1
            return True

    def _record_drop(self, reason: str) -> None:
        self._dropped += 1
        if self._drop_reporter is not None:
            try:
                self._drop_reporter(reason)
            except Exception:
                # Metrics must never make the telemetry boundary fail open or
                # block the instrumented agent.
                return

    def close(self, *, timeout: float | None = None) -> bool:
        """Stop accepting events and report whether the worker fully drained.

        A false result means the timeout expired while work was still queued or
        being written; callers performing fast shutdown must treat that as an
        incomplete audit flush and use the durable spool/retry path.
        """
        with self._lock:
            if self._closed:
                return not self._worker.is_alive()
            self._closed = True
        self._worker.join(timeout)
        return not self._worker.is_alive()

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get(timeout=0.05)
            except Empty:
                with self._lock:
                    closed = self._closed
                if closed:
                    try:
                        self._sink.close()
                    except Exception:
                        with self._lock:
                            self._failed += 1
                        self._report_error(ObserverExportError(), {})
                    return
                continue
            try:
                try:
                    self._sink.write(item)
                    with self._lock:
                        self._exported += 1
                except ApexError as error:
                    with self._lock:
                        self._failed += 1
                    self._report_error(error, item)
                except Exception:
                    with self._lock:
                        self._failed += 1
                    self._report_error(ObserverExportError(), item)
            finally:
                self._queue.task_done()

    def _report_error(self, error: ApexError, event: dict[str, Any]) -> None:
        if self._diagnostic_reporter is None:
            return
        correlation: dict[str, str] = {}
        for key in ("event_id", "trace_id", "run_id"):
            try:
                value = event.get(key)
            except Exception:
                continue
            if isinstance(value, str):
                correlation[key] = value
        error.correlation = {**error.correlation, **correlation}
        try:
            self._diagnostic_reporter.capture(error, component="sdk.observer")
        except Exception:
            if self._emergency_spool is not None:
                try:
                    self._emergency_spool.write(error, component="sdk.observer")
                except Exception:
                    return
