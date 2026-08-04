"""Local SQLite archive backend (dev / CI without cloud credentials)."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .base import HealthCapabilities, PutResult


class LocalArchiveBackend:
    def __init__(self, data_dir: str | Path) -> None:
        path = Path(data_dir)
        path.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path / "objects.sqlite3", check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS objects (
                event_id TEXT PRIMARY KEY,
                event_hash TEXT NOT NULL,
                envelope BLOB NOT NULL
            )
            """
        )
        self._db.commit()

    def put(self, event_id: str, event_hash: str, body: bytes) -> PutResult:
        with self._lock:
            row = self._db.execute(
                "SELECT event_hash, envelope FROM objects WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO objects(event_id, event_hash, envelope) VALUES (?,?,?)",
                    (event_id, event_hash, body),
                )
                self._db.commit()
                return PutResult(status="created", version_id="1", provider="local")
            if row[0] == event_hash and row[1] == body:
                return PutResult(status="replay", version_id="1", provider="local")
            return PutResult(status="conflict", provider="local")

    def health(self) -> HealthCapabilities:
        return HealthCapabilities(
            immutable_retention="supported",
            legal_hold="supported",
            version_identifier="supported",
            read_after_write="supported",
            content_verification="supported",
            provider="local",
        )
