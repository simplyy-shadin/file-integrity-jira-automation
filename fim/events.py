from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from .crypto import canonical_json, hmac_hex, secure_compare


@dataclass(frozen=True)
class SecurityEvent:
    sequence: int
    id: str
    baseline_generation: str
    fingerprint: str
    event_type: str
    path: str
    severity: str
    detected_at: str
    old_state: dict | None
    new_state: dict | None
    details: dict
    previous_chain_hash: str
    chain_hash: str


@dataclass(frozen=True)
class Delivery:
    event_id: str
    channel: str
    status: str
    attempts: int
    next_attempt_at: str | None
    last_attempt_at: str | None
    last_error: str | None
    external_id: str | None


class EventStore:
    def __init__(self, path: Path, integrity_key: bytes):
        self.path = path
        self.integrity_key = integrity_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    baseline_generation TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    old_state_json TEXT,
                    new_state_json TEXT,
                    details_json TEXT NOT NULL,
                    previous_chain_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deliveries (
                    event_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT,
                    last_attempt_at TEXT,
                    last_error TEXT,
                    external_id TEXT,
                    PRIMARY KEY (event_id, channel),
                    FOREIGN KEY (event_id)
                        REFERENCES security_events(id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS ix_events_detected_at
                    ON security_events(detected_at);
                CREATE INDEX IF NOT EXISTS ix_events_type
                    ON security_events(event_type);
                CREATE INDEX IF NOT EXISTS ix_deliveries_due
                    ON deliveries(channel, status, next_attempt_at);
                """
            )
            try:
                self.path.chmod(0o600)
            except OSError:
                pass

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def _fingerprint(
        self,
        baseline_generation: str,
        event_type: str,
        path: str,
        old_state: dict | None,
        new_state: dict | None,
        details: dict,
    ) -> str:
        material = {
            "baseline_generation": baseline_generation,
            "event_type": event_type,
            "path": path,
            "old_state": old_state,
            "new_state": new_state,
            "details": details,
        }
        return hashlib.sha256(canonical_json(material)).hexdigest()

    def add_event(
        self,
        *,
        baseline_generation: str,
        event_type: str,
        path: str,
        severity: str,
        old_state: dict | None = None,
        new_state: dict | None = None,
        details: dict | None = None,
        queue_jira: bool = True,
    ) -> SecurityEvent | None:
        details = details or {}
        fingerprint = self._fingerprint(
            baseline_generation,
            event_type,
            path,
            old_state,
            new_state,
            details,
        )
        event_id = str(uuid4())
        detected_at = self._now()

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT id FROM security_events WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if existing:
                return None

            latest = connection.execute(
                """
                SELECT chain_hash
                FROM security_events
                ORDER BY sequence DESC
                LIMIT 1
                """
            ).fetchone()
            previous_chain_hash = latest["chain_hash"] if latest else "GENESIS"

            immutable = {
                "id": event_id,
                "baseline_generation": baseline_generation,
                "fingerprint": fingerprint,
                "event_type": event_type,
                "path": path,
                "severity": severity,
                "detected_at": detected_at,
                "old_state": old_state,
                "new_state": new_state,
                "details": details,
                "previous_chain_hash": previous_chain_hash,
            }
            chain_hash = hmac_hex(self.integrity_key, immutable)

            cursor = connection.execute(
                """
                INSERT INTO security_events (
                    id,
                    baseline_generation,
                    fingerprint,
                    event_type,
                    path,
                    severity,
                    detected_at,
                    old_state_json,
                    new_state_json,
                    details_json,
                    previous_chain_hash,
                    chain_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    baseline_generation,
                    fingerprint,
                    event_type,
                    path,
                    severity,
                    detected_at,
                    json.dumps(old_state, sort_keys=True)
                    if old_state is not None
                    else None,
                    json.dumps(new_state, sort_keys=True)
                    if new_state is not None
                    else None,
                    json.dumps(details, sort_keys=True),
                    previous_chain_hash,
                    chain_hash,
                ),
            )
            sequence = cursor.lastrowid

            if queue_jira:
                connection.execute(
                    """
                    INSERT INTO deliveries (
                        event_id,
                        channel,
                        status,
                        attempts
                    ) VALUES (?, 'jira', 'pending', 0)
                    """,
                    (event_id,),
                )

        return SecurityEvent(
            sequence=sequence,
            id=event_id,
            baseline_generation=baseline_generation,
            fingerprint=fingerprint,
            event_type=event_type,
            path=path,
            severity=severity,
            detected_at=detected_at,
            old_state=old_state,
            new_state=new_state,
            details=details,
            previous_chain_hash=previous_chain_hash,
            chain_hash=chain_hash,
        )

    def pending_deliveries(self, limit: int = 100) -> list[tuple[SecurityEvent, Delivery]]:
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    e.*,
                    d.channel AS d_channel,
                    d.status AS d_status,
                    d.attempts AS d_attempts,
                    d.next_attempt_at AS d_next_attempt_at,
                    d.last_attempt_at AS d_last_attempt_at,
                    d.last_error AS d_last_error,
                    d.external_id AS d_external_id
                FROM deliveries d
                JOIN security_events e ON e.id = d.event_id
                WHERE d.channel = 'jira'
                  AND d.status IN ('pending', 'retry')
                  AND (
                      d.next_attempt_at IS NULL
                      OR d.next_attempt_at <= ?
                  )
                ORDER BY e.sequence
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()
        return [self._row_to_pair(row) for row in rows]

    def mark_delivered(self, event_id: str, external_id: str) -> None:
        now = self._now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE deliveries
                SET
                    status = 'delivered',
                    attempts = attempts + 1,
                    last_attempt_at = ?,
                    next_attempt_at = NULL,
                    last_error = NULL,
                    external_id = ?
                WHERE event_id = ? AND channel = 'jira'
                """,
                (now, external_id, event_id),
            )

    def mark_retry(
        self,
        event_id: str,
        error: str,
        delay_seconds: int,
    ) -> None:
        now = datetime.now(UTC)
        next_attempt = now + timedelta(seconds=max(delay_seconds, 1))
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE deliveries
                SET
                    status = 'retry',
                    attempts = attempts + 1,
                    last_attempt_at = ?,
                    next_attempt_at = ?,
                    last_error = ?
                WHERE event_id = ? AND channel = 'jira'
                """,
                (
                    now.isoformat(),
                    next_attempt.isoformat(),
                    error[:1000],
                    event_id,
                ),
            )

    def mark_dead_letter(self, event_id: str, error: str) -> None:
        now = self._now()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE deliveries
                SET
                    status = 'dead_letter',
                    attempts = attempts + 1,
                    last_attempt_at = ?,
                    next_attempt_at = NULL,
                    last_error = ?
                WHERE event_id = ? AND channel = 'jira'
                """,
                (now, error[:1000], event_id),
            )

    def delivery_attempts(self, event_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT attempts
                FROM deliveries
                WHERE event_id = ? AND channel = 'jira'
                """,
                (event_id,),
            ).fetchone()
        return int(row["attempts"]) if row else 0

    def list_events(self, limit: int = 50) -> list[SecurityEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM security_events
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def delivery_status_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) AS total
                FROM deliveries
                GROUP BY status
                """
            ).fetchall()
        return {row["status"]: row["total"] for row in rows}

    def verify_chain(self) -> tuple[bool, str]:
        previous = "GENESIS"

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM security_events
                ORDER BY sequence
                """
            ).fetchall()

        for row in rows:
            immutable = {
                "id": row["id"],
                "baseline_generation": row["baseline_generation"],
                "fingerprint": row["fingerprint"],
                "event_type": row["event_type"],
                "path": row["path"],
                "severity": row["severity"],
                "detected_at": row["detected_at"],
                "old_state": self._decode_json(row["old_state_json"]),
                "new_state": self._decode_json(row["new_state_json"]),
                "details": self._decode_json(row["details_json"]) or {},
                "previous_chain_hash": row["previous_chain_hash"],
            }
            expected = hmac_hex(self.integrity_key, immutable)

            if row["previous_chain_hash"] != previous:
                return (
                    False,
                    f"Chain link mismatch at event sequence {row['sequence']}",
                )
            if not secure_compare(row["chain_hash"], expected):
                return (
                    False,
                    f"Event signature mismatch at sequence {row['sequence']}",
                )
            previous = row["chain_hash"]

        return True, f"Verified {len(rows)} event records"

    @staticmethod
    def _decode_json(value: str | None) -> Any:
        return json.loads(value) if value is not None else None

    @classmethod
    def _row_to_event(cls, row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            sequence=row["sequence"],
            id=row["id"],
            baseline_generation=row["baseline_generation"],
            fingerprint=row["fingerprint"],
            event_type=row["event_type"],
            path=row["path"],
            severity=row["severity"],
            detected_at=row["detected_at"],
            old_state=cls._decode_json(row["old_state_json"]),
            new_state=cls._decode_json(row["new_state_json"]),
            details=cls._decode_json(row["details_json"]) or {},
            previous_chain_hash=row["previous_chain_hash"],
            chain_hash=row["chain_hash"],
        )

    @classmethod
    def _row_to_pair(
        cls,
        row: sqlite3.Row,
    ) -> tuple[SecurityEvent, Delivery]:
        event = cls._row_to_event(row)
        delivery = Delivery(
            event_id=row["id"],
            channel=row["d_channel"],
            status=row["d_status"],
            attempts=row["d_attempts"],
            next_attempt_at=row["d_next_attempt_at"],
            last_attempt_at=row["d_last_attempt_at"],
            last_error=row["d_last_error"],
            external_id=row["d_external_id"],
        )
        return event, delivery
