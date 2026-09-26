from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import aiosqlite

from app.models.enums import Zone
from app.models.outbox import OutboxRecord
from app.models.verifkv import GENESIS_HASH

logger = logging.getLogger(__name__)


OUTBOX_AND_VERIFKV_SCHEMA = """
CREATE TABLE IF NOT EXISTS authz_outbox (
    outbox_seq INTEGER PRIMARY KEY AUTOINCREMENT,

    authorization_event_id TEXT NOT NULL UNIQUE,

    request_id TEXT NOT NULL,

    tenant_id TEXT NOT NULL,

    decision INTEGER NOT NULL,

    backend_id TEXT NOT NULL,

    zone TEXT NOT NULL,

    decision_id TEXT NOT NULL,

    policy_version TEXT NOT NULL,

    timestamp TEXT NOT NULL,

    payload TEXT NOT NULL,

    verifkv_seq INTEGER NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_unreconciled
ON authz_outbox(outbox_seq)
WHERE verifkv_seq IS NULL;


CREATE TABLE IF NOT EXISTS verifkv_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,

    event_id TEXT NOT NULL UNIQUE,

    event_type TEXT NOT NULL,

    tenant_id TEXT NULL,

    request_id TEXT NULL,

    payload TEXT NOT NULL,

    timestamp TEXT NOT NULL,

    prev_hash TEXT NOT NULL,

    event_hash TEXT NOT NULL,

    hmac_tag TEXT NOT NULL
);
"""


class VerifKVStore:
    """
    SQLite persistence layer for the durable authorization outbox
    and the VerifKV hash chain.

    This class owns one dedicated SQLite connection.

    Important:
        - authorization outbox writes are synchronous/durable
        - chain folding is performed by the single VerifKV writer
        - both outbox update and chain insertion happen transactionally
    """

    def __init__(
        self,
        db_path: str,
        hmac_secret: str,
    ):
        self.db_path = db_path
        self.hmac_secret = hmac_secret.encode("utf-8")

        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db = await aiosqlite.connect(
            self.db_path,
            isolation_level=None,
        )

        self._db.row_factory = aiosqlite.Row

        await self._db.execute("PRAGMA journal_mode = WAL")

        await self._db.execute("PRAGMA synchronous = NORMAL")

        await self._db.execute("PRAGMA busy_timeout = 5000")

        await self._db.executescript(OUTBOX_AND_VERIFKV_SCHEMA)

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    def _require_db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("VerifKVStore is not initialized")

        return self._db

    async def append_authorization_outbox(
        self,
        *,
        request_id: UUID,
        tenant_id: str,
        decision: bool,
        backend_id: str,
        zone: Zone,
        decision_id: str,
        policy_version: str,
        timestamp: datetime,
        payload: dict[str, Any],
    ) -> int:
        """
        Durably records an authorization decision.

        The transaction MUST complete before the caller forwards
        the request to the LLM serving backend.

        The database generates outbox_seq using AUTOINCREMENT.
        """
        db = self._require_db()

        authorization_event_id = str(uuid4())

        await db.execute("BEGIN IMMEDIATE")

        try:
            cursor = await db.execute(
                """
                INSERT INTO authz_outbox (
                    authorization_event_id,
                    request_id,
                    tenant_id,
                    decision,
                    backend_id,
                    zone,
                    decision_id,
                    policy_version,
                    timestamp,
                    payload,
                    verifkv_seq
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    authorization_event_id,
                    str(request_id),
                    tenant_id,
                    int(decision),
                    backend_id,
                    zone.value,
                    decision_id,
                    policy_version,
                    timestamp.isoformat(),
                    json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )

            outbox_seq = cursor.lastrowid

            await db.commit()

            if outbox_seq is None:
                raise RuntimeError("SQLite did not return outbox sequence")

            return int(outbox_seq)

        except Exception:
            await db.rollback()
            raise

    async def get_unreconciled_outbox(
        self,
    ) -> list[OutboxRecord]:
        """
        Returns all authorization records that have not yet
        been incorporated into VerifKV.

        Ordered by database-generated outbox sequence.
        """
        db = self._require_db()

        cursor = await db.execute("""
            SELECT
                outbox_seq,
                authorization_event_id,
                request_id,
                tenant_id,
                decision,
                backend_id,
                zone,
                decision_id,
                policy_version,
                timestamp,
                payload,
                verifkv_seq
            FROM authz_outbox
            WHERE verifkv_seq IS NULL
            ORDER BY outbox_seq ASC
            """)

        rows = await cursor.fetchall()

        records: list[OutboxRecord] = []

        for row in rows:
            records.append(
                OutboxRecord(
                    outbox_seq=row["outbox_seq"],
                    authorization_event_id=row["authorization_event_id"],
                    request_id=row["request_id"],
                    tenant_id=row["tenant_id"],
                    decision=bool(row["decision"]),
                    backend_id=row["backend_id"],
                    zone=row["zone"],
                    decision_id=row["decision_id"],
                    policy_version=row["policy_version"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    payload=json.loads(row["payload"]),
                    verifkv_seq=row["verifkv_seq"],
                )
            )

        return records

    async def _get_last_hash(
        self,
    ) -> str:
        db = self._require_db()

        cursor = await db.execute("""
            SELECT event_hash
            FROM verifkv_events
            ORDER BY seq DESC
            LIMIT 1
            """)

        row = await cursor.fetchone()

        if row is None:
            return GENESIS_HASH

        return row["event_hash"]

    async def fold_outbox_record(
        self,
        record: OutboxRecord,
    ) -> int:
        """
        Converts one durable outbox record into a VerifKV event.

        IMPORTANT:
            Event insertion and outbox reconciliation are performed
            in ONE transaction.

        Therefore:
            either both happen,
            or neither happens.
        """
        db = self._require_db()

        if record.outbox_seq is None:
            raise ValueError("Cannot fold outbox record without outbox_seq")

        await db.execute("BEGIN IMMEDIATE")

        try:
            # Re-check because another recovery cycle may have already
            # processed the record.
            cursor = await db.execute(
                """
                SELECT
                    verifkv_seq
                FROM authz_outbox
                WHERE outbox_seq = ?
                """,
                (record.outbox_seq,),
            )

            current = await cursor.fetchone()

            if current is None:
                raise RuntimeError("Outbox record disappeared during reconciliation")

            if current["verifkv_seq"] is not None:
                await db.commit()
                return int(current["verifkv_seq"])

            prev_hash = await self._get_last_hash()

            event_id = record.authorization_event_id

            event_timestamp = record.timestamp.isoformat()

            payload = {
                "decision": record.decision,
                "backend_id": record.backend_id,
                "zone": record.zone,
                "decision_id": record.decision_id,
                "policy_version": record.policy_version,
                "outbox_seq": record.outbox_seq,
                **record.payload,
            }

            canonical_event = json.dumps(
                {
                    "event_id": event_id,
                    "event_type": "authz_decision",
                    "tenant_id": record.tenant_id,
                    "request_id": record.request_id,
                    "payload": payload,
                    "timestamp": event_timestamp,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )

            import hashlib
            import hmac

            event_hash = hashlib.sha256(
                (prev_hash + canonical_event).encode("utf-8")
            ).hexdigest()

            hmac_tag = hmac.new(
                self.hmac_secret,
                event_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            insert_cursor = await db.execute(
                """
                INSERT INTO verifkv_events (
                    event_id,
                    event_type,
                    tenant_id,
                    request_id,
                    payload,
                    timestamp,
                    prev_hash,
                    event_hash,
                    hmac_tag
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    "authz_decision",
                    record.tenant_id,
                    record.request_id,
                    json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    event_timestamp,
                    prev_hash,
                    event_hash,
                    hmac_tag,
                ),
            )

            verifkv_seq = insert_cursor.lastrowid

            if verifkv_seq is None:
                raise RuntimeError("SQLite did not return VerifKV sequence")

            await db.execute(
                """
                UPDATE authz_outbox
                SET verifkv_seq = ?
                WHERE outbox_seq = ?
                """,
                (
                    int(verifkv_seq),
                    record.outbox_seq,
                ),
            )

            await db.commit()

            return int(verifkv_seq)

        except Exception:
            await db.rollback()
            raise

    async def verify_chain(
        self,
    ) -> tuple[bool, str]:
        """
        Recomputes the entire VerifKV chain.

        Returns:
            (valid, explanation)
        """
        db = self._require_db()

        cursor = await db.execute("""
            SELECT
                seq,
                event_id,
                event_type,
                tenant_id,
                request_id,
                payload,
                timestamp,
                prev_hash,
                event_hash,
                hmac_tag
            FROM verifkv_events
            ORDER BY seq ASC
            """)

        rows = await cursor.fetchall()

        import hashlib
        import hmac

        previous_hash = GENESIS_HASH

        for row in rows:
            payload = json.loads(row["payload"])

            canonical_event = json.dumps(
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "tenant_id": row["tenant_id"],
                    "request_id": row["request_id"],
                    "payload": payload,
                    "timestamp": row["timestamp"],
                    "prev_hash": row["prev_hash"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )

            if row["prev_hash"] != previous_hash:
                return (
                    False,
                    f"Broken chain at seq={row['seq']}",
                )

            expected_hash = hashlib.sha256(
                (previous_hash + canonical_event).encode("utf-8")
            ).hexdigest()

            if expected_hash != row["event_hash"]:
                return (
                    False,
                    f"Event hash mismatch at seq={row['seq']}",
                )

            expected_hmac = hmac.new(
                self.hmac_secret,
                row["event_hash"].encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(
                expected_hmac,
                row["hmac_tag"],
            ):
                return (
                    False,
                    f"HMAC mismatch at seq={row['seq']}",
                )

            previous_hash = row["event_hash"]

        return (
            True,
            "VerifKV chain is valid",
        )
