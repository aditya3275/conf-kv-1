from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import aiosqlite

from app.models.enums import Zone
from app.models.outbox import OutboxRecord
from app.models.verifkv import (
    GENESIS_HASH,
    VerifKVEventType,
)

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
    sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,

    event_id TEXT NOT NULL UNIQUE,

    event_type TEXT NOT NULL,

    source TEXT NOT NULL,

    tenant_id TEXT,

    request_id TEXT,

    payload_json TEXT NOT NULL,

    event_timestamp TEXT NOT NULL,

    previous_hash TEXT NOT NULL,

    event_hash TEXT NOT NULL,

    hmac_tag TEXT NOT NULL,

    stored_at TEXT NOT NULL
);
"""


class VerifKVStore:
    """
    SQLite persistence layer for:

        1. Durable authorization outbox.
        2. VerifKV tamper-evident hash chain.

    The authorization outbox is written synchronously and durably
    before the request is forwarded to the inference backend.

    A single VerifKVWriter asynchronously folds outbox records into
    the VerifKV hash chain.

    The outbox update and corresponding VerifKV event insertion happen
    in one SQLite transaction.
    """

    def __init__(
        self,
        db_path: str,
        hmac_secret: str,
    ) -> None:
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

    # ------------------------------------------------------------------
    # Durable authorization outbox
    # ------------------------------------------------------------------

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

        SQLite generates outbox_seq using AUTOINCREMENT.
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
        Return all authorization records that have not yet been
        incorporated into VerifKV.

        Records are returned in durable outbox sequence order.
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
                    authorization_event_id=(row["authorization_event_id"]),
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

    # ------------------------------------------------------------------
    # Hash-chain helpers
    # ------------------------------------------------------------------

    async def _get_last_hash(self) -> str:
        db = self._require_db()

        cursor = await db.execute("""
            SELECT event_hash
            FROM verifkv_events
            ORDER BY sequence_number DESC
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
        Convert one durable authorization outbox record into
        a VerifKV AUTHZ_DECISION event.

        Event insertion and outbox reconciliation are committed
        atomically.
        """

        db = self._require_db()

        if record.outbox_seq is None:
            raise ValueError("Cannot fold outbox record without outbox_seq")

        await db.execute("BEGIN IMMEDIATE")

        try:
            # ----------------------------------------------------------
            # Re-check the durable record.
            # ----------------------------------------------------------

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

            # ----------------------------------------------------------
            # Determine previous hash.
            # ----------------------------------------------------------

            previous_hash = await self._get_last_hash()

            event_id = record.authorization_event_id

            event_timestamp = record.timestamp.isoformat()

            event_type = VerifKVEventType.AUTHZ_DECISION.value

            source = "control-plane"

            # ----------------------------------------------------------
            # Build deterministic event payload.
            # ----------------------------------------------------------

            payload = {
                "decision": record.decision,
                "backend_id": record.backend_id,
                "zone": record.zone,
                "decision_id": record.decision_id,
                "policy_version": record.policy_version,
                "outbox_seq": record.outbox_seq,
                **record.payload,
            }

            # ----------------------------------------------------------
            # Canonical event representation.
            #
            # source participates in the hash because it is part of
            # the persisted VerifKV event identity.
            #
            # stored_at intentionally does NOT participate in hashing;
            # it is persistence metadata rather than event semantics.
            # ----------------------------------------------------------

            canonical_event = json.dumps(
                {
                    "event_id": event_id,
                    "event_type": event_type,
                    "source": source,
                    "tenant_id": record.tenant_id,
                    "request_id": record.request_id,
                    "payload": payload,
                    "timestamp": event_timestamp,
                    "prev_hash": previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )

            # ----------------------------------------------------------
            # Hash chain.
            # ----------------------------------------------------------

            event_hash = hashlib.sha256(
                (previous_hash + canonical_event).encode("utf-8")
            ).hexdigest()

            # ----------------------------------------------------------
            # HMAC integrity tag.
            # ----------------------------------------------------------

            hmac_tag = hmac.new(
                self.hmac_secret,
                event_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            stored_at = datetime.now(timezone.utc).isoformat()

            # ----------------------------------------------------------
            # Insert immutable VerifKV event.
            # ----------------------------------------------------------

            insert_cursor = await db.execute(
                """
                INSERT INTO verifkv_events (
                    event_id,
                    event_type,
                    source,
                    tenant_id,
                    request_id,
                    payload_json,
                    event_timestamp,
                    previous_hash,
                    event_hash,
                    hmac_tag,
                    stored_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    source,
                    record.tenant_id,
                    record.request_id,
                    json.dumps(
                        payload,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    event_timestamp,
                    previous_hash,
                    event_hash,
                    hmac_tag,
                    stored_at,
                ),
            )

            sequence_number = insert_cursor.lastrowid

            if sequence_number is None:
                raise RuntimeError("SQLite did not return VerifKV sequence")

            # ----------------------------------------------------------
            # Mark the durable outbox record reconciled.
            # ----------------------------------------------------------

            await db.execute(
                """
                UPDATE authz_outbox
                SET verifkv_seq = ?
                WHERE outbox_seq = ?
                """,
                (
                    int(sequence_number),
                    record.outbox_seq,
                ),
            )

            # ----------------------------------------------------------
            # Commit both operations atomically.
            # ----------------------------------------------------------

            await db.commit()

            return int(sequence_number)

        except Exception:
            await db.rollback()
            raise

    # ------------------------------------------------------------------
    # Chain verification
    # ------------------------------------------------------------------

    async def verify_chain(
        self,
    ) -> tuple[bool, str]:
        """
        Recompute and verify the complete VerifKV chain.

        Returns:

            (True, "VerifKV chain is valid")

        or:

            (False, <explanation>)
        """

        db = self._require_db()

        cursor = await db.execute("""
            SELECT
                sequence_number,
                event_id,
                event_type,
                source,
                tenant_id,
                request_id,
                payload_json,
                event_timestamp,
                previous_hash,
                event_hash,
                hmac_tag
            FROM verifkv_events
            ORDER BY sequence_number ASC
            """)

        rows = await cursor.fetchall()

        previous_hash = GENESIS_HASH

        for row in rows:
            payload = json.loads(row["payload_json"])

            canonical_event = json.dumps(
                {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "source": row["source"],
                    "tenant_id": row["tenant_id"],
                    "request_id": row["request_id"],
                    "payload": payload,
                    "timestamp": row["event_timestamp"],
                    "prev_hash": row["previous_hash"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )

            # ----------------------------------------------------------
            # Previous-hash linkage.
            # ----------------------------------------------------------

            if row["previous_hash"] != previous_hash:
                return (
                    False,
                    ("Broken chain at " f"sequence_number={row['sequence_number']}"),
                )

            # ----------------------------------------------------------
            # Event-hash verification.
            # ----------------------------------------------------------

            expected_hash = hashlib.sha256(
                (previous_hash + canonical_event).encode("utf-8")
            ).hexdigest()

            if expected_hash != row["event_hash"]:
                return (
                    False,
                    (
                        "Event hash mismatch at "
                        f"sequence_number={row['sequence_number']}"
                    ),
                )

            # ----------------------------------------------------------
            # HMAC verification.
            # ----------------------------------------------------------

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
                    ("HMAC mismatch at " f"sequence_number={row['sequence_number']}"),
                )

            previous_hash = row["event_hash"]

        return (
            True,
            "VerifKV chain is valid",
        )
