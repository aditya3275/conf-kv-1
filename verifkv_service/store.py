from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone
from app.models.verifkv import GENESIS_HASH
from pathlib import Path
from threading import Lock
from typing import Any

from app.models.verifkv import VerifKVEvent


class VerifKVStore:
    """
    Tamper-evident provenance store.

    Every event is converted into one deterministic canonical JSON
    representation.

    Hash chain:

        event_hash =
            SHA256(previous_hash + canonical_json)

    Authentication:

        hmac_tag =
            HMAC-SHA256(secret, event_hash)

    Important:
        The exact canonical JSON used to generate the hash is stored
        in payload_json and reused during verification. This avoids
        re-serialization differences during verification.
    """

    def __init__(
        self,
        db_path: str,
        hmac_secret: str,
    ) -> None:

        self.db_path = Path(db_path)

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.hmac_secret = hmac_secret.encode("utf-8")

        self._lock = Lock()

        self._initialize_database()

    # ---------------------------------------------------------
    # Database connection
    # ---------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:

        connection = sqlite3.connect(
            self.db_path,
            timeout=10.0,
        )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA journal_mode=WAL;")

        connection.execute("PRAGMA synchronous=NORMAL;")

        connection.execute("PRAGMA busy_timeout=10000;")

        return connection

    # ---------------------------------------------------------
    # Database initialization
    # ---------------------------------------------------------

    def _initialize_database(self) -> None:

        with self._connect() as connection:

            connection.execute("""
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
                )
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_verifkv_request_id
                ON verifkv_events(request_id)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_verifkv_tenant_id
                ON verifkv_events(tenant_id)
                """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS
                idx_verifkv_event_type
                ON verifkv_events(event_type)
                """)

            connection.commit()

    # ---------------------------------------------------------
    # Previous hash
    # ---------------------------------------------------------

    def _get_previous_hash(
        self,
        connection: sqlite3.Connection,
    ) -> str:

        row = connection.execute("""
            SELECT event_hash
            FROM verifkv_events
            ORDER BY sequence_number DESC
            LIMIT 1
            """).fetchone()

        if row is None:
            return GENESIS_HASH

        return str(row["event_hash"])

    # ---------------------------------------------------------
    # Canonical event representation
    # ---------------------------------------------------------

    @staticmethod
    def _canonicalize_event(
        event: VerifKVEvent,
    ) -> tuple[str, str]:

        timestamp = event.timestamp.astimezone(timezone.utc).isoformat()

        canonical_payload: dict[str, Any] = {
            "event_id": str(event.event_id),
            "event_type": (event.event_type.value),
            "source": event.source,
            "tenant_id": event.tenant_id,
            "request_id": event.request_id,
            "payload": event.payload,
            "timestamp": timestamp,
        }

        canonical_json = json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return (
            canonical_json,
            timestamp,
        )

    # ---------------------------------------------------------
    # Append event
    # ---------------------------------------------------------

    def append(
        self,
        event: VerifKVEvent,
    ) -> int:

        canonical_json, event_timestamp = self._canonicalize_event(event)

        with self._lock:

            with self._connect() as connection:

                previous_hash = self._get_previous_hash(connection)

                hash_input = (previous_hash + canonical_json).encode("utf-8")

                event_hash = hashlib.sha256(hash_input).hexdigest()

                hmac_tag = hmac.new(
                    self.hmac_secret,
                    event_hash.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()

                stored_at = datetime.now(timezone.utc).isoformat()

                cursor = connection.execute(
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
                        str(event.event_id),
                        event.event_type.value,
                        event.source,
                        event.tenant_id,
                        event.request_id,
                        canonical_json,
                        event_timestamp,
                        previous_hash,
                        event_hash,
                        hmac_tag,
                        stored_at,
                    ),
                )

                connection.commit()

                return int(cursor.lastrowid)

    # ---------------------------------------------------------
    # Verify complete hash chain
    # ---------------------------------------------------------

    def verify_chain(self) -> dict[str, Any]:

        with self._connect() as connection:

            rows = connection.execute("""
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
                """).fetchall()

        previous_hash = GENESIS_HASH

        verified = 0

        for row in rows:

            # -------------------------------------------------
            # 1. Verify chain linkage
            # -------------------------------------------------

            if row["previous_hash"] != previous_hash:

                return {
                    "valid": False,
                    "failed_sequence": row["sequence_number"],
                    "reason": ("chain_link_mismatch"),
                    "verified_events": verified,
                }

            # -------------------------------------------------
            # 2. Use the exact canonical JSON originally stored
            # -------------------------------------------------

            canonical_json = row["payload_json"]

            # Make sure it is valid JSON.
            try:

                json.loads(canonical_json)

            except json.JSONDecodeError:

                return {
                    "valid": False,
                    "failed_sequence": row["sequence_number"],
                    "reason": ("invalid_canonical_json"),
                    "verified_events": verified,
                }

            # -------------------------------------------------
            # 3. Recalculate event hash
            # -------------------------------------------------

            hash_input = (previous_hash + canonical_json).encode("utf-8")

            expected_hash = hashlib.sha256(hash_input).hexdigest()

            if expected_hash != row["event_hash"]:

                return {
                    "valid": False,
                    "failed_sequence": row["sequence_number"],
                    "reason": ("event_hash_mismatch"),
                    "verified_events": verified,
                }

            # -------------------------------------------------
            # 4. Verify HMAC
            # -------------------------------------------------

            expected_hmac = hmac.new(
                self.hmac_secret,
                row["event_hash"].encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(
                expected_hmac,
                row["hmac_tag"],
            ):

                return {
                    "valid": False,
                    "failed_sequence": row["sequence_number"],
                    "reason": "hmac_mismatch",
                    "verified_events": verified,
                }

            # -------------------------------------------------
            # 5. Move to next event
            # -------------------------------------------------

            previous_hash = row["event_hash"]

            verified += 1

        # -----------------------------------------------------
        # Empty database is still valid.
        # -----------------------------------------------------

        return {
            "valid": True,
            "verified_events": verified,
        }
