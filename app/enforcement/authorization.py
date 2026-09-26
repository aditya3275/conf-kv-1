from __future__ import annotations

from typing import Protocol

from app.models.verifkv import VerifKVEvent


class VerifKVEventSink(Protocol):
    """
    Non-blocking event sink used by the inference request path.

    The implementation must:
    - never wait for network I/O
    - never perform database I/O
    - never perform durable writes synchronously
    - return immediately
    """

    def emit_nowait(self, event: VerifKVEvent) -> bool:
        """
        Queue an event for asynchronous provenance processing.

        Returns:
            True  -> event accepted into the local queue
            False -> event was dropped because the queue was full
        """
        ...
