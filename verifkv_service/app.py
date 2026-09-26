from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, status

from app.models.verifkv import VerifKVEvent

from verifkv_service.store import VerifKVStore
from verifkv_service.watchdog import (
    BackendWatchdog,
)
from verifkv_service.writer import (
    VerifKVWriter,
)


class VerifKVApplicationState:

    def __init__(
        self,
        db_path: str,
        hmac_secret: str,
        queue_maxsize: int,
        watch_interval_seconds: float,
        watch_timeout_seconds: float,
    ) -> None:

        self.store = VerifKVStore(
            db_path=db_path,
            hmac_secret=hmac_secret,
        )

        self.writer = VerifKVWriter(
            store=self.store,
            queue_maxsize=queue_maxsize,
        )

        self.watchdog = BackendWatchdog(
            writer=self.writer,
            interval_seconds=(watch_interval_seconds),
            timeout_seconds=(watch_timeout_seconds),
        )


def create_app(
    db_path: str = "data/verifkv.db",
    hmac_secret: str = "change-me",
    queue_maxsize: int = 10_000,
    watch_interval_seconds: float = 5.0,
    watch_timeout_seconds: float = 1.5,
) -> FastAPI:

    state = VerifKVApplicationState(
        db_path=db_path,
        hmac_secret=hmac_secret,
        queue_maxsize=queue_maxsize,
        watch_interval_seconds=(watch_interval_seconds),
        watch_timeout_seconds=(watch_timeout_seconds),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):

        await state.writer.start()

        # No GPU/serving targets are registered yet.
        # They will be added during the real vLLM integration phase.
        state.watchdog.set_targets([])

        await state.watchdog.start()

        app.state.verifkv = state

        try:

            yield

        finally:

            await state.watchdog.stop()

            await state.writer.stop()

    app = FastAPI(
        title="VerifKV Provenance Service",
        version="1.0.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    async def health() -> dict:

        return {
            "status": "ok",
            "service": "verifkv",
        }

    @app.post(
        "/v1/events",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def ingest_event(
        event: VerifKVEvent,
    ) -> dict:

        accepted = state.writer.enqueue_nowait(event)

        return {
            "accepted": accepted,
            "event_id": str(event.event_id),
        }

    @app.get("/v1/verify")
    async def verify_chain() -> dict:

        return state.store.verify_chain()

    return app


app = create_app()
