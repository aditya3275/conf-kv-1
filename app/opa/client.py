from __future__ import annotations

import logging

import httpx

from app.models.opa import OPARequest, OPAResponse

logger = logging.getLogger(__name__)


class OPAError(RuntimeError):
    """Base OPA client error."""


class OPAUnavailableError(OPAError):
    """OPA could not be reached."""


class OPADecisionError(OPAError):
    """OPA returned an invalid or unusable response."""


class OPAClient:
    """
    Async, connection-pooled OPA client.

    One long-lived AsyncClient is created during application startup
    and reused for all policy evaluations.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 2.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._client is not None:
            return

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout_seconds),
            limits=httpx.Limits(
                max_connections=100,
                max_keepalive_connections=20,
            ),
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _require_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("OPAClient has not been started")

        return self._client

    async def evaluate(
        self,
        request: OPARequest,
    ) -> OPAResponse:
        """
        Evaluate a policy decision through OPA.

        Any transport failure or malformed response raises an error.
        The eventual enforcement layer must fail closed on these errors.
        """

        client = self._require_client()

        try:
            response = await client.post(
                "/v1/data/confidentialkv/authz",
                json=request.model_dump(mode="json"),
            )

            response.raise_for_status()

        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.HTTPStatusError,
        ) as exc:
            logger.error(
                "OPA request failed: %s",
                exc,
            )

            raise OPAUnavailableError("OPA policy decision unavailable") from exc

        try:
            payload = response.json()

            return OPAResponse.model_validate(payload)

        except Exception as exc:
            logger.error(
                "Invalid OPA response: %s",
                exc,
            )

            raise OPADecisionError("OPA returned an invalid response") from exc
