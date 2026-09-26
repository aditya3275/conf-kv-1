from __future__ import annotations

from contextvars import ContextVar, Token
from uuid import UUID, uuid4

_request_id_ctx: ContextVar[str] = ContextVar(
    "request_id",
    default="-",
)


def new_request_id() -> str:
    return str(uuid4())


def set_request_id(request_id: str | UUID) -> Token[str]:
    return _request_id_ctx.set(str(request_id))


def reset_request_id(token: Token[str]) -> None:
    _request_id_ctx.reset(token)


def get_request_id() -> str:
    return _request_id_ctx.get()
