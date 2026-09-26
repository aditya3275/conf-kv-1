from __future__ import annotations

from collections.abc import Callable

from fastapi import Header, HTTPException, status

from app.models.tenant import Tenant
from app.registry.tenant_registry import TenantRegistry


class AuthenticationError(HTTPException):
    def __init__(self, detail: str = "Invalid authentication credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


def extract_bearer_token(
    authorization: str,
) -> str:
    """
    Extracts a bearer token from:

        Authorization: Bearer <token>
    """
    if not authorization:
        raise AuthenticationError()

    scheme, separator, credentials = authorization.partition(" ")

    if not separator or scheme.lower() != "bearer":
        raise AuthenticationError("Invalid Authorization scheme")

    token = credentials.strip()

    if not token:
        raise AuthenticationError()

    return token


def make_authenticator(
    tenant_registry: TenantRegistry,
) -> Callable:
    """
    Creates a FastAPI dependency bound to the initialized registry.
    """

    async def authenticate(
        authorization: str = Header(default=""),
    ) -> Tenant:
        api_key = extract_bearer_token(authorization)

        tenant = tenant_registry.resolve_by_api_key(api_key)

        if tenant is None:
            raise AuthenticationError()

        return tenant

    return authenticate
