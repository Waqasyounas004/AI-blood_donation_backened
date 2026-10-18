"""FastAPI dependencies shared by the routers."""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Role
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.models.auth import UserProfile
from app.services import auth_service

# auto_error=False so a missing header produces our JSON envelope (401) instead
# of FastAPI's default {"detail": ...} body.
bearer_scheme = HTTPBearer(auto_error=False, description="Supabase access token (JWT)")


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> UserProfile:
    """Resolve and verify the caller from their ``Authorization: Bearer`` token.

    The token is validated against Supabase on every call, so revoked or
    expired tokens stop working immediately. The returned profile carries the
    authoritative role read from the database.
    """
    token = credentials.credentials if credentials else None
    if not token:
        # Allow the token via a query string as a fallback for EventSource /
        # download style clients that cannot set headers.
        token = request.query_params.get("access_token")
    if not token:
        raise AuthenticationError(
            "Provide a Supabase access token in the Authorization header: "
            "'Authorization: Bearer <access_token>'.",
            code="missing_token",
        )
    return auth_service.resolve_user_from_token(token)


def require_roles(*roles: Role) -> Callable[..., UserProfile]:
    """Dependency factory: the caller must hold one of ``roles``."""

    def _dependency(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if current_user.role not in roles:
            raise PermissionDeniedError(
                "This action requires one of the following roles: "
                + ", ".join(sorted(r.value for r in roles))
                + ".",
                details={
                    "required_roles": sorted(r.value for r in roles),
                    "role": current_user.role.value,
                },
            )
        return current_user

    return _dependency