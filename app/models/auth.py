"""Pydantic schemas for the authentication endpoints."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import Role

# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

# Pragmatic e-mail pattern: a dot-atom local part and a dotted domain.
# (pydantic's EmailStr requires the optional `email-validator` package, which
# is not a dependency of this project yet.)
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

#: bcrypt - which Supabase uses to hash passwords - silently truncates at 72
#: bytes. Rejecting longer secrets is safer than accepting a truncated one.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 8

_PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{5,19}$")


def _validate_email(value: str) -> str:
    email = value.strip().lower()
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise ValueError("must be a valid email address")
    local, _, domain = email.partition("@")
    if len(local) > 64 or ".." in local or ".." in domain:
        raise ValueError("must be a valid email address")
    return email


def _validate_password(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"must be at least {MIN_PASSWORD_LENGTH} characters long")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"must not exceed {MAX_PASSWORD_BYTES} bytes")
    if not any(char.isalpha() for char in value):
        raise ValueError("must contain at least one letter")
    if not any(char.isdigit() for char in value):
        raise ValueError("must contain at least one number")
    return value


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------


class SignupRequest(BaseModel):
    """Public registration payload.

    ``role`` is validated against the enum, but the *authorisation* to pick a
    role is enforced separately in the service layer - ``admin`` is never
    accepted from the client even though it is a valid enum value.
    """

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    email: str = Field(..., max_length=254, examples=["donor@example.org"])
    password: str = Field(..., max_length=512, examples=["Str0ng!Pass1"])
    full_name: str = Field(..., min_length=2, max_length=120, examples=["Asha Verma"])
    phone: Optional[str] = Field(None, max_length=32, examples=["+919876543210"])
    role: Role = Field(
        default=Role.DONOR,
        description=(
            "Role requested by the user. 'admin' is rejected - admin accounts "
            "are provisioned by an administrator."
        ),
        examples=["donor"],
    )

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        return _validate_email(value)

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        return _validate_password(value)

    @field_validator("full_name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not any(char.isalnum() for char in value):
            raise ValueError("must contain at least one letter or digit")
        return " ".join(value.split())

    @field_validator("phone")
    @classmethod
    def _check_phone(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not _PHONE_RE.match(cleaned):
            raise ValueError("must be a valid phone number")
        return cleaned


class LoginRequest(BaseModel):
    """Email + password login payload."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    email: str = Field(..., max_length=254, examples=["donor@example.org"])
    password: str = Field(..., max_length=512, examples=["Str0ng!Pass1"])

    @field_validator("email")
    @classmethod
    def _check_email(cls, value: str) -> str:
        return _validate_email(value)

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: str) -> str:
        # Do not re-apply the signup strength rules on login - an account may
        # have been created before those rules existed. Only reject blanks.
        if not value:
            raise ValueError("must not be empty")
        return value


# --------------------------------------------------------------------------
# Responses
# --------------------------------------------------------------------------


class UserProfile(BaseModel):
    """The authoritative profile of the signed-in user."""

    model_config = ConfigDict(from_attributes=True)

    id: str = Field(..., description="Supabase auth user id (profiles.id).")
    email: str = Field(..., description="Primary e-mail address.")
    full_name: Optional[str] = None
    phone: Optional[str] = None
    role: Role = Field(..., description="Authoritative role from the profiles table.")
    is_active: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class TokenResponse(BaseModel):
    """Session handed back after a successful login (or signup)."""

    access_token: str = Field(..., description="Supabase access token (JWT).")
    refresh_token: str = Field(..., description="Supabase refresh token.")
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token lifetime in seconds.")
    expires_at: Optional[int] = None
    user: UserProfile


class SignupResponse(BaseModel):
    """Result of ``POST /api/v1/auth/signup``.

    When e-mail confirmation is disabled (``AUTH_AUTO_CONFIRM_EMAIL=true``)
    the session is returned immediately. When Supabase requires confirmation
    the account is created but ``session`` is ``null`` and
    ``requires_email_confirmation`` is ``true``.
    """

    message: str
    user: UserProfile
    session: Optional[TokenResponse] = None
    requires_email_confirmation: bool = False


class MessageResponse(BaseModel):
    """Simple acknowledgement payload."""

    message: str


class HealthResponse(BaseModel):
    """Shape returned by ``GET /health``."""

    status: str


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    """Consistent error envelope returned by every failing endpoint."""

    error: ErrorDetail


ERROR_RESPONSES: Dict[int, Dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Malformed request"},
    401: {"model": ErrorResponse, "description": "Missing or invalid access token"},
    403: {"model": ErrorResponse, "description": "Authenticated but not allowed"},
    404: {"model": ErrorResponse, "description": "Not found"},
    409: {"model": ErrorResponse, "description": "Resource already exists"},
    422: {"model": ErrorResponse, "description": "Validation error"},
    429: {"model": ErrorResponse, "description": "Rate limited"},
    500: {"model": ErrorResponse, "description": "Unexpected server error"},
    502: {"model": ErrorResponse, "description": "Upstream service error"},
}


__all__: List[str] = [
    "SignupRequest",
    "LoginRequest",
    "UserProfile",
    "TokenResponse",
    "SignupResponse",
    "MessageResponse",
    "HealthResponse",
    "ErrorResponse",
    "ERROR_RESPONSES",
]