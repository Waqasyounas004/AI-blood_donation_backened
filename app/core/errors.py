"""Application level errors.

Every failure that the API returns to a client is expressed as an
:class:`AppError`. A single exception handler turns those into one consistent
JSON envelope::

    {
      "error": {
        "code": "invalid_credentials",
        "message": "Email or password is incorrect.",
        "details": null
      }
    }

The envelope deliberately carries a machine readable ``code`` so the Next.js
frontend can branch on failures without string matching on messages.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class AppError(Exception):
    """Base class for all errors the API reports to clients."""

    status_code: int = 500
    code: str = "internal_error"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: Optional[str] = None,
        *,
        code: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message or self.message
        self.code = code or self.code
        self.status_code = status_code or self.status_code
        self.details = details
        super().__init__(self.message)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


class ValidationError(AppError):
    """Input failed validation (422)."""

    status_code = 422
    code = "validation_error"
    message = "The request payload is invalid."


class AuthenticationError(AppError):
    """Credentials or access token missing/invalid (401)."""

    status_code = 401
    code = "authentication_failed"
    message = "Authentication failed."


class AccountNotConfirmedError(AppError):
    """The account exists but the e-mail address has not been confirmed (403)."""

    status_code = 403
    code = "email_not_confirmed"
    message = "Please confirm your email address before signing in."


class AccountDisabledError(AppError):
    """``profiles.is_active`` is false (403)."""

    status_code = 403
    code = "account_disabled"
    message = "This account has been deactivated."


class PermissionDeniedError(AppError):
    """Caller is authenticated but not allowed to perform the action (403)."""

    status_code = 403
    code = "permission_denied"
    message = "You do not have permission to perform this action."


class ConflictError(AppError):
    """Resource already exists, e.g. duplicate e-mail (409)."""

    status_code = 409
    code = "conflict"
    message = "The resource already exists."


class RateLimitError(AppError):
    """Upstream (Supabase) rate limit hit (429)."""

    status_code = 429
    code = "rate_limited"
    message = "Too many requests. Please try again later."


class UpstreamError(AppError):
    """Supabase returned an unexpected response (502)."""

    status_code = 502
    code = "upstream_error"
    message = "The authentication service is temporarily unavailable."