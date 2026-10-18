"""Signup / login business logic.

Everything that talks to Supabase Auth and the ``profiles`` table lives here so
the HTTP layer stays thin and the rules are testable in one place.

Security rules enforced here
----------------------------
1. The **role is server owned**. ``profiles.role`` is the single source of
   truth for authorisation; the role in the request body is only honoured when
   it is one of the publicly selectable roles and ``admin`` is always refused.
2. Nothing from the client (``user_metadata``, JWT claims, headers) is ever
   used to decide permissions.
3. Passwords and access tokens are never written to the logs or to error
   payloads.
4. A user may only ever be attached to their own profile row.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from postgrest.exceptions import APIError as PostgrestAPIError
from supabase_auth.errors import AuthError
from supabase_auth.types import AuthResponse, User

from app.core.config import PUBLIC_SIGNUP_ROLES, Role, get_settings
from app.core.errors import (
    AccountDisabledError,
    AppError,
    AuthenticationError,
    ConflictError,
    PermissionDeniedError,
    RateLimitError,
    UpstreamError,
    ValidationError,
)
from app.db.supabase import get_admin_client, get_public_client
from app.models.auth import LoginRequest, SignupRequest, TokenResponse, UserProfile

logger = logging.getLogger("app.auth")

PROFILES_TABLE = "profiles"


# ---------------------------------------------------------------------------
# Supabase error translation
# ---------------------------------------------------------------------------

#: Supabase auth error code -> (status, api code, message)
_AUTH_ERROR_MAP: Dict[str, Tuple[int, str, str]] = {
    "email_exists": (409, "email_already_exists", "An account with this email address already exists."),
    "user_already_exists": (409, "email_already_exists", "An account with this email address already exists."),
    "email_address_invalid": (422, "invalid_email", "The email address is not valid."),
    "email_address_not_authorized": (422, "invalid_email", "The email address is not authorized."),
    "email_not_confirmed": (403, "email_not_confirmed", "Please confirm your email address before signing in."),
    "phone_not_confirmed": (403, "phone_not_confirmed", "Please confirm your phone number before signing in."),
    "invalid_credentials": (401, "invalid_credentials", "Email or password is incorrect."),
    "validation_failed": (422, "validation_error", "The credentials did not pass validation."),
    "weak_password": (422, "weak_password", "The password does not meet the security requirements."),
    "over_email_send_rate_limit": (429, "email_rate_limited", "Too many confirmation emails requested. Please try again later."),
    "over_sms_send_rate_limit": (429, "sms_rate_limited", "Too many verification messages requested. Please try again later."),
    "over_request_rate_limit": (429, "rate_limited", "Too many requests. Please try again later."),
    "signup_disabled": (503, "signup_disabled", "Registration is currently disabled."),
    "email_provider_disabled": (503, "signup_disabled", "Email registration is currently disabled."),
    "user_banned": (403, "account_disabled", "This account has been suspended."),
    "bad_jwt": (401, "invalid_token", "The access token is invalid or has expired."),
    "invalid_jwt": (401, "invalid_token", "The access token is invalid or has expired."),
    "no_authorization": (401, "invalid_token", "The access token is invalid or has expired."),
    "not_admin": (403, "permission_denied", "Operation not permitted."),
    "user_not_found": (404, "user_not_found", "The requested user does not exist."),
    "request_timeout": (504, "auth_timeout", "The authentication service timed out."),
}


def _translate_auth_error(exc: AuthError, default_message: str) -> AppError:
    """Convert a Supabase auth exception into an :class:`AppError`."""
    code = getattr(exc, "code", None)
    status = getattr(exc, "status", None)
    message = getattr(exc, "message", None) or default_message

    if code and code in _AUTH_ERROR_MAP:
        http_status, api_code, friendly = _AUTH_ERROR_MAP[code]
        return AppError(friendly, code=api_code, status_code=http_status)

    # Weak passwords carry the individual reasons with them.
    reasons = getattr(exc, "reasons", None)
    if reasons:
        return ValidationError(
            "The password does not meet the security requirements.",
            code="weak_password",
            details={"reasons": list(reasons)},
        )

    logger.warning(
        "Unmapped Supabase auth error",
        extra={"supabase_code": code, "supabase_status": status},
    )
    return UpstreamError(default_message)


# ---------------------------------------------------------------------------
# profiles helpers
# ---------------------------------------------------------------------------


def _profile_select_query():
    return (
        get_admin_client()
        .from_(PROFILES_TABLE)
        .select("id, full_name, phone, role, is_active, created_at, updated_at")
    )


def fetch_profile(user_id: str) -> Optional[Dict[str, Any]]:
    """Return the ``profiles`` row for ``user_id`` or ``None``.

    Uses the service role client so RLS never hides the caller's own row and
    the role can never be spoofed by the caller.
    """
    response = _profile_select_query().eq("id", user_id).limit(1).execute()
    rows = response.data or []
    return rows[0] if rows else None


def ensure_profile(
    *,
    user_id: str,
    full_name: str,
    phone: Optional[str],
    role: Role,
) -> Dict[str, Any]:
    """Create the ``profiles`` row for a freshly registered auth user.

    Idempotent by design: the row is read first and only written when it is
    absent, so this is safe to re-run and will not clobber a row that was
    created by a database trigger or by a concurrent request. It also never
    issues an UPDATE, which keeps it clear of the database trigger that
    forbids role/account-status changes.
    """
    existing = fetch_profile(user_id)
    if existing is not None:
        logger.info("Reusing existing profile", extra={"user_id": user_id})
        return existing

    payload = {
        "id": user_id,
        "full_name": full_name,
        "phone": phone,
        "role": role.value,
        "is_active": True,
    }

    try:
        response = get_admin_client().from_(PROFILES_TABLE).insert(payload).execute()
        rows = response.data or []
        logger.info("Created profile", extra={"user_id": user_id, "role": role.value})
        return rows[0] if rows else fetch_profile(user_id) or payload
    except PostgrestAPIError as exc:
        # 23505 = unique violation: a concurrent signup or a DB trigger beat us.
        if str(getattr(exc, "code", "")) == "23505":
            existing = fetch_profile(user_id)
            if existing is not None:
                return existing
        logger.error("Failed to create profile", extra={"user_id": user_id, "error": str(exc)})
        raise UpstreamError("Could not create the user profile.") from exc
    except Exception as exc:  # pragma: no cover - defensive
        existing = fetch_profile(user_id)
        if existing is not None:
            return existing
        logger.error("Unexpected error creating profile", extra={"user_id": user_id})
        raise UpstreamError("Could not create the user profile.") from exc


def build_user_profile(auth_user: User, profile_row: Dict[str, Any]) -> UserProfile:
    """Combine the Supabase auth user with its authoritative profile row."""
    email = getattr(auth_user, "email", None)
    if not email:
        identities = getattr(auth_user, "identities", None) or []
        email = next(
            (getattr(i, "email", None) for i in identities if getattr(i, "email", None)),
            None,
        )

    raw_role = (profile_row or {}).get("role")
    try:
        role = Role(raw_role)
    except ValueError:
        logger.warning("Profile holds an unknown role", extra={"role": str(raw_role)})
        role = Role.DONOR

    return UserProfile(
        id=profile_row.get("id", getattr(auth_user, "id", "")),
        email=email or "",
        full_name=profile_row.get("full_name"),
        phone=profile_row.get("phone"),
        role=role,
        is_active=bool(profile_row.get("is_active", True)),
        created_at=profile_row.get("created_at"),
        updated_at=profile_row.get("updated_at"),
    )


# ---------------------------------------------------------------------------
# Signup
# ---------------------------------------------------------------------------


def _assert_role_is_signupable(role: Role) -> None:
    """Reject any attempt to self-assign a privileged role.

    This is the single place that enforces the rule, and it runs against the
    role decoded from the request body - the value is never taken from the
    client and then trusted further down the stack.
    """
    if role not in PUBLIC_SIGNUP_ROLES:
        raise PermissionDeniedError(
            f"'{role.value}' cannot be requested at signup. "
            "Administrator accounts are created by an administrator.",
            code="role_not_self_assignable",
            details={"allowed_roles": sorted(r.value for r in PUBLIC_SIGNUP_ROLES)},
        )


def _create_auth_user(*, email: str, password: str, full_name: str, phone: Optional[str]) -> Tuple[User, Optional[Any]]:
    """Create the Supabase auth user. Returns ``(user, session_or_None)``."""
    settings = get_settings()
    metadata: Dict[str, Any] = {"full_name": full_name}
    if phone:
        metadata["phone"] = phone

    if settings.auth_auto_confirm_email:
        # E-mail confirmation is out of scope for this phase, so the account is
        # confirmed immediately. Flip AUTH_AUTO_CONFIRM_EMAIL to false once the
        # confirmation workflow is implemented.
        try:
            response = get_admin_client().auth.admin.create_user(
                {
                    "email": email,
                    "password": password,
                    "email_confirm": True,
                    "user_metadata": metadata,
                }
            )
        except AuthError as exc:
            raise _translate_auth_error(exc, "Could not create the account.") from exc
        return response.user, None

    try:
        response: AuthResponse = get_public_client().auth.sign_up(
            {"email": email, "password": password, "options": {"data": metadata}}
        )
    except AuthError as exc:
        raise _translate_auth_error(exc, "Could not create the account.") from exc

    if response.user is None:
        raise UpstreamError("Could not create the account.")
    return response.user, response.session


def signup(payload: SignupRequest) -> Dict[str, Any]:
    """Register a new user and provision its profile."""
    _assert_role_is_signupable(payload.role)

    auth_user, session = _create_auth_user(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        phone=payload.phone,
    )

    user_id = auth_user.id

    profile_row = ensure_profile(
        user_id=user_id,
        full_name=payload.full_name,
        phone=payload.phone,
        role=payload.role,
    )

    profile = build_user_profile(auth_user, profile_row)

    logger.info(
        "Signup succeeded",
        extra={"user_id": user_id, "role": profile.role.value},
    )

    if session is None and get_settings().auth_auto_confirm_email:
        # create_user does not return a session - mint one so the client can be
        # signed in straight after registering.
        session = _sign_in_for_session(payload.email, payload.password)

    if session is None:
        return {
            "message": (
                "Account created. Please check your email to confirm your address "
                "before signing in."
            ),
            "user": profile,
            "session": None,
            "requires_email_confirmation": True,
        }

    return {
        "message": "Account created successfully.",
        "user": profile,
        "session": _token_response(session, auth_user, profile),
        "requires_email_confirmation": not bool(
            getattr(auth_user, "email_confirmed_at", None)
        ),
    }


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def _sign_in_for_session(email: str, password: str) -> Optional[Any]:
    try:
        response = get_public_client().auth.sign_in_with_password(
            {"email": email, "password": password}
        )
    except AuthError as exc:
        # Signup itself succeeded; the follow-up sign in is best effort.
        logger.warning(
            "Immediate sign-in after signup failed",
            extra={"supabase_code": getattr(exc, "code", None)},
        )
        return None
    return response.session


def login(payload: LoginRequest) -> TokenResponse:
    """Exchange credentials for a session."""
    try:
        response = get_public_client().auth.sign_in_with_password(
            {"email": payload.email, "password": payload.password}
        )
    except AuthError as exc:
        raise _translate_auth_error(exc, "Could not sign you in.") from exc

    session = response.session
    auth_user = response.user
    if session is None or auth_user is None:
        raise AuthenticationError("Could not sign you in.")

    profile_row = fetch_profile(auth_user.id)
    if profile_row is None:
        # Defensive: the profile is created at signup, so this only happens if
        # the row was removed afterwards.
        logger.warning("Profile missing during login; recreating", extra={"user_id": auth_user.id})
        profile_row = ensure_profile(
            user_id=auth_user.id,
            full_name=(auth_user.user_metadata or {}).get("full_name") or payload.email,
            phone=payload.email,
            role=Role.DONOR,
        )

    if not bool(profile_row.get("is_active", True)):
        raise AccountDisabledError()

    profile = build_user_profile(auth_user, profile_row)

    logger.info(
        "Login succeeded",
        extra={"user_id": auth_user.id, "role": profile.role.value},
    )

    return _token_response(session, auth_user, profile)


def _token_response(session: Any, auth_user: User, profile: UserProfile) -> TokenResponse:
    return TokenResponse(
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        token_type=getattr(session, "token_type", None) or "bearer",
        expires_in=int(getattr(session, "expires_in", 3600) or 3600),
        expires_at=getattr(session, "expires_at", None),
        user=profile,
    )


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


def resolve_user_from_token(access_token: str) -> UserProfile:
    """Verify a Supabase access token and return the caller's profile.

    The token is validated by Supabase itself (``GET /auth/v1/user``) which
    checks the signature, the expiry and whether the user is banned. The
    profile - and therefore the role - is then read from the database with the
    service role client so it cannot be influenced by the caller.
    """
    if not access_token or not access_token.strip():
        raise AuthenticationError("An access token is required.", code="missing_token")

    try:
        user_response = get_public_client().auth.get_user(access_token)
    except AuthError as exc:
        raise _translate_auth_error(exc, "Invalid or expired access token.") from exc
    except Exception as exc:
        logger.warning("Token verification failed", extra={"error": type(exc).__name__})
        raise AuthenticationError("Invalid or expired access token.", code="invalid_token") from exc

    auth_user = getattr(user_response, "user", None)
    if auth_user is None:
        raise AuthenticationError("Invalid or expired access token.", code="invalid_token")

    profile_row = fetch_profile(auth_user.id)
    if profile_row is None:
        raise AuthenticationError(
            "No profile is associated with this account.", code="profile_not_found"
        )

    if not bool(profile_row.get("is_active", True)):
        raise AccountDisabledError()

    return build_user_profile(auth_user, profile_row)


def require_roles(profile: UserProfile, *roles: Role) -> None:
    """Raise 403 unless the profile holds one of ``roles``."""
    if profile.role not in roles:
        raise PermissionDeniedError(
            f"This action requires one of the following roles: "
            f"{', '.join(sorted(r.value for r in roles))}.",
            details={"required_roles": sorted(r.value for r in roles), "role": profile.role.value},
        )