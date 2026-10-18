"""Application configuration.

Environment variables are loaded from ``backend/.env`` so the app boots the same
way regardless of the current working directory.

Security notes
--------------
* The Supabase **service role key** is read here and never leaves the backend.
  It is used only for privileged operations (reading/writing ``profiles``).
* ``SUPABASE_SERVICE_ROLE_KEY`` is validated at startup: if it is missing, or if
  it is accidentally set to the publishable key, the application refuses to
  start instead of silently running with the wrong privileges.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import List

from dotenv import load_dotenv

# .../backend/app/core/config.py -> .../backend
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv(os.path.join(BACKEND_DIR, ".env"), override=False)

REDACTED = "***redacted***"


class Role(str, Enum):
    """Roles supported by the platform."""

    DONOR = "donor"
    RECEIVER = "receiver"
    HOSPITAL = "hospital"
    ADMIN = "admin"


#: Roles a member of the public may choose when registering.
#: ``ADMIN`` is deliberately excluded - admin accounts must be provisioned by an
#: administrator, never by the person signing up.
PUBLIC_SIGNUP_ROLES: frozenset[Role] = frozenset({Role.DONOR, Role.RECEIVER, Role.HOSPITAL})

#: Role assigned when a client does not send one.
DEFAULT_SIGNUP_ROLE = Role.DONOR


class ConfigurationError(RuntimeError):
    """Raised when the backend is not configured correctly."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    """Immutable application settings."""

    supabase_url: str
    supabase_publishable_key: str
    supabase_service_role_key: str = field(repr=False)
    auth_auto_confirm_email: bool
    cors_origins: List[str]

    @property
    def service_role_configured(self) -> bool:
        return bool(self.supabase_service_role_key)

    def public_summary(self) -> dict:
        """Settings safe to expose in logs / diagnostics - never includes keys."""
        return {
            "supabase_url": self.supabase_url,
            "supabase_publishable_key": REDACTED,
            "supabase_service_role_key": REDACTED,
            "auth_auto_confirm_email": self.auth_auto_confirm_email,
            "cors_origins": self.cors_origins,
            "public_signup_roles": sorted(role.value for role in PUBLIC_SIGNUP_ROLES),
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build (and cache) the settings object from the environment."""

    supabase_url = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
    publishable = (os.getenv("SUPABASE_PUBLISHABLE_KEY") or "").strip()
    service_role = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()

    missing = [
        name
        for name, value in (
            ("SUPABASE_URL", supabase_url),
            ("SUPABASE_PUBLISHABLE_KEY", publishable),
            ("SUPABASE_SERVICE_ROLE_KEY", service_role),
        )
        if not value
    ]
    if missing:
        raise ConfigurationError(
            "Missing required environment variables: " + ", ".join(missing)
        )

    if not supabase_url.startswith("https://"):
        raise ConfigurationError("SUPABASE_URL must be an https:// URL")

    if supabase_url.endswith(".supabase.co") is False:
        raise ConfigurationError("SUPABASE_URL does not look like a Supabase project URL")

    # Guard against the most common deployment mistake: pasting the publishable
    # key into the service-role variable. That would silently disable RLS.
    if publishable == service_role:
        raise ConfigurationError(
            "SUPABASE_SERVICE_ROLE_KEY must not be the same value as "
            "SUPABASE_PUBLISHABLE_KEY. Copy the real secret key from "
            "Supabase dashboard > Project Settings > API Keys."
        )

    if service_role.startswith("sb_publishable_"):
        raise ConfigurationError(
            "SUPABASE_SERVICE_ROLE_KEY holds a publishable key. Use the secret "
            "(service_role) key instead."
        )

    return Settings(
        supabase_url=supabase_url,
        supabase_publishable_key=publishable,
        supabase_service_role_key=service_role,
        auth_auto_confirm_email=_env_bool("AUTH_AUTO_CONFIRM_EMAIL", True),
        cors_origins=_env_list(
            "CORS_ORIGINS",
            [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ],
        ),
    )