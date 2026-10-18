"""Supabase client factories.

Two clients are exposed:

``get_public_client``
    Built with the *publishable* key. It is only used for the public auth
    flows (sign up, password grant) so those calls run with the same
    privileges as the browser would have.

``get_admin_client``
    Built with the *service role* key. It bypasses RLS and is used only for
    server side work: reading ``profiles`` and creating the profile row during
    signup. The key never leaves this process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

#: Fail fast rather than hanging a request thread if Supabase is unreachable.
POSTGREST_TIMEOUT = 15

from supabase import create_client
from supabase.lib.client_options import SyncClientOptions as ClientOptions

from app.core.config import Settings, get_settings


def _backend_options() -> ClientOptions:
    """The backend is stateless: never persist or auto-refresh a session."""
    return ClientOptions(
        persist_session=False,
        auto_refresh_token=False,
        postgrest_client_timeout=POSTGREST_TIMEOUT,
    )


@lru_cache(maxsize=1)
def _public_client() -> Any:
    settings: Settings = get_settings()
    return create_client(
        settings.supabase_url,
        settings.supabase_publishable_key,
        _backend_options(),
    )


@lru_cache(maxsize=1)
def _admin_client() -> Any:
    settings: Settings = get_settings()
    return create_client(
        settings.supabase_url,
        settings.supabase_service_role_key,
        _backend_options(),
    )


def get_public_client() -> Any:
    """Client authenticated as ``anon``/publishable - safe for public flows."""
    return _public_client()


def get_admin_client() -> Any:
    """Client authenticated with the service role key - backend only."""
    return _admin_client()


def reset_client_cache() -> None:
    """Drop cached clients (used by tests)."""
    _public_client.cache_clear()
    _admin_client.cache_clear()