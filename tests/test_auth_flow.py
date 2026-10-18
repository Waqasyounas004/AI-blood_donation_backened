"""End-to-end checks for the Phase 3.1 authentication endpoints.

Runs against a live server, exercising exactly the same HTTP surface that
Swagger UI uses at http://127.0.0.1:8000/docs.

Usage::

    # terminal 1
    uvicorn app.main:app --reload
    # terminal 2
    python tests/test_auth_flow.py

Every user created here is deleted again at the end, so the script can be run
repeatedly without polluting the project.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import httpx

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
PASSWORD = "Str0ng!Pass1"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

_results: list[tuple[bool, str, str]] = []
_created_user_ids: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    _results.append((condition, name, detail))
    mark = f"{GREEN}PASS{RESET}" if condition else f"{RED}FAIL{RESET}"
    line = f"  [{mark}] {name}"
    if detail and not condition:
        line += f"\n         -> {detail}"
    print(line)
    return condition


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def unique_email(prefix: str = "phase31") -> str:
    """A unique throwaway address; accounts are removed again in cleanup()."""
    return f"{prefix}_{uuid.uuid4().hex[:10]}@example.com"


def signup(client: httpx.Client, **overrides) -> httpx.Response:
    payload = {
        "email": unique_email(),
        "password": PASSWORD,
        "full_name": "Test Person",
        "role": "donor",
    }
    payload.update(overrides)
    response = client.post("/api/v1/auth/signup", json=payload)
    if response.status_code == 201:
        # Remember the id so cleanup is exact - no scanning required.
        user_id = response.json().get("user", {}).get("id")
        if user_id:
            _created_user_ids.append(user_id)
    return response


def login(client: httpx.Client, email: str, password: str = PASSWORD) -> httpx.Response:
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


# ---------------------------------------------------------------------------


def test_system_endpoints(client: httpx.Client) -> None:
    section("1. Existing endpoints still work")
    r = client.get("/")
    check("GET / returns 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
    check(
        "GET / body unchanged",
        r.json() == {"message": "Blood Donation API is running"},
        str(r.json()),
    )

    r = client.get("/health")
    check("GET /health returns 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
    check("GET /health body unchanged", r.json() == {"status": "ok"}, str(r.json()))

    r = client.get("/docs")
    check(
        "GET /docs serves Swagger UI",
        r.status_code == 200 and "swagger-ui" in r.text.lower(),
        f"{r.status_code}",
    )

    r = client.get("/openapi.json")
    spec = r.json() if r.status_code == 200 else {}
    check("GET /openapi.json returns 200", r.status_code == 200)
    check(
        "OpenAPI documents the 3 auth endpoints",
        all(p in spec.get("paths", {}) for p in (
            "/api/v1/auth/signup", "/api/v1/auth/login", "/api/v1/auth/me",
        )),
        str(list(spec.get("paths", {}).keys())),
    )


def test_signup_success(client: httpx.Client) -> None:
    section("2. Signup - happy path")
    r = signup(client, role="donor")
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    check("POST /auth/signup returns 201", r.status_code == 201, f"{r.status_code} {r.text[:300]}")
    check("signup returns a session", body.get("session") is not None, str(body)[:300])
    if body.get("session"):
        check("session has access_token", bool(body["session"].get("access_token")))
        check("session has refresh_token", bool(body["session"].get("refresh_token")))
        check("session expires_in is an int", isinstance(body["session"].get("expires_in"), int))
    check("signup returns the user", bool(body.get("user", {}).get("id")))
    check("role is donor", body.get("user", {}).get("role") == "donor", str(body.get("user")))
    check("profile is_active is true", body.get("user", {}).get("is_active") is True)
    check(
        "no secret keys in response",
        "service_role" not in r.text and "eyJ" in r.text,  # a JWT is expected, a raw service key is not
    )
    return body


def test_signup_roles(client: httpx.Client) -> None:
    section("3. Signup - all publicly selectable roles")
    for role in ("donor", "receiver", "hospital"):
        r = signup(client, role=role)
        body = r.json()
        check(f"role '{role}' accepted (201)", r.status_code == 201, f"{r.status_code} {r.text[:250]}")
        check(f"role '{role}' stored on profile", body.get("user", {}).get("role") == role,
              str(body.get("user")))


def test_admin_escalation_blocked(client: httpx.Client) -> None:
    section("4. Privilege escalation - admin cannot be self-assigned")
    admin_email = unique_email("escalation")
    r = client.post(
        "/api/v1/auth/signup",
        json={
            "email": admin_email,
            "password": PASSWORD,
            "full_name": "Escalation Attempt",
            "role": "admin",
        },
    )
    body = r.json()
    check("signup with role=admin is refused (403)", r.status_code == 403, f"{r.status_code} {r.text[:300]}")
    check(
        "error code is role_not_self_assignable",
        body.get("error", {}).get("code") == "role_not_self_assignable",
        str(body),
    )
    check(
        "error lists the allowed roles",
        sorted(body.get("error", {}).get("details", {}).get("allowed_roles", []))
        == ["donor", "hospital", "receiver"],
        str(body),
    )
    # the refused attempt must not have created anything
    r = login(client, admin_email)
    check("refused admin signup created no auth user", r.status_code == 401, f"{r.status_code}")

    r = client.post(
        "/api/v1/auth/signup",
        json={"email": unique_email(), "password": PASSWORD, "full_name": "X", "role": "superuser"},
    )
    check("unknown role rejected by validation (422)", r.status_code == 422, f"{r.status_code} {r.text[:200]}")


def test_duplicate_email(client: httpx.Client) -> None:
    section("5. Duplicate e-mail handling")
    email = unique_email("duplicate")
    r1 = signup(client, email=email)
    check("first signup succeeds", r1.status_code == 201, f"{r1.status_code} {r1.text[:200]}")
    r2 = signup(client, email=email)
    body = r2.json()
    check("second signup returns 409", r2.status_code == 409, f"{r2.status_code} {r2.text[:250]}")
    check(
        "duplicate error code is email_already_exists",
        body.get("error", {}).get("code") == "email_already_exists",
        str(body),
    )


def test_input_validation(client: httpx.Client) -> None:
    section("6. Input validation")
    cases = [
        ("invalid email format", {"email": "not-an-email", "password": PASSWORD, "full_name": "Test"}),
        ("missing password", {"email": unique_email(), "full_name": "Test"}),
        ("password too short", {"email": unique_email(), "password": "Ab1", "full_name": "Test"}),
        ("password without a number", {"email": unique_email(), "password": "abcdefghij", "full_name": "Test"}),
        ("password without a letter", {"email": unique_email(), "password": "1234567890", "full_name": "Test"}),
        ("password over 72 bytes", {"email": unique_email(), "password": "a1" + "b" * 80, "full_name": "Test"}),
        ("missing full_name", {"email": unique_email(), "password": PASSWORD}),
        ("full_name too short", {"email": unique_email(), "password": PASSWORD, "full_name": "A"}),
        ("missing everything", {}),
    ]
    for name, payload in cases:
        r = client.post("/api/v1/auth/signup", json=payload)
        check(f"{name} -> 422", r.status_code == 422, f"{r.status_code} {r.text[:200]}")
        if r.status_code == 422:
            body = r.json()
            check(
                f"{name} uses the standard error envelope",
                "error" in body and body["error"].get("code") == "validation_error",
                str(body)[:200],
            )


def test_login(client: httpx.Client) -> None:
    section("7. Login")
    email = unique_email("login")
    signup(client, email=email)

    r = login(client, email)
    body = r.json()
    check("login with correct credentials -> 200", r.status_code == 200, f"{r.status_code} {r.text[:300]}")
    check("login returns access_token", bool(body.get("access_token")))
    check("login returns refresh_token", bool(body.get("refresh_token")))
    check("login returns the authoritative role", body.get("user", {}).get("role") == "donor", str(body.get("user")))
    check("login echoes the email", body.get("user", {}).get("email") == email)

    r = login(client, email, "WrongPassword1")
    check("wrong password -> 401", r.status_code == 401, f"{r.status_code} {r.text[:200]}")
    check(
        "wrong password error code is invalid_credentials",
        r.json().get("error", {}).get("code") == "invalid_credentials",
        r.text[:200],
    )

    r = login(client, unique_email("ghost"), PASSWORD)
    check("unknown email -> 401", r.status_code == 401, f"{r.status_code} {r.text[:200]}")
    check(
        "unknown email is indistinguishable from a wrong password",
        r.json().get("error", {}).get("code") == "invalid_credentials",
        r.text[:200],
    )

    r = client.post("/api/v1/auth/login", json={"email": "bad-email", "password": PASSWORD})
    check("invalid email on login -> 422", r.status_code == 422, f"{r.status_code} {r.text[:200]}")

    return body


def test_protected_endpoint(client: httpx.Client) -> None:
    section("8. Token verification on /auth/me")
    email = unique_email("me")
    signup(client, email=email)
    token = login(client, email).json()["access_token"]

    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    body = r.json()
    check("valid token -> 200", r.status_code == 200, f"{r.status_code} {r.text[:250]}")
    check("me returns the right email", body.get("email") == email, str(body)[:200])
    check("me returns the role", body.get("role") == "donor", str(body)[:200])

    r = client.get("/api/v1/auth/me")
    check("missing token -> 401", r.status_code == 401, f"{r.status_code} {r.text[:200]}")
    check("missing token error code is missing_token",
          r.json().get("error", {}).get("code") == "missing_token", r.text[:200])

    r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage.token.value"})
    check("malformed token -> 401", r.status_code == 401, f"{r.status_code} {r.text[:200]}")
    check("malformed token error code is invalid_token",
          r.json().get("error", {}).get("code") == "invalid_token", r.text[:200])

    # a valid JWT belonging to a *different* Supabase project must not be accepted
    r = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6NDA3MDkwODgwMH0.invalidsignature"},
    )
    check("forged token -> 401", r.status_code == 401, f"{r.status_code} {r.text[:200]}")


def test_role_cannot_be_tampered_with(client: httpx.Client) -> None:
    section("9. Role cannot be changed by the user")
    from app.services.auth_service import fetch_profile

    email = unique_email("tamper")
    signup(client, email=email, role="donor")
    session = login(client, email).json()
    user_id = session["user"]["id"]
    user_headers = {
        "apikey": os.environ["SUPABASE_PUBLISHABLE_KEY"],
        "Authorization": f"Bearer {session['access_token']}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    rest = f"{os.environ['SUPABASE_URL'].rstrip('/')}/rest/v1/profiles?id=eq.{user_id}"

    # 1. try to change the role through PostgREST using the user's own token
    r = httpx.patch(rest, headers=user_headers, json={"role": "admin"}, timeout=30)
    check("database refuses a user-initiated role change", r.status_code >= 400, f"{r.status_code} {r.text[:200]}")

    profile = fetch_profile(user_id)
    check("role in the database is still donor", profile.get("role") == "donor", str(profile))

    # 2. the role served by /auth/me is read from the database, not from claims
    r = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {session['access_token']}"})
    check("/auth/me still reports donor", r.json().get("role") == "donor", str(r.json())[:200])


def test_account_status_is_lock_down(client: httpx.Client) -> None:
    section("10. Account status cannot be changed through PostgREST")
    from app.db.supabase import get_admin_client
    from app.services.auth_service import fetch_profile

    email = unique_email("lockdown")
    signup(client, email=email)
    user_id = login(client, email).json()["user"]["id"]

    # Even the service role must not be able to flip is_active over PostgREST:
    # a database trigger rejects the change. Deactivation therefore requires a
    # trusted SQL session, not an API call.
    try:
        get_admin_client().from_("profiles").update({"is_active": False}).eq("id", user_id).execute()
        check("database blocks changing is_active", False, "the update unexpectedly succeeded")
    except Exception as exc:
        check(
            "database blocks changing is_active (even for the service role)",
            "not allowed to change role or account status" in str(exc),
            str(exc)[:200],
        )

    try:
        get_admin_client().from_("profiles").update({"role": "admin"}).eq("id", user_id).execute()
        check("database blocks changing role", False, "the update unexpectedly succeeded")
    except Exception as exc:
        check(
            "database blocks changing role (even for the service role)",
            "not allowed to change role or account status" in str(exc),
            str(exc)[:200],
        )

    check("account is still usable", login(client, email).status_code == 200)
    check("is_active is still true", fetch_profile(user_id).get("is_active") is True)


def cleanup() -> None:
    """Delete exactly the accounts this run created, then verify it worked."""
    section("Cleanup")
    if not _created_user_ids:
        print("  no accounts were created")
        return
    try:
        from app.db.supabase import get_admin_client

        admin = get_admin_client()
        failed = []
        for user_id in _created_user_ids:
            try:
                admin.auth.admin.delete_user(user_id)
            except Exception as exc:
                failed.append((user_id, str(exc)[:80]))

        # Verify rather than assume: a leftover account would silently pollute
        # the project and make the next run's results misleading.
        survivors = []
        for user_id in _created_user_ids:
            try:
                admin.auth.admin.get_user_by_id(user_id)
                survivors.append(user_id)
            except Exception:
                pass  # already gone - good

        removed = len(_created_user_ids) - len(survivors)
        print(f"  removed {removed}/{len(_created_user_ids)} test accounts")
        check("every test account was cleaned up", not survivors, f"survivors: {survivors}")
        if failed:
            print(f"  {YELLOW}note: {len(failed)} delete call(s) errored: {failed}{RESET}")
    except Exception as exc:  # pragma: no cover
        print(f"  {YELLOW}cleanup skipped: {exc}{RESET}")


def main() -> int:
    print(f"Testing {BASE_URL}")
    with httpx.Client(base_url=BASE_URL, timeout=60.0) as client:
        try:
            client.get("/health")
        except Exception as exc:
            print(f"{RED}Backend is not reachable at {BASE_URL}{RESET}: {exc}")
            print("Start it with: uvicorn app.main:app --reload")
            return 2

        test_system_endpoints(client)
        test_signup_success(client)
        test_signup_roles(client)
        test_admin_escalation_blocked(client)
        test_duplicate_email(client)
        test_input_validation(client)
        test_login(client)
        test_protected_endpoint(client)
        test_role_cannot_be_tampered_with(client)
        test_account_status_is_lock_down(client)

    cleanup()

    passed = sum(1 for ok, _, _ in _results if ok)
    total = len(_results)
    failed = [name for ok, name, _ in _results if not ok]
    print(f"\n{'=' * 60}")
    colour = GREEN if not failed else RED
    print(f"{colour}{passed}/{total} checks passed{RESET}")
    if failed:
        print(f"{RED}Failed:{RESET}")
        for name in failed:
            print(f"  - {name}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())