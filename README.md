# Backend - Intelligent Blood Donation & Emergency Response Platform

FastAPI + Supabase Auth backend. Phase 3.1 covers **signup** and **login**.

## Running it

```powershell
cd D:\BloodDonation\backend
.\.venv\Scripts\Activate.ps1          # or use .\.venv\Scripts\python.exe directly
uvicorn app.main:app --reload
```

Then open **http://127.0.0.1:8000/docs** for Swagger UI.

Configuration lives in `backend/.env` (see `.env.example`). The service role key
is read only by the backend and is never returned by an endpoint.

## Endpoints

| Method | Path                    | Purpose                                    |
| ------ | ----------------------- | ------------------------------------------ |
| GET    | `/`                     | Service banner                             |
| GET    | `/health`               | Liveness check                             |
| POST   | `/api/v1/auth/signup`   | Register a donor / receiver / hospital     |
| POST   | `/api/v1/auth/login`    | Exchange credentials for a session         |
| GET    | `/api/v1/auth/me`       | Inspect the signed-in user (bearer token)  |

Protected routes expect `Authorization: Bearer <access_token>`.

### Signup

```json
{
  "email": "donor@example.org",
  "password": "Str0ng!Pass1",
  "full_name": "Asha Verma",
  "phone": "+919876543210",
  "role": "donor"
}
```

* `role` accepts `donor`, `receiver`, `hospital` and defaults to `donor`.
* `role: "admin"` is refused with **403** — admin accounts are provisioned by an
  administrator, never self-assigned.

### Errors

Every failure uses one envelope, with a machine readable `code`:

```json
{ "error": { "code": "email_already_exists", "message": "...", "details": null } }
```

## Tests

Start the server, then in a second terminal:

```powershell
.\.venv\Scripts\python.exe tests\test_auth_flow.py
```

The script drives the live API over HTTP (the same calls Swagger UI's *Execute*
button makes), creates only throwaway `@example.com` accounts and deletes them
again at the end, verifying the cleanup rather than assuming it worked.

## Layout

```
app/
  main.py                 FastAPI app, CORS, error handlers, / and /health
  core/config.py          env loading, role definitions, startup validation
  core/errors.py          AppError hierarchy -> JSON error envelope
  db/supabase.py          public (publishable) and admin (service role) clients
  models/auth.py          request/response schemas
  services/auth_service.py signup, login, profile provisioning, token checks
  dependencies.py         get_current_user / require_roles
  routers/auth.py         /api/v1/auth/*
```

## Security notes

* `profiles.role` is the **only** source of truth for a user's role. It is read
  from the database with the service role client on every request; nothing the
  client sends (JWT claims, `user_metadata`, request body) is trusted for
  authorisation.
* Signup never issues an UPDATE on `profiles`, which keeps it clear of the
  database trigger that forbids role and account-status changes.
* Access and refresh tokens are handed to the client (the Next.js app needs
  them) but are never logged; the startup log prints configuration with the keys
  redacted.