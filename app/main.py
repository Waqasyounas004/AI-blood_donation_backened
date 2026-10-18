"""Intelligent Blood Donation & Emergency Response Platform - backend API.

Phase 3.1 adds signup and login on top of Supabase Auth.

Run locally::

    uvicorn app.main:app --reload

Interactive API docs: http://127.0.0.1:8000/docs
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import ConfigurationError, get_settings
from app.core.errors import AppError
from app.routers import auth as auth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
)
logger = logging.getLogger("app")


def _error_response(
    status_code: int, code: str, message: str, details: Any = None
) -> JSONResponse:
    """Single error envelope shared by every failure path."""
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "details": details}},
    )


def create_app() -> FastAPI:
    app = FastAPI(
        title="Intelligent Blood Donation API",
        version="0.3.1",
        description=(
            "Backend for the Intelligent Blood Donation & Emergency Response "
            "Platform.\n\n"
            "**Authentication (Phase 3.1)**\n\n"
            "* `POST /api/v1/auth/signup` - register a donor, receiver or hospital\n"
            "* `POST /api/v1/auth/login` - exchange credentials for a session\n"
            "* `GET  /api/v1/auth/me` - inspect the signed-in user\n\n"
            "Protected endpoints expect `Authorization: Bearer <access_token>`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # ------------------------------------------------------------------
    # CORS (the Next.js frontend runs on a different origin)
    # ------------------------------------------------------------------
    settings = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # ------------------------------------------------------------------
    # Error handlers - one consistent JSON shape for every failure
    # ------------------------------------------------------------------
    @app.exception_handler(AppError)
    async def _app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        if exc.status_code >= 500:
            logger.error("Request failed: %s", exc.code)
        return JSONResponse(status_code=exc.status_code, content=exc.to_payload())

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(part) for part in err.get("loc", []) if part != "body"),
                "message": err.get("msg", "invalid value"),
                "type": err.get("type"),
            }
            for err in exc.errors()
        ]
        return _error_response(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "validation_error",
            "The request payload is invalid.", details,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        code = {
            400: "bad_request",
            401: "authentication_failed",
            403: "permission_denied",
            404: "not_found",
            405: "method_not_allowed",
        }.get(exc.status_code, "http_error")
        return _error_response(exc.status_code, code, detail)

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
        # Log the detail server-side, return an opaque message to the client so
        # internals (and credentials) can never leak through an error body.
        logger.exception("Unhandled error: %s", type(exc).__name__)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "An unexpected error occurred.",
        )

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(auth_router.router, prefix="/api/v1")

    # ------------------------------------------------------------------
    # Existing endpoints (unchanged behaviour)
    # ------------------------------------------------------------------
    @app.get("/", tags=["System"])
    def root() -> Dict[str, Any]:
        return {"message": "Blood Donation API is running"}

    @app.get("/health", tags=["System"])
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    logger.info("Configuration loaded: %s", settings.public_summary())
    return app


try:
    app = create_app()
except ConfigurationError as exc:  # pragma: no cover - startup misconfiguration
    logger.critical("Backend misconfigured: %s", exc)
    raise