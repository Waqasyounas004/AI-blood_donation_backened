"""Authentication routes: signup, login and the current user."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status

from app.dependencies import get_current_user
from app.models.auth import (
    ERROR_RESPONSES,
    ErrorResponse,
    LoginRequest,
    SignupRequest,
    SignupResponse,
    TokenResponse,
    UserProfile,
)
from app.services import auth_service

logger = logging.getLogger("app.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description=(
        "Creates a Supabase auth user and provisions its `profiles` row.\n\n"
        "`role` may be `donor`, `receiver` or `hospital`. Requesting `admin` "
        "is refused with **403** - administrator accounts are provisioned by an "
        "administrator, never by the person signing up.\n\n"
        "When e-mail confirmation is enabled on the Supabase project the "
        "account is created without a session and "
        "`requires_email_confirmation` is returned as `true`."
    ),
    responses={
        201: {"description": "Account created"},
        403: ERROR_RESPONSES[403],
        409: ERROR_RESPONSES[409],
        422: ERROR_RESPONSES[422],
        429: ERROR_RESPONSES[429],
        502: ERROR_RESPONSES[502],
    },
)
def signup(payload: SignupRequest) -> dict:
    return auth_service.signup(payload)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Sign in with email and password",
    description=(
        "Exchanges an email/password pair for a Supabase session.\n\n"
        "The returned `user.role` is read from the `profiles` table, never from "
        "anything supplied by the client. Send the `access_token` back as "
        "`Authorization: Bearer <access_token>` on protected endpoints."
    ),
    responses={
        200: {"description": "Signed in"},
        401: ERROR_RESPONSES[401],
        403: {"model": ErrorResponse, "description": "Email not confirmed, or the account is deactivated"},
        422: ERROR_RESPONSES[422],
        429: ERROR_RESPONSES[429],
        502: ERROR_RESPONSES[502],
    },
)
def login(payload: LoginRequest) -> TokenResponse:
    return auth_service.login(payload)


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get the signed-in user",
    description=(
        "Verifies the Supabase access token and returns the caller's profile, "
        "including the authoritative role. Useful for the frontend to decide "
        "what to render after a page reload."
    ),
    responses={
        200: {"description": "The signed-in user"},
        401: ERROR_RESPONSES[401],
        403: ERROR_RESPONSES[403],
    },
)
def me(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
    return current_user