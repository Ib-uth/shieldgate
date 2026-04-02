"""Authentication routes for login, refresh, and logout"""

import os
import secrets
from datetime import timedelta
from typing import Any

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from ..utils.jwt_utils import JWTManager, create_sample_tokens

_REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60


def _set_refresh_token_cookie(response: Response, token: str) -> None:
    """httpOnly refresh cookie for cross-site admin UI (HTTPS)."""
    response.set_cookie(
        key="refresh_token",
        value=token,
        max_age=_REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=True,
        samesite="none",
    )


# Schemas
class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    expires_in: int
    token_type: str = "bearer"


# Security scheme for refresh token
refresh_scheme = HTTPBearer(auto_error=False)

# Production dashboard: only this email may sign in (password is not verified).
_PRODUCTION_ALLOWED_EMAIL = "uthibraheem@gmail.com"


def _is_production() -> bool:
    return os.getenv("ENVIRONMENT", "").lower() == "production"


def create_auth_routes(jwt_manager: JWTManager, redis_client: redis.Redis) -> APIRouter:
    """Create authentication routes"""
    router = APIRouter(prefix="/auth", tags=["authentication"])

    @router.get("/test-tokens")
    async def test_tokens() -> dict[str, str]:
        """
        Development-only: return sample JWTs for admin, user, and readonly roles.
        Disabled in production (returns 404).
        """
        if os.getenv("ENVIRONMENT", "").lower() != "development":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Not found"
            )
        return create_sample_tokens(jwt_manager)

    @router.post("/login", response_model=LoginResponse)
    async def login(request: LoginRequest, response: Response) -> LoginResponse:
        """
        Authenticate user and return tokens.

        In a real implementation, this would validate credentials against a database.
        Production accepts only the configured owner email; development uses demo rules.
        """

        email_for_claims = request.email.strip()
        if _is_production():
            if email_for_claims.lower() != _PRODUCTION_ALLOWED_EMAIL.lower():
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid credentials",
                )
            role = "admin"
            user_id = "admin-owner"
            email_for_claims = _PRODUCTION_ALLOWED_EMAIL
        else:
            # Development / non-production: demo authentication based on email
            if "admin" in request.email:
                role = "admin"
                user_id = "admin-123"
            elif "user" in request.email:
                role = "user"
                user_id = "user-456"
            else:
                role = "readonly"
                user_id = "readonly-789"

        # Create access token (15 minutes)
        access_token = jwt_manager.create_token(
            {"sub": user_id, "email": email_for_claims, "role": role},
            expires_in=15 * 60,
        )  # 15 minutes

        # Create refresh token (7 days)
        refresh_token = secrets.token_urlsafe(32)
        refresh_jti = f"refresh_{refresh_token}"

        claims_blob = f"{user_id}|{email_for_claims}|{role}"

        # Store refresh token in Redis with expiry
        await redis_client.setex(
            f"refresh_token:{refresh_token}", timedelta(days=7), refresh_jti
        )
        await redis_client.setex(
            f"refresh_token_claims:{refresh_token}",
            timedelta(days=7),
            claims_blob,
        )

        # Set refresh token in httpOnly cookie (cross-site admin UI + HTTPS gateway)
        _set_refresh_token_cookie(response, refresh_token)

        return LoginResponse(
            access_token=access_token, expires_in=15 * 60, token_type="bearer"
        )

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh_access_token(
        http_request: Request,
        body: RefreshRequest,
        response: Response,
        credentials: HTTPAuthorizationCredentials | None = Depends(refresh_scheme),
    ) -> TokenResponse:
        """
        Refresh access token using refresh token.
        """

        refresh_token: str | None = body.refresh_token
        if not refresh_token and credentials and credentials.credentials:
            refresh_token = credentials.credentials
        if not refresh_token:
            refresh_token = http_request.cookies.get("refresh_token")

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token required",
            )

        # Check if refresh token exists and is not revoked
        refresh_jti = await redis_client.get(f"refresh_token:{refresh_token}")
        if not refresh_jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # Check if refresh token is revoked
        is_revoked = await redis_client.sismember(  # type: ignore[misc]
            "refresh_token:revoked", refresh_jti
        )
        if is_revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
            )

        claims_raw = await redis_client.get(f"refresh_token_claims:{refresh_token}")
        if not claims_raw:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired, please log in again",
            )

        parts = claims_raw.split("|", 2)
        if len(parts) != 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired, please log in again",
            )
        user_id, email, role = parts[0], parts[1], parts[2]

        # Create new access token
        new_access_token = jwt_manager.create_token(
            {"sub": user_id, "email": email, "role": role}, expires_in=15 * 60
        )  # 15 minutes

        # Create new refresh token (rotation)
        new_refresh_token = secrets.token_urlsafe(32)
        new_refresh_jti = f"refresh_{new_refresh_token}"

        # Revoke old refresh token
        await redis_client.sadd("refresh_token:revoked", refresh_jti)  # type: ignore[misc]
        await redis_client.delete(f"refresh_token:{refresh_token}")  # type: ignore[misc]
        await redis_client.delete(f"refresh_token_claims:{refresh_token}")  # type: ignore[misc]

        # Store new refresh token and claims
        await redis_client.setex(
            f"refresh_token:{new_refresh_token}", timedelta(days=7), new_refresh_jti
        )
        await redis_client.setex(
            f"refresh_token_claims:{new_refresh_token}",
            timedelta(days=7),
            claims_raw,
        )

        _set_refresh_token_cookie(response, new_refresh_token)

        return TokenResponse(
            access_token=new_access_token, expires_in=15 * 60, token_type="bearer"
        )

    @router.post("/logout")
    async def logout(
        http_request: Request,
        response: Response,
        credentials: HTTPAuthorizationCredentials | None = Depends(refresh_scheme),
    ) -> dict[str, Any]:
        """
        Logout user by revoking refresh token.
        """

        refresh_token: str | None = None

        if credentials and credentials.credentials:
            if credentials.credentials.startswith("refresh_"):
                refresh_token = credentials.credentials[8:]

        if not refresh_token:
            refresh_token = http_request.cookies.get("refresh_token")

        if refresh_token:
            refresh_jti = f"refresh_{refresh_token}"
            await redis_client.sadd("refresh_token:revoked", refresh_jti)  # type: ignore[misc]
            await redis_client.delete(f"refresh_token:{refresh_token}")  # type: ignore[misc]
            await redis_client.delete(f"refresh_token_claims:{refresh_token}")  # type: ignore[misc]

        response.delete_cookie(
            "refresh_token",
            path="/",
            secure=True,
            httponly=True,
            samesite="none",
        )

        return {"message": "Successfully logged out"}

    @router.get("/me")
    async def get_current_user(request: Request) -> dict[str, Any]:
        """
        Get current user information from access token (JWT middleware).
        """
        user = getattr(request.state, "user", None)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
        return {
            "sub": user.sub,
            "email": user.email,
            "role": user.role,
        }

    return router
