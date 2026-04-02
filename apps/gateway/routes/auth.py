"""Authentication routes for login, refresh, and logout"""

import os
import secrets
from datetime import timedelta
from typing import Any

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from ..middleware.rbac import require_role
from ..utils.jwt_utils import JWTManager, create_sample_tokens


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
        For demo purposes, we'll create tokens based on email domain.
        """

        # Simple demo authentication based on email
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
            {"sub": user_id, "email": request.email, "role": role}, expires_in=15 * 60
        )  # 15 minutes

        # Create refresh token (7 days)
        refresh_token = secrets.token_urlsafe(32)
        refresh_jti = f"refresh_{refresh_token}"

        # Store refresh token in Redis with expiry
        await redis_client.setex(
            f"refresh_token:{refresh_token}", timedelta(days=7), refresh_jti
        )

        # Set refresh token in httpOnly cookie
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=7 * 24 * 60 * 60,  # 7 days
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
        )

        return LoginResponse(
            access_token=access_token, expires_in=15 * 60, token_type="bearer"
        )

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh_access_token(
        request: RefreshRequest,
        response: Response,
        credentials: HTTPAuthorizationCredentials | None = Depends(refresh_scheme),
    ) -> TokenResponse:
        """
        Refresh access token using refresh token.
        """

        # Get refresh token from cookie or request body
        refresh_token = None

        if request.refresh_token:
            refresh_token = request.refresh_token
        elif credentials and credentials.credentials:
            # Try to get from Authorization header (for testing)
            refresh_token = credentials.credentials

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

        # Get user info from refresh token (in real implementation, this would come from database)
        # For demo, extract role from token pattern
        user_id = f"refresh-user-{refresh_token[:8]}"
        email = f"refresh-{refresh_token[:8]}@example.com"
        role = "user"  # Default role for refresh

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

        # Store new refresh token
        await redis_client.setex(
            f"refresh_token:{new_refresh_token}", timedelta(days=7), new_refresh_jti
        )

        # Set new refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            max_age=7 * 24 * 60 * 60,  # 7 days
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
        )

        return TokenResponse(
            access_token=new_access_token, expires_in=15 * 60, token_type="bearer"
        )

    @router.post("/logout")
    async def logout(
        response: Response,
        credentials: HTTPAuthorizationCredentials | None = Depends(refresh_scheme),
    ) -> dict[str, Any]:
        """
        Logout user by revoking refresh token.
        """

        # Try to get refresh token from Authorization header (for testing)
        refresh_token = None

        if credentials and credentials.credentials:
            # Check if it's a refresh token (starts with 'refresh_')
            if credentials.credentials.startswith("refresh_"):
                # Extract actual token from JTI
                refresh_token = credentials.credentials[8:]  # Remove 'refresh_' prefix

        # Also try to get from cookie (normal flow)
        if not refresh_token:
            # In a real implementation, you'd get this from the request cookies
            # For now, we'll skip this as it requires request object access
            pass

        if refresh_token:
            # Revoke the refresh token
            refresh_jti = f"refresh_{refresh_token}"
            await redis_client.sadd("refresh_token:revoked", refresh_jti)  # type: ignore[misc]
            await redis_client.delete(f"refresh_token:{refresh_token}")  # type: ignore[misc]

        # Clear refresh token cookie
        response.delete_cookie("refresh_token")

        return {"message": "Successfully logged out"}

    @router.get("/me")
    @require_role("readonly")
    async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    ) -> dict[str, Any]:
        """
        Get current user information from access token.
        """
        # This would normally validate the token and return user info
        # For now, return a placeholder
        return {
            "message": "This endpoint would return current user information",
            "token": credentials.credentials,
        }

    return router
