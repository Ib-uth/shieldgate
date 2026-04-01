"""JWT authentication middleware"""

from collections.abc import Callable

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

from ..models.schemas import UserClaims
from ..utils.jwt_utils import JWTManager


class JWTMiddleware(BaseHTTPMiddleware):
    """Middleware to handle JWT authentication"""

    def __init__(self, app, jwt_manager: JWTManager, public_paths: list | None = None):
        super().__init__(app)
        self.jwt_manager = jwt_manager
        self.public_paths = public_paths or ["/health", "/metrics"]
        self.security = HTTPBearer(auto_error=False)

    async def dispatch(self, request: Request, call_next: Callable):
        # Skip auth for public paths
        if request.url.path in self.public_paths:
            return await call_next(request)

        # Extract token from Authorization header
        credentials: HTTPAuthorizationCredentials | None = await self.security(request)

        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Verify token
        user_claims = self.jwt_manager.verify_token(credentials.credentials)

        if user_claims is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check if token is expired
        if self.jwt_manager.is_token_expired(credentials.credentials):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Add user claims to request state
        request.state.user = user_claims
        request.state.user_id = user_claims.sub
        request.state.user_role = user_claims.role

        return await call_next(request)


class JWTAuthenticator:
    """Helper class for JWT authentication in route handlers"""

    def __init__(self, jwt_manager: JWTManager):
        self.jwt_manager = jwt_manager

    def get_current_user(self, request: Request) -> UserClaims:
        """Get current user from request state"""
        if not hasattr(request.state, "user"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
        return request.state.user

    def get_user_id(self, request: Request) -> str:
        """Get current user ID from request state"""
        if not hasattr(request.state, "user_id"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
        return request.state.user_id

    def get_user_role(self, request: Request) -> str:
        """Get current user role from request state"""
        if not hasattr(request.state, "user_role"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
            )
        return request.state.user_role

    def create_token(self, user_claims: dict, expires_in: int = 3600) -> str:
        """Create a JWT token"""
        return self.jwt_manager.create_token(user_claims, expires_in)

    def verify_token(self, token: str) -> UserClaims | None:
        """Verify and decode a JWT token"""
        return self.jwt_manager.verify_token(token)
