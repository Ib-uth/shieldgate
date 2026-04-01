"""JWT authentication middleware"""

from collections.abc import Callable

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

from ..models.schemas import UserClaims
from ..utils.jwt_utils import JWTManager


def _jwt_auth_json_response(
    request: Request, status_code: int, detail: str, *, www_authenticate: bool
) -> JSONResponse:
    """Return 401-style JSON without raising through BaseHTTPMiddleware (avoids ExceptionGroup in TestClient)."""
    headers = {"WWW-Authenticate": "Bearer"} if www_authenticate else None
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "type": "http_error",
                "status_code": status_code,
                "detail": detail,
                "request_id": getattr(request.state, "request_id", "unknown"),
            }
        },
        headers=headers,
    )


class JWTMiddleware(BaseHTTPMiddleware):
    """Middleware to handle JWT authentication"""

    def __init__(
        self,
        app,
        get_jwt_manager: Callable[[], JWTManager | None],
        public_paths: list | None = None,
    ):
        super().__init__(app)
        self._get_jwt_manager = get_jwt_manager
        self.public_paths = public_paths or ["/health", "/metrics"]
        self.security = HTTPBearer(auto_error=False)

    async def dispatch(self, request: Request, call_next: Callable):
        path = request.url.path
        if path in self.public_paths:
            return await call_next(request)
        if path.startswith("/health/") or path.startswith("/metrics/"):
            return await call_next(request)
        if path == "/auth" or path.startswith("/auth/"):
            return await call_next(request)
        if path == "/proxy/public" or path.startswith("/proxy/public/"):
            return await call_next(request)

        jwt_manager = self._get_jwt_manager()
        if jwt_manager is None:
            return await call_next(request)

        # Extract token from Authorization header
        credentials: HTTPAuthorizationCredentials | None = await self.security(request)

        if credentials is None:
            return _jwt_auth_json_response(
                request,
                status.HTTP_401_UNAUTHORIZED,
                "Missing authorization header",
                www_authenticate=True,
            )

        # Verify token
        user_claims = jwt_manager.verify_token(credentials.credentials)

        if user_claims is None:
            return _jwt_auth_json_response(
                request,
                status.HTTP_401_UNAUTHORIZED,
                "Invalid or expired token",
                www_authenticate=True,
            )

        # Check if token is expired
        if jwt_manager.is_token_expired(credentials.credentials):
            return _jwt_auth_json_response(
                request,
                status.HTTP_401_UNAUTHORIZED,
                "Token expired",
                www_authenticate=True,
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
