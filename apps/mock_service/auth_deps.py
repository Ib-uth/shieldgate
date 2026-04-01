"""Auth helpers for mock service (separate from main to avoid circular imports with routes)."""

from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security_optional = HTTPBearer(auto_error=False)

MOCK_USERS = {
    "admin-123": {
        "id": "admin-123",
        "email": "admin@shieldgate.dev",
        "role": "admin",
        "name": "Admin User",
    },
    "user-456": {
        "id": "user-456",
        "email": "user@shieldgate.dev",
        "role": "user",
        "name": "Regular User",
    },
    "readonly-789": {
        "id": "readonly-789",
        "email": "readonly@shieldgate.dev",
        "role": "readonly",
        "name": "Readonly User",
    },
}


async def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_optional),
) -> dict[str, Any]:
    """Trust gateway-forwarded identity or mock Bearer tokens."""
    user_id = request.headers.get("X-User-ID")
    if user_id and user_id in MOCK_USERS:
        return MOCK_USERS[user_id]

    role = request.headers.get("X-User-Role")
    if user_id and role:
        return {
            "id": user_id,
            "email": request.headers.get("X-User-Email", ""),
            "role": role,
            "name": MOCK_USERS.get(user_id, {}).get("name", user_id),
        }

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token = credentials.credentials
    if token.startswith("mock-"):
        uid = token[5:]
        if uid in MOCK_USERS:
            return MOCK_USERS[uid]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
    )


def require_role(required_role: str):
    """Role requirement decorator"""

    def role_checker(user: dict[str, Any] = Depends(verify_token)):
        if user["role"] != required_role and user["role"] != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Required role: {required_role}",
            )
        return user

    return role_checker


def require_minimum_role(minimum_role: str):
    """Minimum role requirement decorator"""
    role_hierarchy = {"readonly": 1, "user": 2, "admin": 3}

    def role_checker(user: dict[str, Any] = Depends(verify_token)):
        user_level = role_hierarchy.get(user["role"], 0)
        required_level = role_hierarchy.get(minimum_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient privileges. Minimum role required: {minimum_role}",
            )
        return user

    return role_checker
