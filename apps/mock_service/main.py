"""Mock downstream service for testing ShieldGate gateway"""

import os
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .routes import router

app = FastAPI(
    title="Mock Downstream Service",
    description="Mock service for testing ShieldGate API gateway with 3-tier authentication",
    version="1.0.0",
)

# Include routes
app.include_router(router, prefix="/api/v1")

# JWT verification (simplified for mock service)
security = HTTPBearer()

# Mock data
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


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict[str, Any]:
    """Simple token verification for mock service"""
    # In a real service, this would verify the JWT signature
    # For mock purposes, we'll extract user info from a mock token format
    token = credentials.credentials

    # Mock token format: "mock-{user_id}"
    if token.startswith("mock-"):
        user_id = token[5:]
        if user_id in MOCK_USERS:
            return MOCK_USERS[user_id]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
    )


def require_role(required_role: str):
    """Role requirement decorator"""

    def role_checker(user: dict[str, Any] = Depends(verify_token)):
        if (
            user["role"] != required_role and user["role"] != "admin"
        ):  # Admin can access everything
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


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "mock-downstream",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Mock Downstream Service",
        "message": "This is a mock service for testing ShieldGate API gateway",
        "endpoints": {
            "public": "/public - No authentication required",
            "user": "/user - Requires user role or higher",
            "admin": "/admin - Requires admin role only",
        },
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("MOCK_SERVICE_PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)
