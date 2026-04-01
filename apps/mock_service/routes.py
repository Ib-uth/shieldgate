"""API routes for mock downstream service"""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from .main import require_minimum_role, require_role, verify_token

router = APIRouter()

# Mock data stores
MOCK_DATA = {
    "posts": [
        {
            "id": "1",
            "title": "First Post",
            "content": "This is the first post",
            "author": "user-456",
        },
        {
            "id": "2",
            "title": "Second Post",
            "content": "This is the second post",
            "author": "user-456",
        },
        {
            "id": "3",
            "title": "Admin Post",
            "content": "This is an admin post",
            "author": "admin-123",
        },
    ],
    "users": [
        {
            "id": "user-456",
            "name": "Regular User",
            "email": "user@shieldgate.dev",
            "role": "user",
        },
        {
            "id": "readonly-789",
            "name": "Readonly User",
            "email": "readonly@shieldgate.dev",
            "role": "readonly",
        },
        {
            "id": "admin-123",
            "name": "Admin User",
            "email": "admin@shieldgate.dev",
            "role": "admin",
        },
    ],
    "settings": {
        "maintenance_mode": False,
        "max_users": 1000,
        "feature_flags": {"new_ui": True, "beta_features": False},
    },
}


# Public endpoints (no authentication required)
@router.get("/public")
async def public_endpoint():
    """Public endpoint - no authentication required"""
    return {
        "message": "This is a public endpoint",
        "access_level": "public",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "service_info": "Mock Downstream Service",
            "version": "1.0.0",
            "public_data": "Anyone can access this",
        },
    }


@router.get("/public/posts")
async def get_public_posts():
    """Get public posts - no authentication required"""
    return {
        "posts": MOCK_DATA["posts"][:2],  # Return first 2 posts
        "total": len(MOCK_DATA["posts"]),
        "access_level": "public",
    }


# User endpoints (require user role or higher)
@router.get("/user")
async def user_endpoint(user: dict[str, Any] = Depends(require_minimum_role("user"))):
    """User endpoint - requires user role or higher"""
    return {
        "message": f"Hello {user['name']}! This is a user-only endpoint",
        "access_level": "user",
        "user_info": {"id": user["id"], "name": user["name"], "role": user["role"]},
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/user/posts")
async def get_user_posts(user: dict[str, Any] = Depends(require_minimum_role("user"))):
    """Get all posts - requires user role or higher"""
    return {
        "posts": MOCK_DATA["posts"],
        "total": len(MOCK_DATA["posts"]),
        "access_level": "user",
        "requested_by": user["name"],
    }


@router.get("/user/profile")
async def get_user_profile(
    user: dict[str, Any] = Depends(require_minimum_role("user")),
):
    """Get user profile - requires user role or higher"""
    return {
        "profile": user,
        "access_level": "user",
        "permissions": ["read_posts", "create_posts", "update_own_posts"],
    }


# Admin endpoints (require admin role only)
@router.get("/admin")
async def admin_endpoint(user: dict[str, Any] = Depends(require_role("admin"))):
    """Admin endpoint - requires admin role only"""
    return {
        "message": f"Hello {user['name']}! This is an admin-only endpoint",
        "access_level": "admin",
        "admin_info": {
            "id": user["id"],
            "name": user["name"],
            "role": user["role"],
            "permissions": ["read", "write", "delete", "admin"],
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/admin/users")
async def get_all_users(user: dict[str, Any] = Depends(require_role("admin"))):
    """Get all users - requires admin role"""
    return {
        "users": MOCK_DATA["users"],
        "total": len(MOCK_DATA["users"]),
        "access_level": "admin",
        "requested_by": user["name"],
    }


@router.get("/admin/settings")
async def get_system_settings(user: dict[str, Any] = Depends(require_role("admin"))):
    """Get system settings - requires admin role"""
    return {
        "settings": MOCK_DATA["settings"],
        "access_level": "admin",
        "requested_by": user["name"],
    }


@router.post("/admin/settings")
async def update_system_settings(
    settings: dict[str, Any], user: dict[str, Any] = Depends(require_role("admin"))
):
    """Update system settings - requires admin role"""
    # In a real service, this would update the database
    return {
        "message": "Settings updated successfully",
        "updated_settings": settings,
        "access_level": "admin",
        "updated_by": user["name"],
        "timestamp": datetime.utcnow().isoformat(),
    }


# Test endpoints for different scenarios
@router.get("/test/auth")
async def test_authentication(user: dict[str, Any] = Depends(verify_token)):
    """Test authentication - any authenticated user"""
    return {
        "message": "Authentication successful",
        "user": user,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/test/delay/{seconds}")
async def test_delay(seconds: int):
    """Test endpoint with artificial delay"""
    import asyncio

    await asyncio.sleep(seconds)
    return {
        "message": f"Response after {seconds} seconds",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/test/error/{status_code}")
async def test_error(status_code: int):
    """Test endpoint that returns error"""
    raise HTTPException(
        status_code=status_code, detail=f"Test error with status code {status_code}"
    )
