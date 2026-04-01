"""Role-Based Access Control (RBAC) middleware and decorators"""

from collections.abc import Callable
from functools import wraps

from fastapi import HTTPException, Request, status

from .auth import JWTAuthenticator


class RoleHierarchy:
    """Defines role hierarchy and permissions"""

    # Role hierarchy: higher number = more privileges
    ROLE_LEVELS = {"readonly": 1, "user": 2, "admin": 3}

    # Role permissions
    ROLE_PERMISSIONS = {
        "readonly": ["read"],
        "user": ["read", "write"],
        "admin": ["read", "write", "delete", "admin"],
    }

    @classmethod
    def can_access(cls, user_role: str, required_role: str) -> bool:
        """Check if user role can access required role"""
        if user_role not in cls.ROLE_LEVELS:
            return False
        if required_role not in cls.ROLE_LEVELS:
            return False

        return cls.ROLE_LEVELS[user_role] >= cls.ROLE_LEVELS[required_role]

    @classmethod
    def has_permission(cls, user_role: str, permission: str) -> bool:
        """Check if user role has specific permission"""
        if user_role not in cls.ROLE_PERMISSIONS:
            return False

        return permission in cls.ROLE_PERMISSIONS[user_role]


class RBACMiddleware:
    """RBAC middleware for role-based access control"""

    def __init__(self, jwt_authenticator: JWTAuthenticator):
        self.jwt_authenticator = jwt_authenticator

    def check_role(self, request: Request, required_role: str) -> bool:
        """Check if current user has required role"""
        try:
            user_role = self.jwt_authenticator.get_user_role(request)
            return RoleHierarchy.can_access(user_role, required_role)
        except HTTPException:
            return False

    def check_permission(self, request: Request, permission: str) -> bool:
        """Check if current user has specific permission"""
        try:
            user_role = self.jwt_authenticator.get_user_role(request)
            return RoleHierarchy.has_permission(user_role, permission)
        except HTTPException:
            return False


def require_role(required_role: str):
    """Decorator to require specific role for route access"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from function arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")

            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found",
                )

            # Check if user is authenticated
            if not hasattr(request.state, "user_role"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            user_role = request.state.user_role

            # Check role hierarchy
            if not RoleHierarchy.can_access(user_role, required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges. Required role: {required_role}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_permission(permission: str):
    """Decorator to require specific permission for route access"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from function arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")

            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found",
                )

            # Check if user is authenticated
            if not hasattr(request.state, "user_role"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            user_role = request.state.user_role

            # Check permission
            if not RoleHierarchy.has_permission(user_role, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges. Required permission: {permission}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_roles(roles: list[str]):
    """Decorator to require any of the specified roles"""

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from function arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if request is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Request object not found",
                )

            # Check if user is authenticated
            if not hasattr(request.state, "user_role"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            user_role = request.state.user_role

            # Check if user has any of the required roles
            has_required_role = any(
                RoleHierarchy.can_access(user_role, role) for role in roles
            )

            if not has_required_role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient privileges. Required one of: {', '.join(roles)}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# Common role decorators
require_admin = require_role("admin")
require_user = require_role("user")
require_readonly = require_role("readonly")

# Common permission decorators
require_read_permission = require_permission("read")
require_write_permission = require_permission("write")
require_delete_permission = require_permission("delete")
require_admin_permission = require_permission("admin")
