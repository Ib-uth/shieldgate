"""Main FastAPI application for ShieldGate API Gateway"""

import os
import tempfile
from pathlib import Path

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .middleware.auth import JWTAuthenticator, JWTMiddleware
from .middleware.ratelimit import RateLimitMiddleware
from .middleware.rbac import RBACMiddleware
from .middleware.threat_detection import ThreatDetectionMiddleware
from .models.database import Base, engine
from .routes.admin import create_admin_routes
from .routes.auth import create_auth_routes
from .routes.health import create_health_routes, create_metrics_routes
from .routes.proxy import RequestProxy, create_proxy_routes
from .utils.jwt_utils import JWTManager

# Global variables for services
jwt_manager: JWTManager | None = None
jwt_authenticator: JWTAuthenticator | None = None
rbac_middleware: RBACMiddleware | None = None
request_proxy: RequestProxy | None = None
redis_client: redis.Redis | None = None

_routes_registered = False


def _writable_jwt_key_paths(
    preferred_private: str, preferred_public: str
) -> tuple[str, str]:
    """Return paths for JWT PEM files in a directory we can create/write (e.g. Render read-only app root)."""
    keys_dir = os.getenv("JWT_KEYS_DIR")
    if keys_dir:
        d = Path(keys_dir).expanduser()
        d.mkdir(parents=True, exist_ok=True)
        return str(d / "private.pem"), str(d / "public.pem")

    parent = Path(preferred_private).expanduser().resolve().parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        probe = parent / ".shieldgate_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return preferred_private, preferred_public
    except OSError:
        tmp_root = os.environ.get("TMPDIR") or tempfile.gettempdir()
        fallback = Path(tmp_root) / "shieldgate-jwt-keys"
        fallback.mkdir(parents=True, exist_ok=True)
        return str(fallback / "private.pem"), str(fallback / "public.pem")


async def startup():
    """Initialize application services"""
    global jwt_manager, jwt_authenticator, rbac_middleware, request_proxy, redis_client

    print("Starting ShieldGate API Gateway...")

    # Initialize Redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    try:
        redis_client = redis.from_url(redis_url)
        await redis_client.ping()
        print("Redis connection established")
    except Exception as e:
        print(f"Failed to connect to Redis: {e}")
        redis_client = None

    # Initialize JWT manager (use JWT_KEYS_DIR or /tmp fallback when app dir is read-only)
    private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem")
    public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

    try:
        jwt_manager = JWTManager(private_key_path, public_key_path)
        if jwt_manager.load_keys():
            print("JWT keys loaded successfully")
            jwt_authenticator = JWTAuthenticator(jwt_manager)
        else:
            print("Failed to load JWT keys, generating new ones...")
            wpriv, wpub = _writable_jwt_key_paths(private_key_path, public_key_path)
            if (wpriv, wpub) != (private_key_path, public_key_path):
                jwt_manager = JWTManager(wpriv, wpub)
            jwt_manager.generate_key_pair(wpriv, wpub)
            if jwt_manager.load_keys():
                jwt_authenticator = JWTAuthenticator(jwt_manager)
            else:
                print("Could not load JWT keys after generation")
    except Exception as e:
        print(f"Failed to initialize JWT manager: {e}")

    # Initialize RBAC
    if jwt_manager and jwt_authenticator:
        rbac_middleware = RBACMiddleware(jwt_authenticator)
        print("RBAC middleware initialized")

    # Initialize request proxy
    downstream_url = os.getenv("DOWNSTREAM_URL", "http://localhost:8001")
    try:
        if jwt_authenticator:
            request_proxy = RequestProxy(downstream_url, jwt_authenticator)
            print("Request proxy initialized")
        else:
            print("Skipping request proxy: JWT authenticator not available")
    except Exception as e:
        print(f"Failed to initialize request proxy: {e}")

    # Initialize database
    try:
        # Create tables using the engine from database.py
        if engine:
            Base.metadata.create_all(bind=engine)
            print("Database initialized")
        else:
            print("DATABASE_URL not set, skipping database initialization")
    except Exception as e:
        print(f"Failed to initialize database: {e}")
        raise

    print("ShieldGate API Gateway started successfully!")


async def shutdown():
    """Cleanup application services"""
    global redis_client

    print("Shutting down ShieldGate API Gateway...")

    # Close Redis connection
    if redis_client:
        await redis_client.close()
        print("Redis connection closed")

    # Close database connections
    if engine:
        engine.dispose()
        print("Database connections closed")

    print("ShieldGate API Gateway shut down complete")


# Create FastAPI application
app = FastAPI(
    title="ShieldGate API Gateway",
    description="Production-ready API gateway with auth, rate limiting & threat detection",
    version="1.0.0",
)

# Middleware must be registered at import time (Starlette forbids add_middleware during startup).
# Order: first registered is innermost (closest to routes); last registered is outermost (runs first).
_redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
app.add_middleware(
    RateLimitMiddleware,
    redis_url=_redis_url,
    ip_requests=int(os.getenv("RATE_LIMIT_IP_REQUESTS", 60)),
    ip_window=int(os.getenv("RATE_LIMIT_IP_WINDOW", 60)),
    user_requests=int(os.getenv("RATE_LIMIT_USER_REQUESTS", 300)),
    user_window=int(os.getenv("RATE_LIMIT_USER_WINDOW", 60)),
    skip_paths=["/health", "/metrics"],
)
_model_path = os.getenv("THREAT_MODEL_PATH", "./models/threat_model.joblib")
_flag_t = float(os.getenv("THREAT_SCORE_FLAG_THRESHOLD", 0.7))
_block_t = float(os.getenv("THREAT_SCORE_BLOCK_THRESHOLD", 0.9))
app.add_middleware(
    ThreatDetectionMiddleware,
    get_redis_client=lambda: redis_client,
    model_path=_model_path,
    flag_threshold=_flag_t,
    block_threshold=_block_t,
)
app.add_middleware(
    JWTMiddleware,
    get_jwt_manager=lambda: jwt_manager,
    public_paths=[
        "/health",
        "/metrics",
        "/auth/login",
        "/auth/refresh",
        "/auth/logout",
        "/auth/test-tokens",
    ],
)
# CORS last so it is outermost: handles OPTIONS preflight before JWT / route matching.
# If ALLOWED_ORIGINS is unset or empty, browsers get 400 on preflight ("Disallowed CORS origin").
_default_cors = "http://localhost:3000,https://shieldgate.onrender.com"
_cors_env = os.getenv("ALLOWED_ORIGINS", _default_cors).strip()
if not _cors_env:
    _cors_env = _default_cors
allowed_origins = [o.strip().rstrip("/") for o in _cors_env.split(",") if o.strip()]
_allow_origin_regex = os.getenv("ALLOWED_ORIGIN_REGEX", "").strip() or None
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=_allow_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add routes
def setup_routes():
    """Setup application routes"""
    # Health and metrics always (needed for load balancers / degraded startup)
    health_router = create_health_routes(redis_client, engine)
    metrics_router = create_metrics_routes(redis_client, engine)
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(metrics_router, prefix="/metrics", tags=["metrics"])

    admin_router = create_admin_routes(rbac_middleware, engine)
    app.include_router(admin_router, prefix="/admin", tags=["admin"])

    if not request_proxy:
        print(
            "Warning: Request proxy not initialized — /proxy/* routes are not registered "
            "(set JWT keys and DOWNSTREAM_URL for full gateway)"
        )
        return

    proxy_handler, _catch_all = create_proxy_routes(request_proxy)
    app.add_route(
        "/proxy/{path:path}",
        proxy_handler,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )


@app.on_event("startup")
async def on_startup():
    global _routes_registered
    await startup()
    if _routes_registered:
        return
    # Auth routes need JWT; login/refresh need Redis for refresh tokens. If Redis is
    # missing, routes still register so clients get 503 + message instead of 404.
    if jwt_manager:
        app.include_router(
            create_auth_routes(jwt_manager, redis_client, engine=engine),
            tags=["authentication"],
        )
    setup_routes()
    _routes_registered = True


@app.on_event("shutdown")
async def on_shutdown():
    await shutdown()


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "ShieldGate API Gateway",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "metrics": "/metrics",
            "admin": "/admin",
            "proxy": "/proxy/{path}",
        },
    }


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "http_error",
                "status_code": exc.status_code,
                "detail": exc.detail,
                "request_id": getattr(request.state, "request_id", "unknown"),
            }
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "internal_error",
                "status_code": 500,
                "detail": "Internal server error",
                "request_id": getattr(request.state, "request_id", "unknown"),
            }
        },
    )


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("GATEWAY_HOST", "0.0.0.0")
    port = int(os.getenv("GATEWAY_PORT", 8000))

    uvicorn.run("main:app", host=host, port=port, reload=True, log_level="info")
