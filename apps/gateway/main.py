"""Main FastAPI application for ShieldGate API Gateway"""

import os
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from .middleware.auth import JWTAuthenticator, JWTMiddleware
from .middleware.ratelimit import RateLimitMiddleware
from .middleware.rbac import RBACMiddleware
from .middleware.threat_detection import ThreatDetectionMiddleware
from .models.database import Base, engine
from .routes.admin import create_admin_routes
from .routes.auth import create_auth_routes
from .routes.health import create_health_routes
from .routes.proxy import RequestProxy, create_proxy_routes
from .utils.jwt_utils import JWTManager

# Global variables for services
jwt_manager: JWTManager | None = None
jwt_authenticator: JWTAuthenticator | None = None
rbac_middleware: RBACMiddleware | None = None
request_proxy: RequestProxy | None = None
redis_client: redis.Redis | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    await startup()
    yield
    # Shutdown
    await shutdown()


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

    # Initialize JWT manager
    private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem")
    public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

    try:
        jwt_manager = JWTManager(private_key_path, public_key_path)
        if jwt_manager.load_keys():
            print("JWT keys loaded successfully")
            jwt_authenticator = JWTAuthenticator(jwt_manager)
        else:
            print("Failed to load JWT keys, generating new ones...")
            jwt_manager.generate_key_pair(private_key_path, public_key_path)
            jwt_manager.load_keys()
            jwt_authenticator = JWTAuthenticator(jwt_manager)
    except Exception as e:
        print(f"Failed to initialize JWT manager: {e}")

    # Initialize RBAC
    if jwt_manager:
        rbac_middleware = RBACMiddleware()
        print("RBAC middleware initialized")

    # Initialize request proxy
    downstream_url = os.getenv("DOWNSTREAM_URL", "http://localhost:8001")
    try:
        request_proxy = RequestProxy(downstream_url)
        print("Request proxy initialized")
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
    lifespan=lifespan,
)

# Add CORS middleware
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Add custom middleware
def setup_middleware(app):
    """Setup application middleware"""
    # Rate limiting middleware
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    app.add_middleware(
        RateLimitMiddleware,
        redis_url=redis_url,
        ip_requests=int(os.getenv("RATE_LIMIT_IP_REQUESTS", 60)),
        ip_window=int(os.getenv("RATE_LIMIT_IP_WINDOW", 60)),
        user_requests=int(os.getenv("RATE_LIMIT_USER_REQUESTS", 300)),
        user_window=int(os.getenv("RATE_LIMIT_USER_WINDOW", 60)),
        skip_paths=["/health", "/metrics"],
    )

    # JWT authentication middleware
    if jwt_manager:
        app.add_middleware(
            JWTMiddleware,
            jwt_manager=jwt_manager,
            public_paths=["/health", "/metrics", "/auth"],
        )

    # RBAC middleware
    if rbac_middleware:
        app.add_middleware(RBACMiddleware, rbac=rbac_middleware)

    # Threat detection middleware
    if redis_client:
        model_path = os.getenv("THREAT_MODEL_PATH", "./models/threat_model.joblib")
        flag_threshold = float(os.getenv("THREAT_SCORE_FLAG_THRESHOLD", 0.7))
        block_threshold = float(os.getenv("THREAT_SCORE_BLOCK_THRESHOLD", 0.9))

        app.add_middleware(
            ThreatDetectionMiddleware,
            redis_client=redis_client,
            model_path=model_path,
            flag_threshold=flag_threshold,
            block_threshold=block_threshold,
        )

    # Auth routes
    if jwt_manager and redis_client:
        auth_router = create_auth_routes(jwt_manager, redis_client)
        app.include_router(auth_router, tags=["authentication"])


# Setup middleware after JWT manager is initialized
@app.on_event("startup")
async def setup_app_middleware():
    """Setup middleware after startup"""
    setup_middleware(app)


# Add routes
def setup_routes():
    """Setup application routes"""
    if not request_proxy:
        raise RuntimeError("Request proxy not initialized")

    # Health and metrics routes
    health_router, metrics_router = create_health_routes(redis_client, engine)
    app.include_router(health_router, prefix="/health", tags=["health"])
    app.include_router(metrics_router, prefix="/metrics", tags=["metrics"])

    # Admin routes
    admin_router = create_admin_routes(rbac_middleware, engine)
    app.include_router(admin_router, prefix="/admin", tags=["admin"])

    # Proxy routes
    proxy_handler, catch_all_handler = create_proxy_routes(request_proxy)

    # Specific proxy routes
    app.add_route(
        "/proxy/{path:path}",
        proxy_handler,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )

    # Catch-all proxy for any other path
    app.add_route(
        "/{path:path}",
        catch_all_handler,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )


# Setup routes after all dependencies are initialized
@app.on_event("startup")
async def setup_app_routes():
    """Setup routes after startup"""
    setup_routes()


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
            "catch_all": "/{path}",
        },
    }


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions"""
    return {
        "error": {
            "type": "http_error",
            "status_code": exc.status_code,
            "detail": exc.detail,
            "request_id": getattr(request.state, "request_id", "unknown"),
        }
    }


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    return {
        "error": {
            "type": "internal_error",
            "status_code": 500,
            "detail": "Internal server error",
            "request_id": getattr(request.state, "request_id", "unknown"),
        }
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("GATEWAY_HOST", "0.0.0.0")
    port = int(os.getenv("GATEWAY_PORT", 8000))

    uvicorn.run("main:app", host=host, port=port, reload=True, log_level="info")
