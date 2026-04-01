"""Mock downstream service for testing ShieldGate gateway"""

import os
from datetime import datetime

from fastapi import FastAPI

from .routes import router

app = FastAPI(
    title="Mock Downstream Service",
    description="Mock service for testing ShieldGate API gateway with 3-tier authentication",
    version="1.0.0",
)

app.include_router(router, prefix="/api/v1")


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
