"""Structured logging middleware"""

import json
import time
import uuid
from datetime import datetime
from typing import Any

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..models.database import RequestLog, SessionLocal

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured JSON logging of all requests"""

    def __init__(self, app, log_to_db: bool = True):
        super().__init__(app)
        self.log_to_db = log_to_db

    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate request ID
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Record start time
        start_time = time.time()

        # Extract request information
        request_info = self.extract_request_info(request)

        # Log request start
        logger.info("request_started", request_id=request_id, **request_info)

        try:
            # Process request
            response = await call_next(request)

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # Extract response information
            response_info = self.extract_response_info(response, latency_ms)

            # Create log entry
            log_entry = self.create_log_entry(
                request_id=request_id,
                request_info=request_info,
                response_info=response_info,
            )

            # Log request completion
            logger.info("request_completed", request_id=request_id, **log_entry)

            # Store in database if enabled
            if self.log_to_db:
                await self.store_log_entry(log_entry)

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id

            return response

        except Exception as e:
            # Calculate latency for failed requests
            latency_ms = (time.time() - start_time) * 1000

            # Log error
            logger.error(
                "request_failed",
                request_id=request_id,
                error=str(e),
                latency_ms=latency_ms,
                **request_info,
            )

            # Store error log entry
            if self.log_to_db:
                error_log_entry = self.create_log_entry(
                    request_id=request_id,
                    request_info=request_info,
                    response_info={
                        "status_code": 500,
                        "latency_ms": latency_ms,
                        "response_size": 0,
                    },
                    error=str(e),
                )
                await self.store_log_entry(error_log_entry)

            raise

    def extract_request_info(self, request: Request) -> dict[str, Any]:
        """Extract relevant information from request"""
        # Get client IP
        client_ip = self.get_client_ip(request)

        # Get user agent
        user_agent = request.headers.get("user-agent", "")

        # Get user information if authenticated
        user_id = None
        user_role = None
        if hasattr(request.state, "user_id"):
            user_id = request.state.user_id
        if hasattr(request.state, "user_role"):
            user_role = request.state.user_role

        # Get threat score if available
        threat_score = 0.0
        if hasattr(request.state, "threat_score"):
            threat_score = request.state.threat_score

        # Get rate limit info if available
        rate_limit_info = None
        if hasattr(request.state, "rate_limit"):
            rate_limit_info = request.state.rate_limit

        return {
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": self.sanitize_headers(dict(request.headers)),
            "client_ip": client_ip,
            "user_agent": user_agent,
            "user_id": user_id,
            "user_role": user_role,
            "threat_score": threat_score,
            "rate_limit": rate_limit_info,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def extract_response_info(
        self, response: Response, latency_ms: float
    ) -> dict[str, Any]:
        """Extract relevant information from response"""
        return {
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "response_size": len(response.body) if hasattr(response, "body") else 0,
            "headers": self.sanitize_headers(dict(response.headers)),
        }

    def create_log_entry(
        self,
        request_id: str,
        request_info: dict[str, Any],
        response_info: dict[str, Any],
        error: str | None = None,
    ) -> dict[str, Any]:
        """Create a log entry dictionary"""
        return {
            "request_id": request_id,
            "timestamp": request_info["timestamp"],
            "method": request_info["method"],
            "path": request_info["path"],
            "status_code": response_info["status_code"],
            "latency_ms": response_info["latency_ms"],
            "user_id": request_info.get("user_id"),
            "ip": request_info["client_ip"],
            "user_agent": request_info["user_agent"],
            "threat_score": request_info.get("threat_score", 0.0),
            "blocked": response_info["status_code"] == 429
            or response_info["status_code"] == 403,
            "headers": json.dumps(request_info["headers"]),
            "response_size": response_info.get("response_size", 0),
            "error": error,
        }

    async def store_log_entry(self, log_entry: dict[str, Any]):
        """Store log entry in database"""
        try:
            db = SessionLocal()
            try:
                # Create RequestLog object
                db_log = RequestLog(
                    request_id=log_entry["request_id"],
                    timestamp=datetime.fromisoformat(
                        log_entry["timestamp"].replace("Z", "+00:00")
                    ),
                    method=log_entry["method"],
                    path=log_entry["path"],
                    status_code=log_entry["status_code"],
                    latency_ms=log_entry["latency_ms"],
                    user_id=log_entry.get("user_id"),
                    ip=log_entry["ip"],
                    user_agent=log_entry["user_agent"],
                    threat_score=log_entry["threat_score"],
                    blocked=log_entry["blocked"],
                    headers=log_entry.get("headers"),
                    response_size=log_entry.get("response_size"),
                )

                db.add(db_log)
                db.commit()

            except Exception as e:
                db.rollback()
                print(f"Failed to store log entry: {e}")
            finally:
                db.close()

        except Exception as e:
            print(f"Database connection error: {e}")

    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check for X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to client IP
        return request.client.host if request.client else "unknown"

    def sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitize headers to remove sensitive information"""
        sensitive_headers = {
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "password",
            "secret",
            "token",
            "key",
        }

        sanitized = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value

        return sanitized


class RequestLogger:
    """Helper class for request logging"""

    @staticmethod
    def log_security_event(
        request_id: str,
        event_type: str,
        details: dict[str, Any],
        severity: str = "warning",
    ):
        """Log security-related events"""
        logger.warning(
            "security_event",
            request_id=request_id,
            event_type=event_type,
            severity=severity,
            **details,
        )

    @staticmethod
    def log_threat_detection(
        request_id: str,
        threat_score: float,
        features: dict[str, Any],
        blocked: bool = False,
    ):
        """Log threat detection events"""
        severity = "critical" if blocked else "warning"

        logger.warning(
            "threat_detected",
            request_id=request_id,
            threat_score=threat_score,
            blocked=blocked,
            severity=severity,
            features=features,
        )

    @staticmethod
    def log_rate_limit_exceeded(
        request_id: str, identifier: str, limit_type: str, retry_after: int
    ):
        """Log rate limit exceeded events"""
        logger.warning(
            "rate_limit_exceeded",
            request_id=request_id,
            identifier=identifier,
            limit_type=limit_type,
            retry_after=retry_after,
            severity="warning",
        )

    @staticmethod
    def log_authentication_failure(request_id: str, reason: str, ip: str):
        """Log authentication failures"""
        logger.warning(
            "auth_failure",
            request_id=request_id,
            reason=reason,
            ip=ip,
            severity="warning",
        )
