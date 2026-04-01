"""Redis-based sliding window rate limiting middleware"""

import time
from typing import Any

import redis.asyncio as redis
import redis.exceptions
from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


class RedisRateLimiter:
    """Redis-based sliding window rate limiter"""

    def __init__(
        self,
        redis_client: redis.Redis,
        ip_requests: int = 60,
        ip_window: int = 60,
        user_requests: int = 300,
        user_window: int = 60,
    ):
        self.redis = redis_client
        self.ip_requests = ip_requests
        self.ip_window = ip_window
        self.user_requests = user_requests
        self.user_window = user_window

    async def is_rate_limited(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
        current_time: float | None = None,
    ) -> dict[str, Any]:
        """
        Check if rate limit is exceeded using sliding window algorithm

        Args:
            key: Redis key for rate limiting
            max_requests: Maximum requests allowed
            window_seconds: Time window in seconds
            current_time: Current timestamp (for testing)

        Returns:
            Dict with rate limiting info
        """
        if current_time is None:
            current_time = time.time()

        # Remove old entries outside the window
        window_start = current_time - window_seconds
        await self.redis.zremrangebyscore(key, 0, window_start)

        # Count current requests in window
        current_requests = await self.redis.zcard(key)

        # Check if rate limit exceeded
        is_limited = current_requests >= max_requests

        # Add current request to the sorted set
        await self.redis.zadd(key, {str(current_time): current_time})

        # Set expiration on the key
        await self.redis.expire(key, window_seconds)

        # Calculate retry-after if limited
        retry_after = 0
        if is_limited:
            # Get the oldest request timestamp
            oldest_requests = await self.redis.zrange(key, 0, 0, withscores=True)
            if oldest_requests:
                oldest_timestamp = oldest_requests[0][1]
                retry_after = int(oldest_timestamp + window_seconds - current_time)
                retry_after = max(1, retry_after)  # At least 1 second

        return {
            "limited": is_limited,
            "current_requests": current_requests,
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "retry_after": retry_after,
            "reset_time": int(current_time + window_seconds),
        }

    async def check_ip_rate_limit(self, ip: str) -> dict[str, Any]:
        """Check rate limit for IP address"""
        key = f"rate_limit:ip:{ip}"
        return await self.is_rate_limited(key, self.ip_requests, self.ip_window)

    async def check_user_rate_limit(self, user_id: str) -> dict[str, Any]:
        """Check rate limit for authenticated user"""
        key = f"rate_limit:user:{user_id}"
        return await self.is_rate_limited(key, self.user_requests, self.user_window)

    async def get_rate_limit_stats(self, key: str) -> dict[str, Any]:
        """Get current rate limit statistics"""
        current_time = time.time()

        # Get all requests in the current window
        requests = await self.redis.zrange(key, 0, -1, withscores=True)

        if not requests:
            return {
                "current_requests": 0,
                "requests_in_window": [],
                "window_start": current_time - self.ip_window,
                "window_end": current_time,
            }

        request_times = [float(req[1]) for req in requests]

        return {
            "current_requests": len(request_times),
            "requests_in_window": request_times,
            "window_start": current_time - self.ip_window,
            "window_end": current_time,
            "oldest_request": min(request_times),
            "newest_request": max(request_times),
        }


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""

    def __init__(
        self,
        app,
        redis_url: str,
        ip_requests: int = 60,
        ip_window: int = 60,
        user_requests: int = 300,
        user_window: int = 60,
        skip_paths: list | None = None,
    ):
        super().__init__(app)
        self.redis_url = redis_url
        self.ip_requests = ip_requests
        self.ip_window = ip_window
        self.user_requests = user_requests
        self.user_window = user_window
        self.skip_paths = skip_paths or ["/health", "/metrics"]
        self._redis_client = None

    async def get_redis_client(self) -> redis.Redis:
        """Get or create Redis client"""
        if self._redis_client is None:
            self._redis_client = redis.from_url(self.redis_url, decode_responses=True)
        return self._redis_client

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for certain paths
        if request.url.path in self.skip_paths:
            return await call_next(request)

        # Get client IP
        client_ip = self.get_client_ip(request)

        try:
            redis_client = await self.get_redis_client()
            rate_limiter = RedisRateLimiter(
                redis_client,
                self.ip_requests,
                self.ip_window,
                self.user_requests,
                self.user_window,
            )

            # Check rate limit based on authentication
            if hasattr(request.state, "user_id"):
                # Authenticated user - use user rate limit
                rate_limit_result = await rate_limiter.check_user_rate_limit(
                    request.state.user_id
                )
                limit_type = "user"
            else:
                # Unauthenticated - use IP rate limit
                rate_limit_result = await rate_limiter.check_ip_rate_limit(client_ip)
                limit_type = "ip"

            # Add rate limit info to request state
            request.state.rate_limit = rate_limit_result
            request.state.rate_limit_type = limit_type

            # Return 429 if rate limited
            if rate_limit_result["limited"]:
                response = Response(
                    content="Rate limit exceeded",
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                )
                response.headers["X-RateLimit-Limit"] = str(
                    rate_limit_result["max_requests"]
                )
                response.headers["X-RateLimit-Remaining"] = "0"
                response.headers["X-RateLimit-Reset"] = str(
                    rate_limit_result["reset_time"]
                )
                response.headers["Retry-After"] = str(rate_limit_result["retry_after"])
                return response

            # Add rate limit headers to response
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(
                rate_limit_result["max_requests"]
            )
            response.headers["X-RateLimit-Remaining"] = str(
                rate_limit_result["max_requests"]
                - rate_limit_result["current_requests"]
            )
            response.headers["X-RateLimit-Reset"] = str(rate_limit_result["reset_time"])

            return response

        except redis.exceptions.ConnectionError:
            # If Redis is unavailable, allow the request but log it
            print("Redis connection failed - rate limiting disabled")
            return await call_next(request)
        except Exception as e:
            print(f"Rate limiting error: {e}")
            return await call_next(request)

    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check for X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(",")[0].strip()

        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to client IP
        return request.client.host if request.client else "unknown"


class RateLimitHeaders:
    """Helper class for rate limit headers"""

    @staticmethod
    def add_rate_limit_headers(response: Response, rate_limit_result: dict[str, Any]):
        """Add rate limit headers to response"""
        response.headers["X-RateLimit-Limit"] = str(rate_limit_result["max_requests"])
        response.headers["X-RateLimit-Remaining"] = str(
            rate_limit_result["max_requests"] - rate_limit_result["current_requests"]
        )
        response.headers["X-RateLimit-Reset"] = str(rate_limit_result["reset_time"])

        if rate_limit_result["limited"]:
            response.headers["Retry-After"] = str(rate_limit_result["retry_after"])
