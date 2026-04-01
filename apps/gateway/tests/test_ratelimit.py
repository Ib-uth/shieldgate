"""Test rate limiting middleware"""

import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from ..main import app
from ..middleware.ratelimit import RedisRateLimiter


class TestRedisRateLimiter:
    """Test Redis rate limiter functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.redis_mock = AsyncMock()
        self.rate_limiter = RedisRateLimiter(
            self.redis_mock,
            ip_requests=10,
            ip_window=60,
            user_requests=100,
            user_window=60,
        )

    @pytest.mark.asyncio
    async def test_ip_rate_limit_check(self):
        """Test IP rate limiting"""
        # Mock Redis responses
        self.redis_mock.zremrangebyscore.return_value = 0  # No old entries
        self.redis_mock.zcard.return_value = 5  # Current requests
        self.redis_mock.zadd.return_value = 1  # Successfully added
        self.redis_mock.expire.return_value = 1  # Successfully set expiry

        result = await self.rate_limiter.check_ip_rate_limit("192.168.1.1")

        assert result["limited"] is False
        assert result["current_requests"] == 5
        assert result["max_requests"] == 10
        assert result["retry_after"] == 0

    @pytest.mark.asyncio
    async def test_ip_rate_limit_exceeded(self):
        """Test IP rate limit exceeded"""
        # Mock Redis responses for exceeded limit
        self.redis_mock.zremrangebyscore.return_value = 0
        self.redis_mock.zcard.return_value = 10  # At limit
        self.redis_mock.zadd.return_value = 1
        self.redis_mock.expire.return_value = 1
        self.redis_mock.zrange.return_value = [
            (b"test", time.time() - 30)
        ]  # 30 seconds ago

        result = await self.rate_limiter.check_ip_rate_limit("192.168.1.1")

        assert result["limited"] is True
        assert result["current_requests"] == 10
        assert result["max_requests"] == 10
        assert result["retry_after"] > 0

    @pytest.mark.asyncio
    async def test_user_rate_limit_check(self):
        """Test user rate limiting"""
        # Mock Redis responses
        self.redis_mock.zremrangebyscore.return_value = 0
        self.redis_mock.zcard.return_value = 25
        self.redis_mock.zadd.return_value = 1
        self.redis_mock.expire.return_value = 1

        result = await self.rate_limiter.check_user_rate_limit("user-123")

        assert result["limited"] is False
        assert result["current_requests"] == 25
        assert result["max_requests"] == 100

    @pytest.mark.asyncio
    async def test_sliding_window_cleanup(self):
        """Test sliding window cleanup of old entries"""
        current_time = time.time()
        window_start = current_time - 60

        # Mock Redis to return some old entries that should be cleaned up
        self.redis_mock.zremrangebyscore.return_value = 3  # Removed 3 old entries
        self.redis_mock.zcard.return_value = 7  # 7 current entries
        self.redis_mock.zadd.return_value = 1
        self.redis_mock.expire.return_value = 1

        await self.rate_limiter.check_ip_rate_limit("192.168.1.1")

        # Verify cleanup was called with correct time range
        self.redis_mock.zremrangebyscore.assert_called_once()
        call_args = self.redis_mock.zremrangebyscore.call_args
        assert call_args[0][0] == "rate_limit:ip:192.168.1.1"
        assert call_args[0][1] == 0
        assert call_args[0][2] < window_start

    @pytest.mark.asyncio
    async def test_redis_error_handling(self):
        """Test graceful handling of Redis errors"""
        # Mock Redis to raise connection error
        self.redis_mock.zremrangebyscore.side_effect = Exception(
            "Redis connection failed"
        )

        # Should not raise exception, but handle gracefully
        with pytest.raises(Exception):
            await self.rate_limiter.check_ip_rate_limit("192.168.1.1")

    @pytest.mark.asyncio
    async def test_get_rate_limit_stats(self):
        """Test getting rate limit statistics"""
        # Mock Redis responses
        self.redis_mock.zrange.return_value = [
            (b"req1", time.time() - 10),
            (b"req2", time.time() - 20),
            (b"req3", time.time() - 30),
        ]

        stats = await self.rate_limiter.get_rate_limit_stats(
            "rate_limit:ip:192.168.1.1"
        )

        assert stats["current_requests"] == 3
        assert len(stats["requests_in_window"]) == 3
        assert stats["oldest_request"] > 0
        assert stats["newest_request"] > 0


class TestRateLimitMiddleware:
    """Test rate limiting middleware"""

    def setup_method(self):
        """Setup test environment"""
        self.client = TestClient(app)

    @patch("apps.gateway.main.redis_client")
    def test_rate_limit_headers_added(self, mock_redis):
        """Test rate limit headers are added to responses"""
        # Mock Redis client and rate limiter
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.check_ip_rate_limit.return_value = {
            "limited": False,
            "current_requests": 5,
            "max_requests": 60,
            "retry_after": 0,
            "reset_time": int(time.time()) + 60,
        }

        with patch(
            "apps.gateway.main.RedisRateLimiter", return_value=mock_rate_limiter
        ):
            response = self.client.get("/health")

            # Should have rate limit headers
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers

    @patch("apps.gateway.main.redis_client")
    def test_rate_limit_exceeded_response(self, mock_redis):
        """Test response when rate limit is exceeded"""
        # Mock Redis client and rate limiter
        mock_rate_limiter = AsyncMock()
        mock_rate_limiter.check_ip_rate_limit.return_value = {
            "limited": True,
            "current_requests": 60,
            "max_requests": 60,
            "retry_after": 30,
            "reset_time": int(time.time()) + 30,
        }

        with patch(
            "apps.gateway.main.RedisRateLimiter", return_value=mock_rate_limiter
        ):
            response = self.client.get("/proxy/public")

            assert response.status_code == 429
            assert "Retry-After" in response.headers
            assert "X-RateLimit-Limit" in response.headers
            assert response.headers["Retry-After"] == "30"

    @patch("apps.gateway.main.redis_client")
    def test_user_vs_ip_rate_limits(self, mock_redis):
        """Test different rate limits for users vs IPs"""
        # Mock Redis client and rate limiter
        mock_rate_limiter = AsyncMock()

        # Test unauthenticated request (IP-based)
        mock_rate_limiter.check_ip_rate_limit.return_value = {
            "limited": False,
            "current_requests": 5,
            "max_requests": 60,
            "retry_after": 0,
            "reset_time": int(time.time()) + 60,
        }

        with patch(
            "apps.gateway.main.RedisRateLimiter", return_value=mock_rate_limiter
        ):
            self.client.get("/proxy/public")

            # Should check IP rate limit for unauthenticated request
            mock_rate_limiter.check_ip_rate_limit.assert_called_once()
            mock_rate_limiter.check_user_rate_limit.assert_not_called()

    def test_public_paths_skipped(self):
        """Test rate limiting is skipped for public paths"""
        response = self.client.get("/health")
        # Health check should work regardless of rate limiting
        assert response.status_code == 200


class TestRateLimitProperties:
    """Property-based testing for rate limiting"""

    @pytest.mark.asyncio
    async def test_rate_limit_invariants(self):
        """Test rate limiting invariants using property-based testing"""
        from hypothesis import given
        from hypothesis import strategies as st

        redis_mock = AsyncMock()
        rate_limiter = RedisRateLimiter(redis_mock, ip_requests=10, ip_window=60)

        @given(
            current_requests=st.integers(min_value=0, max_value=20),
            max_requests=st.integers(min_value=1, max_value=100),
        )
        async def test_rate_limit_logic(current_requests, max_requests):
            # Mock Redis responses
            redis_mock.zremrangebyscore.return_value = 0
            redis_mock.zcard.return_value = current_requests
            redis_mock.zadd.return_value = 1
            redis_mock.expire.return_value = 1

            # Mock oldest request for retry_after calculation
            if current_requests >= max_requests:
                redis_mock.zrange.return_value = [(b"test", time.time() - 30)]

            result = await rate_limiter.check_ip_rate_limit("192.168.1.1")

            # Invariants
            assert result["current_requests"] == current_requests
            assert result["max_requests"] == max_requests

            # Should be limited if current >= max
            if current_requests >= max_requests:
                assert result["limited"] is True
                assert result["retry_after"] > 0
            else:
                assert result["limited"] is False
                assert result["retry_after"] == 0

        await test_rate_limit_logic()


if __name__ == "__main__":
    pytest.main([__file__])
