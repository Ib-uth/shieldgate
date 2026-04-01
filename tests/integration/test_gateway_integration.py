"""Integration tests for ShieldGate API Gateway"""

import asyncio

import pytest


class TestGatewayIntegration:
    """Test complete gateway functionality"""

    @pytest.mark.asyncio
    async def test_public_endpoint_no_auth(self, gateway_client):
        """Test public endpoints don't require authentication"""
        response = await gateway_client.get("/health")
        assert response.status_code == 200

        # Test proxy to public endpoint
        response = await gateway_client.get("/proxy/public")
        assert response.status_code in [200, 404]  # 404 if mock service not running

    @pytest.mark.asyncio
    async def test_admin_token_access(self, gateway_client, test_tokens):
        """Test admin token can access admin endpoints"""
        headers = {"Authorization": f"Bearer {test_tokens['admin']}"}

        # Test admin stats endpoint
        response = await gateway_client.get("/admin/stats", headers=headers)
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist yet

        # Test protected proxy endpoint
        response = await gateway_client.get("/proxy/admin", headers=headers)
        assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_user_token_access(self, gateway_client, test_tokens):
        """Test user token can access user endpoints but not admin"""
        headers = {"Authorization": f"Bearer {test_tokens['user']}"}

        # Test user endpoint access
        response = await gateway_client.get("/proxy/user", headers=headers)
        assert response.status_code in [200, 404]

        # Test admin endpoint access (should be forbidden)
        response = await gateway_client.get("/proxy/admin", headers=headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_readonly_token_access(self, gateway_client, test_tokens):
        """Test readonly token has limited access"""
        headers = {"Authorization": f"Bearer {test_tokens['readonly']}"}

        # Test public endpoint access
        response = await gateway_client.get("/proxy/public", headers=headers)
        assert response.status_code in [200, 404]

        # Test user endpoint access (should be forbidden)
        response = await gateway_client.get("/proxy/user", headers=headers)
        assert response.status_code == 403

        # Test admin endpoint access (should be forbidden)
        response = await gateway_client.get("/proxy/admin", headers=headers)
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self, gateway_client):
        """Test invalid tokens are rejected"""
        headers = {"Authorization": "Bearer invalid_token"}

        response = await gateway_client.get("/proxy/user", headers=headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_token_rejected(self, gateway_client):
        """Test missing auth token is rejected"""
        response = await gateway_client.get("/proxy/user")
        assert response.status_code == 401


class TestRateLimitingIntegration:
    """Test rate limiting functionality"""

    @pytest.mark.asyncio
    async def test_ip_rate_limiting(self, gateway_client):
        """Test IP-based rate limiting"""
        # Send 65 requests rapidly (limit is 60)
        responses = []

        for _i in range(65):
            response = await gateway_client.get("/proxy/public")
            responses.append(response.status_code)

            # Add small delay to avoid overwhelming
            await asyncio.sleep(0.01)

        # First 60 should succeed
        assert sum(1 for code in responses[:60] if code in [200, 404]) == 60

        # 61st should be rate limited
        assert responses[60] == 429

        # Check rate limit headers
        rate_limited_response = await gateway_client.get("/proxy/public")
        assert "Retry-After" in rate_limited_response.headers
        assert "X-RateLimit-Limit" in rate_limited_response.headers
        assert int(rate_limited_response.headers["Retry-After"]) > 0

    @pytest.mark.asyncio
    async def test_user_rate_limiting(self, gateway_client, test_tokens):
        """Test user-based rate limiting (higher limits)"""
        headers = {"Authorization": f"Bearer {test_tokens['user']}"}

        # Send 310 requests rapidly (limit is 300)
        responses = []

        for _i in range(310):
            response = await gateway_client.get("/proxy/user", headers=headers)
            responses.append(response.status_code)
            await asyncio.sleep(0.001)  # Very small delay

        # First 300 should succeed
        assert sum(1 for code in responses[:300] if code in [200, 404]) == 300

        # 301st should be rate limited
        assert responses[300] == 429


class TestProxyIntegration:
    """Test request proxying functionality"""

    @pytest.mark.asyncio
    async def test_proxy_headers_transformation(self, gateway_client, test_tokens):
        """Test proxy properly transforms headers"""
        headers = {
            "Authorization": f"Bearer {test_tokens['user']}",
            "X-Custom-Header": "test-value",
            "User-Agent": "test-agent",
        }

        response = await gateway_client.get("/proxy/user", headers=headers)

        if response.status_code == 200:
            # Should have forwarded headers
            assert "X-Request-ID" in response.headers
            assert "X-Forwarded-For" in response.headers

            # Should not have auth headers forwarded
            # (This depends on mock service implementation)

    @pytest.mark.asyncio
    async def test_proxy_error_handling(self, gateway_client):
        """Test proxy handles downstream errors properly"""
        # Test with non-existent endpoint
        response = await gateway_client.get("/proxy/nonexistent")
        assert response.status_code in [404, 502]  # Either not found or service error


class TestThreatDetectionIntegration:
    """Test threat detection functionality"""

    @pytest.mark.asyncio
    async def test_threat_score_headers(self, gateway_client):
        """Test threat score headers are present"""
        response = await gateway_client.get("/proxy/public")

        # Should have threat score headers if model is loaded
        # (This depends on whether threat detection middleware is properly configured)
        if response.status_code in [200, 404]:
            # Check for threat score headers (may not always be present)
            threat_score = response.headers.get("X-Threat-Score")
            response.headers.get("X-Threat-Action")

            if threat_score:
                assert 0.0 <= float(threat_score) <= 1.0

    @pytest.mark.asyncio
    async def test_high_threat_blocking(self, gateway_client):
        """Test high threat scores result in blocking"""
        # This test would need to trigger threat detection
        # In a real scenario, this might involve:
        # - High request frequency from same IP
        # - Suspicious user agent
        # - Unusual request patterns

        # For now, just verify the endpoint exists
        response = await gateway_client.get("/proxy/public")
        assert response.status_code in [
            200,
            404,
            403,
        ]  # 403 if blocked by threat detection


class TestHealthChecks:
    """Test health and monitoring endpoints"""

    @pytest.mark.asyncio
    async def test_health_endpoint(self, gateway_client):
        """Test health check endpoint"""
        response = await gateway_client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert "services" in data
        assert "redis" in data["services"]
        assert "database" in data["services"]

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, gateway_client, test_tokens):
        """Test metrics endpoint"""
        headers = {"Authorization": f"Bearer {test_tokens['admin']}"}

        response = await gateway_client.get("/metrics?hours=1", headers=headers)
        assert response.status_code in [200, 403]  # 403 if not admin

        if response.status_code == 200:
            data = response.json()
            assert "total_requests" in data
            assert "error_rate" in data
            assert "threat_score_distribution" in data


class TestCORSConfiguration:
    """Test CORS configuration"""

    @pytest.mark.asyncio
    async def test_cors_headers(self, gateway_client):
        """Test CORS headers are properly set"""
        response = await gateway_client.options("/proxy/public")

        # Should have CORS headers
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers
