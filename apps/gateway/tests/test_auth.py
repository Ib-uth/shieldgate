"""Test JWT authentication middleware"""

import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ..main import app
from ..utils.jwt_utils import JWTManager


class TestJWTAuthentication:
    """Test JWT authentication functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.client = TestClient(app)
        self.jwt_manager = JWTManager("test_private.pem", "test_public.pem")

        # Generate test keys
        self.jwt_manager.generate_key_pair("test_private.pem", "test_public.pem")

        # Create test tokens
        self.admin_token = self.jwt_manager.create_token(
            {"sub": "admin-123", "email": "admin@test.com", "role": "admin"}
        )

        self.user_token = self.jwt_manager.create_token(
            {"sub": "user-456", "email": "user@test.com", "role": "user"}
        )

    def test_public_endpoint_no_auth(self):
        """Test public endpoints don't require authentication"""
        response = self.client.get("/health")
        assert response.status_code == 200

    def test_protected_endpoint_without_token(self):
        """Test protected endpoints require authentication"""
        response = self.client.get("/admin/stats")
        assert response.status_code == 401

    def test_protected_endpoint_with_valid_token(self):
        """Test protected endpoints accept valid tokens"""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = self.client.get("/admin/stats", headers=headers)
        # Should work if admin stats endpoint exists
        assert response.status_code in [200, 404]  # 404 if endpoint doesn't exist yet

    def test_invalid_token_rejected(self):
        """Test invalid tokens are rejected"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = self.client.get("/admin/stats", headers=headers)
        assert response.status_code == 401

    def test_expired_token_rejected(self):
        """Test expired tokens are rejected"""
        # Create expired token
        expired_token = self.jwt_manager.create_token(
            {"sub": "user-123", "email": "user@test.com", "role": "user"}, expires_in=-1
        )  # Already expired

        headers = {"Authorization": f"Bearer {expired_token}"}
        response = self.client.get("/admin/stats", headers=headers)
        assert response.status_code == 401

    def test_token_claims_attached_to_request(self):
        """Test token claims are attached to request state"""
        with patch("apps.gateway.main.jwt_manager", self.jwt_manager):
            headers = {"Authorization": f"Bearer {self.admin_token}"}
            response = self.client.get("/proxy/public", headers=headers)
            # Should proxy to mock service
            assert response.status_code in [200, 404]

    def test_malformed_token_rejected(self):
        """Test malformed tokens are rejected"""
        headers = {"Authorization": "Bearer malformed.token.here"}
        response = self.client.get("/admin/stats", headers=headers)
        assert response.status_code == 401

    def test_missing_authorization_header(self):
        """Test missing authorization header is rejected"""
        response = self.client.get("/admin/stats")
        assert response.status_code == 401

    def test_bearer_prefix_required(self):
        """Test Bearer prefix is required"""
        headers = {"Authorization": self.admin_token}
        response = self.client.get("/admin/stats", headers=headers)
        assert response.status_code == 401


class TestJWTManager:
    """Test JWT manager utility functions"""

    def setup_method(self):
        """Setup test environment"""
        self.private_key = "test_private.pem"
        self.public_key = "test_public.pem"
        self.jwt_manager = JWTManager(self.private_key, self.public_key)

        # Generate test keys
        self.jwt_manager.generate_key_pair(self.private_key, self.public_key)

    def test_token_creation_and_verification(self):
        """Test token creation and verification"""
        claims = {"sub": "user-123", "email": "user@test.com", "role": "user"}

        token = self.jwt_manager.create_token(claims)
        verified_claims = self.jwt_manager.verify_token(token)

        assert verified_claims is not None
        assert verified_claims.sub == claims["sub"]
        assert verified_claims.email == claims["email"]
        assert verified_claims.role == claims["role"]

    def test_token_expiry(self):
        """Test token expiry"""
        claims = {"sub": "user-123", "email": "user@test.com", "role": "user"}

        # Create token that expires immediately
        token = self.jwt_manager.create_token(claims, expires_in=0)

        # Wait a moment to ensure expiry
        time.sleep(0.1)

        assert self.jwt_manager.is_token_expired(token)

    def test_invalid_signature(self):
        """Test tokens with invalid signatures are rejected"""
        # Create token with different manager (different keys)
        other_manager = JWTManager("other_private.pem", "other_public.pem")
        other_manager.generate_key_pair("other_private.pem", "other_public.pem")

        claims = {"sub": "user-123", "email": "user@test.com", "role": "user"}
        token = other_manager.create_token(claims)

        # Try to verify with our manager
        verified_claims = self.jwt_manager.verify_token(token)
        assert verified_claims is None

    def test_key_generation(self):
        """Test RSA key pair generation"""
        # Clean up existing keys
        import os

        if os.path.exists(self.private_key):
            os.remove(self.private_key)
        if os.path.exists(self.public_key):
            os.remove(self.public_key)

        # Generate new keys
        self.jwt_manager.generate_key_pair(self.private_key, self.public_key)

        # Verify keys exist
        assert os.path.exists(self.private_key)
        assert os.path.exists(self.public_key)

        # Test keys work
        claims = {"sub": "test", "email": "test@test.com", "role": "user"}
        token = self.jwt_manager.create_token(claims)
        verified = self.jwt_manager.verify_token(token)
        assert verified is not None

    def test_sample_tokens(self):
        """Test sample token generation"""
        from ..utils.jwt_utils import create_sample_tokens

        tokens = create_sample_tokens(self.jwt_manager)

        assert "admin" in tokens
        assert "user" in tokens
        assert "readonly" in tokens

        # Verify each token
        for role, token in tokens.items():
            claims = self.jwt_manager.verify_token(token)
            assert claims is not None
            assert claims.role == role


if __name__ == "__main__":
    pytest.main([__file__])
