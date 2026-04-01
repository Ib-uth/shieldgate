"""Integration tests use the same JWT keys as the live gateway (CI-generated keys)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

try:
    import redis as redis_sync
except ImportError:
    redis_sync = None  # type: ignore[misc, assignment]

from apps.gateway.utils.jwt_utils import JWTManager


@pytest.fixture(scope="session")
def jwt_manager() -> JWTManager:
    """Load keys from the environment paths used when uvicorn was started."""
    priv = os.environ.get("JWT_PRIVATE_KEY_PATH", "keys/private.pem")
    pub = os.environ.get("JWT_PUBLIC_KEY_PATH", "keys/public.pem")
    if not Path(priv).is_file() or not Path(pub).is_file():
        pytest.skip(
            "JWT key files not found (expected keys/private.pem for integration)"
        )
    manager = JWTManager(priv, pub)
    if not manager.load_keys():
        pytest.fail("Could not load JWT keys for integration tests")
    return manager


@pytest.fixture(scope="session")
def test_env_vars():
    """Avoid overriding JWT/DB in the pytest process; the gateway already started with CI env."""
    yield {}


@pytest.fixture
def clear_rate_limit_keys() -> None:
    """Delete gateway rate-limit keys in Redis (same REDIS_URL as uvicorn).

    Safe only for CI / local / dedicated staging Redis — never against production.
    """
    if redis_sync is None:
        pytest.skip("redis package not installed (pip install redis)")
    url = os.environ.get("REDIS_URL")
    if not url:
        pytest.skip("REDIS_URL is not set (required to reset rate limits)")
    client = redis_sync.Redis.from_url(url, decode_responses=True)
    try:
        for key in client.scan_iter(match="rate_limit:*"):
            client.delete(key)
    finally:
        client.close()
