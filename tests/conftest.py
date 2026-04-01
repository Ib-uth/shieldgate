"""Pytest configuration and fixtures for integration tests"""

import asyncio
import os
import pytest
import tempfile
from pathlib import Path

from apps.gateway.utils.jwt_utils import JWTManager
from apps.gateway.utils.ml_utils import generate_synthetic_training_data, train_threat_detection_model


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def temp_dirs():
    """Create temporary directories for test files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        keys_dir = Path(temp_dir) / "keys"
        models_dir = Path(temp_dir) / "models"
        keys_dir.mkdir()
        models_dir.mkdir()
        yield str(keys_dir), str(models_dir)


@pytest.fixture(scope="session")
def jwt_manager(temp_dirs):
    """Create JWT manager with test keys"""
    keys_dir, _ = temp_dirs
    private_key = Path(keys_dir) / "test_private.pem"
    public_key = Path(keys_dir) / "test_public.pem"
    
    # Generate test keys
    manager = JWTManager(str(private_key), str(public_key))
    manager.generate_key_pair(str(private_key), str(public_key))
    
    yield manager


@pytest.fixture(scope="session")
def test_tokens(jwt_manager):
    """Generate test tokens for different roles"""
    tokens = {}
    
    # Admin token
    tokens["admin"] = jwt_manager.create_token({
        "sub": "admin-test-123",
        "email": "admin@test.com",
        "role": "admin"
    })
    
    # User token
    tokens["user"] = jwt_manager.create_token({
        "sub": "user-test-456",
        "email": "user@test.com", 
        "role": "user"
    })
    
    # Readonly token
    tokens["readonly"] = jwt_manager.create_token({
        "sub": "readonly-test-789",
        "email": "readonly@test.com",
        "role": "readonly"
    })
    
    return tokens


@pytest.fixture(scope="session")
def threat_model(temp_dirs):
    """Create and train a threat detection model for testing"""
    _, models_dir = temp_dirs
    model_path = Path(models_dir) / "test_threat_model.joblib"
    
    # Generate small training dataset
    training_data = generate_synthetic_training_data(100)
    
    # Train model
    model = train_threat_detection_model(training_data, str(model_path))
    
    yield str(model_path)


@pytest.fixture(scope="session")
def test_env_vars(temp_dirs, threat_model):
    """Set up test environment variables"""
    keys_dir, _ = temp_dirs
    
    env_vars = {
        "DATABASE_URL": "sqlite:///./test.db",
        "REDIS_URL": "redis://localhost:6379",
        "JWT_PRIVATE_KEY_PATH": f"{keys_dir}/test_private.pem",
        "JWT_PUBLIC_KEY_PATH": f"{keys_dir}/test_public.pem",
        "THREAT_MODEL_PATH": threat_model,
        "DOWNSTREAM_URL": "http://localhost:8001",
        "RATE_LIMIT_IP_REQUESTS": "60",
        "RATE_LIMIT_IP_WINDOW": "60",
        "RATE_LIMIT_USER_REQUESTS": "300",
        "RATE_LIMIT_USER_WINDOW": "60",
        "THREAT_SCORE_FLAG_THRESHOLD": "0.7",
        "THREAT_SCORE_BLOCK_THRESHOLD": "0.9",
        "ALLOWED_ORIGINS": "http://localhost:3000"
    }
    
    # Set environment variables
    for key, value in env_vars.items():
        os.environ[key] = value
    
    yield env_vars
    
    # Clean up environment variables
    for key in env_vars:
        os.environ.pop(key, None)


@pytest.fixture
async def gateway_client(test_env_vars):
    """Create HTTP client for gateway testing"""
    import httpx
    
    async with httpx.AsyncClient(
        base_url="http://localhost:8000",
        timeout=30.0
    ) as client:
        yield client


@pytest.fixture
async def mock_service_client():
    """Create HTTP client for mock service testing"""
    import httpx
    
    async with httpx.AsyncClient(
        base_url="http://localhost:8001",
        timeout=30.0
    ) as client:
        yield client
