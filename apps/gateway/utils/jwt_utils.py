"""JWT utilities for RS256 token handling"""

import os
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from ..models.schemas import UserClaims


class JWTManager:
    """Manages JWT token creation and validation with RS256"""

    def __init__(self, private_key_path: str, public_key_path: str):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self._private_key = None
        self._public_key = None
        self.algorithm = "RS256"

    def _load_keys(self) -> None:
        """Load RSA keys from files"""
        if not os.path.exists(self.private_key_path):
            raise FileNotFoundError(f"Private key not found: {self.private_key_path}")
        if not os.path.exists(self.public_key_path):
            raise FileNotFoundError(f"Public key not found: {self.public_key_path}")

        with open(self.private_key_path, "rb") as f:
            self._private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        with open(self.public_key_path, "rb") as f:
            self._public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    @property
    def private_key(self):
        if self._private_key is None:
            self._load_keys()
        return self._private_key

    @property
    def public_key(self):
        if self._public_key is None:
            self._load_keys()
        return self._public_key

    def create_token(self, user_claims: Dict[str, Any], expires_in: int = 3600) -> str:
        """Create a JWT token with user claims"""
        now = int(time.time())
        expires_at = now + expires_in

        # Add standard claims
        payload = {"iat": now, "exp": expires_at, **user_claims}

        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def verify_token(self, token: str) -> Optional[UserClaims]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
            return UserClaims(**payload)
        except JWTError as e:
            print(f"JWT verification failed: {e}")
            return None

    def is_token_expired(self, token: str) -> bool:
        """Check if token is expired"""
        try:
            payload = jwt.decode(token, self.public_key, algorithms=[self.algorithm])
            exp = payload.get("exp")
            if exp is None:
                return True
            return exp < int(time.time())
        except JWTError:
            return True

    @staticmethod
    def generate_key_pair(private_key_path: str, public_key_path: str) -> None:
        """Generate RSA key pair for JWT signing"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write keys to files
        os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
        os.makedirs(os.path.dirname(public_key_path), exist_ok=True)

        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        print("Generated RSA key pair:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key: {public_key_path}")


def create_sample_tokens(jwt_manager: JWTManager) -> Dict[str, str]:
    """Create sample tokens for testing different roles"""
    tokens = {}

    # Admin token
    admin_claims = {
        "sub": "admin-123",
        "email": "admin@shieldgate.dev",
        "role": "admin",
    }
    tokens["admin"] = jwt_manager.create_token(admin_claims)

    # User token
    user_claims = {"sub": "user-456", "email": "user@shieldgate.dev", "role": "user"}
    tokens["user"] = jwt_manager.create_token(user_claims)

    # Readonly token
    readonly_claims = {
        "sub": "readonly-789",
        "email": "readonly@shieldgate.dev",
        "role": "readonly",
    }
    tokens["readonly"] = jwt_manager.create_token(readonly_claims)

    return tokens
