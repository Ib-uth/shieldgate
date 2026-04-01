#!/usr/bin/env python3
"""Script to generate RSA key pair for JWT signing"""

import os
import sys
import argparse
from pathlib import Path

# Add the apps directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'apps', 'gateway'))

from utils.jwt_utils import JWTManager


def main():
    parser = argparse.ArgumentParser(description="Generate RSA key pair for JWT signing")
    parser.add_argument(
        "--private-key",
        default="./keys/private.pem",
        help="Path for private key file"
    )
    parser.add_argument(
        "--public-key",
        default="./keys/public.pem", 
        help="Path for public key file"
    )
    
    args = parser.parse_args()
    
    # Create directories if they don't exist
    private_key_path = Path(args.private_key)
    public_key_path = Path(args.public_key)
    
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    
    print("Generating RSA key pair for JWT signing...")
    print(f"Private key: {args.private_key}")
    print(f"Public key: {args.public_key}")
    
    # Generate key pair
    JWTManager.generate_key_pair(args.private_key, args.public_key)
    
    # Test the keys
    print("\nTesting key pair...")
    try:
        jwt_manager = JWTManager(args.private_key, args.public_key)
        
        # Test token creation and verification
        test_claims = {
            "sub": "test-user",
            "email": "test@example.com",
            "role": "user"
        }
        
        token = jwt_manager.create_token(test_claims)
        verified_claims = jwt_manager.verify_token(token)
        
        if verified_claims and verified_claims.sub == test_claims["sub"]:
            print("✓ Key pair test successful!")
            print(f"✓ Sample token: {token[:50]}...")
        else:
            print("✗ Key pair test failed!")
            sys.exit(1)
            
    except Exception as e:
        print(f"✗ Key pair test failed: {e}")
        sys.exit(1)
    
    print("\nKey pair generation complete!")
    print("\nEnvironment variables to set:")
    print(f"JWT_PRIVATE_KEY_PATH={args.private_key}")
    print(f"JWT_PUBLIC_KEY_PATH={args.public_key}")
    
    # Generate sample tokens for testing
    print("\nGenerating sample tokens...")
    from utils.jwt_utils import create_sample_tokens
    
    sample_tokens = create_sample_tokens(jwt_manager)
    
    print("\nSample JWT tokens (for testing):")
    print(f"Admin token: {sample_tokens['admin']}")
    print(f"User token: {sample_tokens['user']}")
    print(f"Readonly token: {sample_tokens['readonly']}")
    
    print("\nUsage examples:")
    print("# Test with curl:")
    print(f"curl -H 'Authorization: Bearer {sample_tokens['user']}' http://localhost:8000/user")
    print(f"curl -H 'Authorization: Bearer {sample_tokens['admin']}' http://localhost:8000/admin")


if __name__ == "__main__":
    main()
