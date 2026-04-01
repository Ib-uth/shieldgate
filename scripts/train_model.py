#!/usr/bin/env python3
"""Script to train threat detection model"""

import os
import sys
import argparse
from pathlib import Path

# Add the apps directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'apps', 'gateway'))

from utils.ml_utils import generate_synthetic_training_data, train_threat_detection_model


def main():
    parser = argparse.ArgumentParser(description="Train threat detection model")
    parser.add_argument(
        "--output", 
        default="./models/threat_model.joblib",
        help="Output path for trained model"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10000,
        help="Number of synthetic training samples"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible results"
    )
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"Training threat detection model...")
    print(f"Output path: {args.output}")
    print(f"Training samples: {args.samples}")
    print(f"Random seed: {args.seed}")
    
    # Generate synthetic training data
    print("Generating synthetic training data...")
    training_data = generate_synthetic_training_data(args.samples)
    
    # Train model
    print("Training model...")
    model = train_threat_detection_model(training_data, args.output)
    
    print("Model training complete!")
    print(f"Model saved to: {args.output}")
    
    # Test model with sample data
    print("\nTesting model with sample requests...")
    
    test_requests = [
        {
            "ip_request_count": 1,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": "2024-01-01T10:00:00",
            "path": "/public",
            "request_size": 500,
            "headers": {"host": "example.com", "user-agent": "Mozilla/5.0"}
        },
        {
            "ip_request_count": 50,
            "user_agent": "bot/1.0 suspicious-agent-string",
            "timestamp": "2024-01-01T03:00:00",
            "path": "/admin",
            "request_size": 50000,
            "headers": {f"header-{i}": "value" for i in range(25)}
        }
    ]
    
    for i, test_request in enumerate(test_requests, 1):
        threat_score = model.predict_threat_score(test_request)
        is_threat = model.is_threat(threat_score)
        should_block = model.should_block(threat_score)
        
        print(f"\nTest Request {i}:")
        print(f"  Threat Score: {threat_score:.3f}")
        print(f"  Is Threat: {is_threat}")
        print(f"  Should Block: {should_block}")
        print(f"  Path: {test_request['path']}")
        print(f"  IP Requests: {test_request['ip_request_count']}")


if __name__ == "__main__":
    main()
