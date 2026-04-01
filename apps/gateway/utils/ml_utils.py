"""ML utilities for threat detection"""

import math
import numpy as np
import joblib
from typing import Dict, Any, List, Optional
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from ..models.schemas import ThreatFeatures


class ThreatDetectionModel:
    """ML-based threat detection using Isolation Forest"""
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_names = [
            "ip_request_count",
            "user_agent_entropy", 
            "hour_of_day",
            "endpoint_category_numeric",
            "request_size",
            "header_count"
        ]
        self.endpoint_categories = {
            "public": 0,
            "user": 1,
            "admin": 2,
            "health": 3,
            "metrics": 4,
            "unknown": 5
        }
    
    def load_model(self) -> bool:
        """Load pre-trained model from file"""
        try:
            if self.model_path:
                model_data = joblib.load(self.model_path)
                self.model = model_data["model"]
                self.scaler = model_data["scaler"]
                return True
            return False
        except Exception as e:
            print(f"Failed to load model: {e}")
            return False
    
    def save_model(self, model_path: str):
        """Save trained model to file"""
        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "endpoint_categories": self.endpoint_categories
        }
        joblib.dump(model_data, model_path)
    
    def extract_features(self, request_data: Dict[str, Any]) -> ThreatFeatures:
        """Extract features from request data"""
        # IP request count (how many requests from this IP recently)
        ip_request_count = request_data.get("ip_request_count", 1)
        
        # User agent entropy
        user_agent = request_data.get("user_agent", "")
        user_agent_entropy = self.calculate_entropy(user_agent)
        
        # Hour of day
        timestamp = request_data.get("timestamp", datetime.utcnow())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        hour_of_day = timestamp.hour
        
        # Endpoint category
        path = request_data.get("path", "")
        endpoint_category = self.categorize_endpoint(path)
        
        # Request size
        request_size = request_data.get("request_size", 0)
        
        # Header count
        headers = request_data.get("headers", {})
        header_count = len(headers)
        
        return ThreatFeatures(
            ip_request_count=ip_request_count,
            user_agent_entropy=user_agent_entropy,
            hour_of_day=hour_of_day,
            endpoint_category=endpoint_category,
            request_size=request_size,
            header_count=header_count
        )
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def categorize_endpoint(self, path: str) -> str:
        """Categorize endpoint path"""
        path_lower = path.lower()
        
        if "/public" in path_lower or path_lower == "/":
            return "public"
        elif "/user" in path_lower:
            return "user"
        elif "/admin" in path_lower:
            return "admin"
        elif "/health" in path_lower:
            return "health"
        elif "/metrics" in path_lower:
            return "metrics"
        else:
            return "unknown"
    
    def prepare_features(self, features: ThreatFeatures) -> np.ndarray:
        """Prepare features for model prediction"""
        # Convert endpoint category to numeric
        endpoint_numeric = self.endpoint_categories.get(
            features.endpoint_category, 
            self.endpoint_categories["unknown"]
        )
        
        # Create feature array
        feature_array = np.array([
            features.ip_request_count,
            features.user_agent_entropy,
            features.hour_of_day,
            endpoint_numeric,
            features.request_size,
            features.header_count
        ]).reshape(1, -1)
        
        # Scale features
        if self.scaler:
            feature_array = self.scaler.transform(feature_array)
        
        return feature_array
    
    def predict_threat_score(self, request_data: Dict[str, Any]) -> float:
        """Predict threat score for request"""
        if self.model is None:
            return 0.0  # No threat if model not loaded
        
        # Extract features
        features = self.extract_features(request_data)
        
        # Prepare features
        feature_array = self.prepare_features(features)
        
        # Predict anomaly score (lower = more anomalous)
        anomaly_score = self.model.decision_function(feature_array)[0]
        
        # Convert to threat score (0-1, higher = more threatening)
        # Isolation Forest returns negative scores for anomalies
        threat_score = max(0.0, min(1.0, (0.5 - anomaly_score) * 2))
        
        return threat_score
    
    def is_threat(self, threat_score: float, threshold: float = 0.7) -> bool:
        """Check if threat score indicates a threat"""
        return threat_score >= threshold
    
    def should_block(self, threat_score: float, block_threshold: float = 0.9) -> bool:
        """Check if request should be blocked based on threat score"""
        return threat_score >= block_threshold


def generate_synthetic_training_data(n_samples: int = 10000) -> List[Dict[str, Any]]:
    """Generate synthetic training data for threat detection"""
    np.random.seed(42)  # For reproducible results
    
    data = []
    
    for i in range(n_samples):
        # Generate normal traffic patterns
        ip_request_count = np.random.poisson(2)  # Most IPs make few requests
        user_agent_entropy = np.random.normal(3.5, 0.8)  # Normal user agents
        hour_of_day = np.random.randint(0, 24)  # All hours
        endpoint_categories = ["public", "user", "admin", "health", "metrics"]
        endpoint_category = np.random.choice(endpoint_categories, p=[0.4, 0.3, 0.1, 0.1, 0.1])
        request_size = np.random.exponential(1000)  # Most requests are small
        header_count = np.random.poisson(8)  # Normal number of headers
        
        # Add some anomalies (10% of data)
        if i < n_samples * 0.1:
            # Anomalous patterns
            ip_request_count = np.random.poisson(50)  # High request rate
            user_agent_entropy = np.random.normal(6.0, 1.0)  # Unusual user agents
            request_size = np.random.exponential(10000)  # Large requests
            header_count = np.random.poisson(20)  # Many headers
        
        data.append({
            "ip_request_count": max(1, ip_request_count),
            "user_agent_entropy": max(0, user_agent_entropy),
            "hour_of_day": hour_of_day,
            "endpoint_category": endpoint_category,
            "request_size": max(0, request_size),
            "header_count": max(1, header_count)
        })
    
    return data


def train_threat_detection_model(
    training_data: List[Dict[str, Any]],
    model_path: str
) -> ThreatDetectionModel:
    """Train threat detection model"""
    print(f"Training threat detection model with {len(training_data)} samples...")
    
    # Initialize model
    model = ThreatDetectionModel()
    
    # Convert training data to feature arrays
    endpoint_categories = model.endpoint_categories
    
    X = []
    for data_point in training_data:
        endpoint_numeric = endpoint_categories.get(
            data_point["endpoint_category"],
            endpoint_categories["unknown"]
        )
        
        features = [
            data_point["ip_request_count"],
            data_point["user_agent_entropy"],
            data_point["hour_of_day"],
            endpoint_numeric,
            data_point["request_size"],
            data_point["header_count"]
        ]
        X.append(features)
    
    X = np.array(X)
    
    # Split data for training
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Isolation Forest
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_jobs=-1
    )
    
    iso_forest.fit(X_train_scaled)
    
    # Evaluate model
    test_scores = iso_forest.decision_function(X_test_scaled)
    print(f"Model training complete. Test score range: {test_scores.min():.3f} to {test_scores.max():.3f}")
    
    # Save model components
    model.model = iso_forest
    model.scaler = scaler
    model.save_model(model_path)
    
    print(f"Model saved to {model_path}")
    return model


def create_threat_detection_middleware(model_path: str):
    """Create threat detection middleware"""
    model = ThreatDetectionModel(model_path)
    
    if not model.load_model():
        print("Warning: Could not load threat detection model")
    
    return model
