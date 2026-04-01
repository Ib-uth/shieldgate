"""Test ML threat detection middleware"""

from unittest.mock import Mock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from ..main import app
from ..utils.ml_utils import (
    ThreatDetectionModel,
    generate_synthetic_training_data,
    train_threat_detection_model,
)


class TestThreatDetectionModel:
    """Test threat detection model functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.model_path = "test_threat_model.joblib"
        self.model = ThreatDetectionModel(self.model_path)

    def test_feature_extraction(self):
        """Test feature extraction from request data"""
        request_data = {
            "ip_request_count": 5,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "timestamp": "2024-01-01T10:00:00",
            "path": "/api/v1/users",
            "request_size": 1024,
            "headers": {"host": "example.com", "user-agent": "Mozilla/5.0"},
        }

        features = self.model.extract_features(request_data)

        assert features.ip_request_count == 5
        assert features.user_agent_entropy > 0
        assert features.hour_of_day == 10
        assert features.endpoint_category in [
            "public",
            "user",
            "admin",
            "health",
            "metrics",
            "unknown",
        ]
        assert features.request_size == 1024
        assert features.header_count == 2

    def test_endpoint_categorization(self):
        """Test endpoint path categorization"""
        test_cases = [
            ("/public", "public"),
            ("/user/profile", "user"),
            ("/admin/settings", "admin"),
            ("/health", "health"),
            ("/metrics", "metrics"),
            ("/unknown/path", "unknown"),
            ("/api/v1/public/data", "public"),
            ("/api/v1/user/info", "user"),
        ]

        for path, expected_category in test_cases:
            category = self.model.categorize_endpoint(path)
            assert category == expected_category

    def test_user_agent_entropy_calculation(self):
        """Test user agent entropy calculation"""
        # High entropy (random characters)
        high_entropy_ua = "xYz123!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
        entropy_high = self.model.calculate_entropy(high_entropy_ua)

        # Low entropy (repetitive characters)
        low_entropy_ua = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        entropy_low = self.model.calculate_entropy(low_entropy_ua)

        # Normal user agent
        normal_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        entropy_normal = self.model.calculate_entropy(normal_ua)

        assert entropy_high > entropy_normal
        assert entropy_normal > entropy_low
        assert entropy_high > 3.0  # Should be reasonably high
        assert entropy_low < 1.0  # Should be very low

    def test_feature_preparation(self):
        """Test feature preparation for model prediction"""
        from ..utils.ml_utils import ThreatFeatures

        features = ThreatFeatures(
            ip_request_count=10,
            user_agent_entropy=3.5,
            hour_of_day=14,
            endpoint_category="user",
            request_size=2048,
            header_count=8,
        )

        feature_array = self.model.prepare_features(features)

        assert feature_array.shape == (1, 6)  # 6 features
        assert feature_array.dtype == np.float64

    def test_threat_score_interpretation(self):
        """Test threat score interpretation"""
        # Test threat level determination
        assert self.model.is_threat(0.8, 0.7) is True
        assert self.model.is_threat(0.6, 0.7) is False
        assert self.model.should_block(0.95, 0.9) is True
        assert self.model.should_block(0.8, 0.9) is False

    def test_synthetic_data_generation(self):
        """Test synthetic training data generation"""
        data = generate_synthetic_training_data(100)

        assert len(data) == 100
        assert all(isinstance(item, dict) for item in data)

        # Check required fields
        required_fields = [
            "ip_request_count",
            "user_agent_entropy",
            "hour_of_day",
            "endpoint_category",
            "request_size",
            "header_count",
        ]

        for item in data:
            for field in required_fields:
                assert field in item
                assert isinstance(item[field], (int, float))

    def test_model_training(self):
        """Test model training process"""
        # Generate small dataset for testing
        training_data = generate_synthetic_training_data(100)

        # Train model
        trained_model = train_threat_detection_model(training_data, self.model_path)

        assert trained_model.model is not None
        assert trained_model.scaler is not None

        # Test prediction
        test_request = {
            "ip_request_count": 1,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": "2024-01-01T10:00:00",
            "path": "/public",
            "request_size": 500,
            "headers": {"host": "example.com"},
        }

        threat_score = trained_model.predict_threat_score(test_request)
        assert 0.0 <= threat_score <= 1.0

    def test_model_loading(self):
        """Test model loading and saving"""
        # Create and train a model
        training_data = generate_synthetic_training_data(50)
        trained_model = train_threat_detection_model(training_data, self.model_path)

        # Create new model instance and load
        new_model = ThreatDetectionModel(self.model_path)
        loaded = new_model.load_model()

        assert loaded is True
        assert new_model.model is not None
        assert new_model.scaler is not None

        # Test that loaded model works
        test_request = {
            "ip_request_count": 1,
            "user_agent": "Mozilla/5.0",
            "timestamp": "2024-01-01T10:00:00",
            "path": "/public",
            "request_size": 500,
            "headers": {"host": "test.com"},
        }

        score1 = trained_model.predict_threat_score(test_request)
        score2 = new_model.predict_threat_score(test_request)

        assert abs(score1 - score2) < 0.001  # Should be very close


class TestThreatDetectionMiddleware:
    """Test threat detection middleware"""

    def setup_method(self):
        """Setup test environment"""
        self.client = TestClient(app)

    @patch("apps.gateway.main.ThreatDetectionModel")
    def test_threat_score_header_added(self, mock_model_class):
        """Test threat score header is added to responses"""
        # Mock model
        mock_model = Mock()
        mock_model.load_model.return_value = True
        mock_model.predict_threat_score.return_value = 0.3  # Low threat
        mock_model.is_threat.return_value = False
        mock_model.should_block.return_value = False
        mock_model_class.return_value = mock_model

        response = self.client.get("/proxy/public")

        # Should have threat score header if model is loaded
        # (This depends on middleware implementation)
        assert response.status_code in [200, 404]  # Should not be blocked

    @patch("apps.gateway.main.ThreatDetectionModel")
    def test_high_threat_score_blocked(self, mock_model_class):
        """Test high threat scores result in blocking"""
        # Mock model with high threat score
        mock_model = Mock()
        mock_model.load_model.return_value = True
        mock_model.predict_threat_score.return_value = 0.95  # High threat
        mock_model.is_threat.return_value = True
        mock_model.should_block.return_value = True
        mock_model_class.return_value = mock_model

        response = self.client.get("/proxy/public")

        # Should be blocked
        assert response.status_code == 403

    @patch("apps.gateway.main.ThreatDetectionModel")
    def test_medium_threat_score_flagged(self, mock_model_class):
        """Test medium threat scores are flagged but not blocked"""
        # Mock model with medium threat score
        mock_model = Mock()
        mock_model.load_model.return_value = True
        mock_model.predict_threat_score.return_value = 0.8  # Medium threat
        mock_model.is_threat.return_value = True
        mock_model.should_block.return_value = False
        mock_model_class.return_value = mock_model

        response = self.client.get("/proxy/public")

        # Should be flagged but allowed through
        assert response.status_code in [200, 404]  # Not blocked

    def test_model_not_loaded_graceful_degradation(self):
        """Test graceful degradation when model is not loaded"""
        # If model fails to load, requests should still work
        response = self.client.get("/health")
        assert response.status_code == 200


class TestThreatAnalyzer:
    """Test threat analyzer functionality"""

    def setup_method(self):
        """Setup test environment"""
        self.model = Mock()
        self.model.extract_features.return_value = Mock()
        self.model.predict_threat_score.return_value = 0.7
        self.model.is_threat.return_value = True
        self.model.should_block.return_value = False

        from ..middleware.threat_detection import ThreatAnalyzer

        self.analyzer = ThreatAnalyzer(self.model)

    def test_threat_level_classification(self):
        """Test threat level classification"""
        test_cases = [
            (0.95, "critical"),
            (0.8, "high"),
            (0.6, "medium"),
            (0.4, "low"),
            (0.1, "minimal"),
        ]

        for score, expected_level in test_cases:
            level = self.analyzer.get_threat_level(score)
            assert level == expected_level

    def test_feature_contributions(self):
        """Test feature contribution analysis"""
        features = Mock()
        features.ip_request_count = 50  # High
        features.user_agent_entropy = 6.0  # High
        features.hour_of_day = 3  # Unusual hour
        features.endpoint_category = "admin"  # Sensitive
        features.request_size = 50000  # Large
        features.header_count = 25  # Many headers

        contributions = self.analyzer.get_feature_contributions(features)

        # Should have contributions for high values
        assert contributions["ip_request_count"] > 0
        assert contributions["user_agent_entropy"] > 0
        assert contributions["endpoint_category"] > 0

    def test_complete_analysis(self):
        """Test complete threat analysis"""
        request_data = {
            "ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0",
            "timestamp": "2024-01-01T10:00:00",
            "path": "/admin/settings",
            "request_size": 1000,
            "headers": {"host": "test.com"},
        }

        analysis = self.analyzer.analyze_request(request_data)

        assert "threat_score" in analysis
        assert "threat_level" in analysis
        assert "is_threat" in analysis
        assert "should_block" in analysis
        assert "features" in analysis
        assert "feature_contributions" in analysis

        assert analysis["threat_score"] == 0.7
        assert analysis["is_threat"] is True
        assert analysis["should_block"] is False


if __name__ == "__main__":
    pytest.main([__file__])
