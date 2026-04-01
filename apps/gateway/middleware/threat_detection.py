"""Threat detection middleware"""

import os
from typing import Dict, Any, Optional
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from ..utils.ml_utils import ThreatDetectionModel
from ..middleware.logging import RequestLogger


class ThreatDetectionMiddleware(BaseHTTPMiddleware):
    """Middleware for ML-based threat detection"""
    
    def __init__(
        self,
        app,
        redis_client: redis.Redis,
        model_path: str,
        flag_threshold: float = 0.7,
        block_threshold: float = 0.9
    ):
        super().__init__(app)
        self.redis_client = redis_client
        self.model_path = model_path
        self.flag_threshold = flag_threshold
        self.block_threshold = block_threshold
        self.model = None
        self.load_model()
    
    def load_model(self):
        """Load threat detection model"""
        try:
            self.model = ThreatDetectionModel(self.model_path)
            if not self.model.load_model():
                print("Warning: Could not load threat detection model")
                self.model = None
            else:
                print("Threat detection model loaded successfully")
        except Exception as e:
            print(f"Error loading threat detection model: {e}")
            self.model = None
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip threat detection for health endpoints
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)
        
        # Skip if model not loaded
        if self.model is None:
            return await call_next(request)
        
        try:
            # Extract request data for threat analysis
            request_data = await self.extract_request_data(request)
            
            # Calculate threat score
            threat_score = self.model.predict_threat_score(request_data)
            
            # Store threat score in request state
            request.state.threat_score = threat_score
            
            # Log threat detection
            features = self.model.extract_features(request_data)
            RequestLogger.log_threat_detection(
                request_id=getattr(request.state, "request_id", "unknown"),
                threat_score=threat_score,
                features=features.dict(),
                blocked=self.model.should_block(threat_score, self.block_threshold)
            )
            
            # Block request if threat score is too high
            if self.model.should_block(threat_score, self.block_threshold):
                return Response(
                    content="Request blocked due to high threat score",
                    status_code=status.HTTP_403_FORBIDDEN,
                    headers={
                        "X-Threat-Score": str(threat_score),
                        "X-Threat-Action": "blocked"
                    }
                )
            
            # Process request
            response = await call_next(request)
            
            # Add threat score header if flagged
            if self.model.is_threat(threat_score, self.flag_threshold):
                response.headers["X-Threat-Score"] = str(threat_score)
                response.headers["X-Threat-Action"] = "flagged"
            
            return response
            
        except Exception as e:
            print(f"Threat detection error: {e}")
            # Continue processing if threat detection fails
            return await call_next(request)
    
    async def extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract relevant data from request for threat analysis"""
        # Get client IP
        client_ip = self.get_client_ip(request)
        
        # Get user agent
        user_agent = request.headers.get("user-agent", "")
        
        # Get timestamp
        from datetime import datetime
        timestamp = datetime.utcnow()
        
        # Get path
        path = request.url.path
        
        # Get headers count
        headers = dict(request.headers)
        header_count = len(headers)
        
        # Estimate request size (rough approximation)
        content_length = request.headers.get("content-length")
        request_size = int(content_length) if content_length else 0
        
        # Get IP request count (simplified - in production, this would come from Redis/DB)
        ip_request_count = await self.get_ip_request_count(client_ip)
        
        return {
            "ip_request_count": ip_request_count,
            "user_agent": user_agent,
            "timestamp": timestamp,
            "path": path,
            "request_size": request_size,
            "headers": headers,
            "header_count": header_count
        }
    
    def get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check for X-Forwarded-For header first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # Check for X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to client IP
        return request.client.host if request.client else "unknown"
    
    async def get_ip_request_count(self, ip: str) -> int:
        """Get recent request count for IP from Redis"""
        try:
            # Use same sliding window as rate limiter
            current_time = int(time.time())
            window_start = current_time - 60  # 60-second window
            
            # Count requests in the sliding window
            count = await self.redis_client.zcount(
                f"rate_limit:ip:{ip}",
                window_start,
                current_time
            )
            
            return max(1, count)  # Return at least 1
        except Exception as e:
            print(f"Error getting IP request count: {e}")
            return 1  # Fallback to 1


class ThreatAnalyzer:
    """Helper class for threat analysis and reporting"""
    
    def __init__(self, model: ThreatDetectionModel):
        self.model = model
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a request and return detailed threat information"""
        # Extract features
        features = self.model.extract_features(request_data)
        
        # Calculate threat score
        threat_score = self.model.predict_threat_score(request_data)
        
        # Determine threat level
        threat_level = self.get_threat_level(threat_score)
        
        # Get feature contributions (simplified)
        feature_contributions = self.get_feature_contributions(features)
        
        return {
            "threat_score": threat_score,
            "threat_level": threat_level,
            "is_threat": self.model.is_threat(threat_score),
            "should_block": self.model.should_block(threat_score),
            "features": features.dict(),
            "feature_contributions": feature_contributions
        }
    
    def get_threat_level(self, threat_score: float) -> str:
        """Get threat level classification"""
        if threat_score >= 0.9:
            return "critical"
        elif threat_score >= 0.7:
            return "high"
        elif threat_score >= 0.5:
            return "medium"
        elif threat_score >= 0.3:
            return "low"
        else:
            return "minimal"
    
    def get_feature_contributions(self, features) -> Dict[str, float]:
        """Get simplified feature contributions to threat score"""
        # This is a simplified implementation
        # In a real system, you might use SHAP values or other interpretability methods
        
        contributions = {}
        
        # High IP request count contributes to threat
        if features.ip_request_count > 20:
            contributions["ip_request_count"] = min(0.3, features.ip_request_count / 100)
        else:
            contributions["ip_request_count"] = 0.0
        
        # High user agent entropy contributes to threat
        if features.user_agent_entropy > 5:
            contributions["user_agent_entropy"] = min(0.2, (features.user_agent_entropy - 5) / 5)
        else:
            contributions["user_agent_entropy"] = 0.0
        
        # Unusual hours contribute to threat
        if features.hour_of_day < 6 or features.hour_of_day > 22:
            contributions["hour_of_day"] = 0.1
        else:
            contributions["hour_of_day"] = 0.0
        
        # Admin endpoints are more sensitive
        if features.endpoint_category == "admin":
            contributions["endpoint_category"] = 0.1
        else:
            contributions["endpoint_category"] = 0.0
        
        # Large requests contribute to threat
        if features.request_size > 10000:
            contributions["request_size"] = min(0.2, features.request_size / 100000)
        else:
            contributions["request_size"] = 0.0
        
        # Many headers contribute to threat
        if features.header_count > 15:
            contributions["header_count"] = min(0.1, features.header_count / 50)
        else:
            contributions["header_count"] = 0.0
        
        return contributions
