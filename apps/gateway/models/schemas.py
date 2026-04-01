"""Pydantic schemas for API requests and responses"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class RequestLog(BaseModel):
    """Schema for request log entries"""

    request_id: str
    timestamp: datetime
    method: str
    path: str
    status_code: int
    latency_ms: float
    user_id: Optional[str] = None
    ip: str
    user_agent: str
    threat_score: float = 0.0
    blocked: bool = False


class HealthResponse(BaseModel):
    """Health check response"""

    status: str = "healthy"
    timestamp: datetime
    version: str = "0.1.0"
    services: Dict[str, Any]


class MetricsResponse(BaseModel):
    """Metrics response"""

    timestamp: datetime
    period_hours: int = 1
    total_requests: int
    error_rate: float
    top_blocked_ips: List[Dict[str, Any]]
    threat_score_distribution: Dict[str, Any]
    top_endpoints: List[Dict[str, Any]]


class TokenResponse(BaseModel):
    """JWT token response"""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserClaims(BaseModel):
    """JWT claims for user"""

    sub: str = Field(..., description="User ID")
    email: str
    role: str = Field(..., description="User role: admin, user, readonly")
    exp: int = Field(..., description="Expiration timestamp")
    iat: int = Field(..., description="Issued at timestamp")


class ProxyRequest(BaseModel):
    """Proxy request metadata"""

    method: str
    path: str
    headers: Dict[str, Any]
    body: Optional[bytes] = None
    query_params: Optional[Dict[str, Any]] = None


class ThreatFeatures(BaseModel):
    """Features for threat detection model"""

    ip_request_count: int
    user_agent_entropy: float
    hour_of_day: int
    endpoint_category: str
    request_size: int
    header_count: int
