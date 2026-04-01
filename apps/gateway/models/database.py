"""SQLAlchemy database models"""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class RequestLog(Base):
    """Request log table for storing all gateway requests"""
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=func.now(), index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(500), nullable=False)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Float, nullable=False)
    user_id = Column(String(100), nullable=True, index=True)
    ip = Column(String(45), nullable=False, index=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    threat_score = Column(Float, nullable=False, default=0.0, index=True)
    blocked = Column(Boolean, nullable=False, default=False)
    headers = Column(Text, nullable=True)  # JSON string
    response_size = Column(Integer, nullable=True)

    # Indexes for common queries
    __table_args__ = (
        Index('idx_timestamp_ip', 'timestamp', 'ip'),
        Index('idx_timestamp_user', 'timestamp', 'user_id'),
        Index('idx_blocked_timestamp', 'blocked', 'timestamp'),
        Index('idx_threat_score_timestamp', 'threat_score', 'timestamp'),
    )


class BlockedIP(Base):
    """Blocked IPs table for persistent blocking"""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    blocked_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    reason = Column(String(200), nullable=True)
    threat_score = Column(Float, nullable=True)
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    unblocked_by = Column(String(100), nullable=True)


class Metrics(Base):
    """Aggregated metrics table"""
    __tablename__ = "metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=func.now(), index=True)
    period_minutes = Column(Integer, nullable=False, default=5)
    total_requests = Column(Integer, nullable=False, default=0)
    error_requests = Column(Integer, nullable=False, default=0)
    blocked_requests = Column(Integer, nullable=False, default=0)
    unique_ips = Column(Integer, nullable=False, default=0)
    avg_latency_ms = Column(Float, nullable=False, default=0.0)
    avg_threat_score = Column(Float, nullable=False, default=0.0)

    # Index for time-series queries
    __table_args__ = (
        Index('idx_timestamp_period', 'timestamp', 'period_minutes'),
    )
