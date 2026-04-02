"""SQLAlchemy database models"""

import os
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.sql import func

DATABASE_URL = os.environ.get("DATABASE_URL")
engine: Engine | None = create_engine(DATABASE_URL) if DATABASE_URL else None

# Create session factory
SessionLocal: sessionmaker[Session] | None = (
    sessionmaker(autocommit=False, autoflush=False, bind=engine) if engine else None
)


class Base(DeclarativeBase):
    pass


def get_db_session() -> Session:
    """Return a new DB session or raise if DATABASE_URL is not configured."""
    if SessionLocal is None:
        raise RuntimeError("DATABASE_URL is not configured")
    return SessionLocal()


class RequestLog(Base):
    """Request log table for storing all gateway requests"""

    __tablename__ = "request_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(500))
    status_code: Mapped[int] = mapped_column(Integer)
    latency_ms: Mapped[float] = mapped_column(Float)
    user_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, index=True, default=0.0)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    headers: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index("idx_timestamp_ip", "timestamp", "ip"),
        Index("idx_timestamp_user", "timestamp", "user_id"),
        Index("idx_blocked_timestamp", "blocked", "timestamp"),
        Index("idx_threat_score_timestamp", "threat_score", "timestamp"),
    )


class User(Base):
    """Admin / dashboard users (stored in PostgreSQL e.g. Neon)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="admin")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class BlockedIP(Base):
    """Blocked IPs table for persistent blocking"""

    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    unblocked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    unblocked_by: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Metrics(Base):
    """Aggregated metrics table"""

    __tablename__ = "metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    period_minutes: Mapped[int] = mapped_column(Integer, default=5)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    error_requests: Mapped[int] = mapped_column(Integer, default=0)
    blocked_requests: Mapped[int] = mapped_column(Integer, default=0)
    unique_ips: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    avg_threat_score: Mapped[float] = mapped_column(Float, default=0.0)

    __table_args__ = (Index("idx_timestamp_period", "timestamp", "period_minutes"),)
