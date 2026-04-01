"""Admin-only routes"""

import os
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Body, HTTPException, status
from sqlalchemy import desc, func

from ..middleware.rbac import require_admin
from ..models.database import BlockedIP, RequestLog, SessionLocal
from ..utils.jwt_utils import JWTManager


def create_admin_routes(rbac_middleware, database_engine) -> APIRouter:
    """Create admin-only routes"""
    router = APIRouter()

    @router.get("/stats")
    @require_admin
    async def get_admin_stats():
        """Get comprehensive admin statistics"""
        try:
            db = SessionLocal()
            try:
                # Time ranges for different statistics
                now = datetime.utcnow()
                last_hour = now - timedelta(hours=1)
                last_day = now - timedelta(days=1)
                last_week = now - timedelta(weeks=1)

                # Request counts by time period
                stats = {}

                for period_name, start_time in [
                    ("last_hour", last_hour),
                    ("last_day", last_day),
                    ("last_week", last_week),
                ]:
                    total_requests = (
                        db.query(RequestLog)
                        .filter(RequestLog.timestamp >= start_time)
                        .count()
                    )

                    error_requests = (
                        db.query(RequestLog)
                        .filter(
                            RequestLog.timestamp >= start_time,
                            RequestLog.status_code >= 400,
                        )
                        .count()
                    )

                    blocked_requests = (
                        db.query(RequestLog)
                        .filter(RequestLog.timestamp >= start_time, RequestLog.blocked)
                        .count()
                    )

                    unique_ips = (
                        db.query(RequestLog.ip)
                        .filter(RequestLog.timestamp >= start_time)
                        .distinct()
                        .count()
                    )

                    avg_latency = (
                        db.query(func.avg(RequestLog.latency_ms))
                        .filter(RequestLog.timestamp >= start_time)
                        .scalar()
                        or 0
                    )

                    avg_threat_score = (
                        db.query(func.avg(RequestLog.threat_score))
                        .filter(RequestLog.timestamp >= start_time)
                        .scalar()
                        or 0
                    )

                    stats[period_name] = {
                        "total_requests": total_requests,
                        "error_requests": error_requests,
                        "blocked_requests": blocked_requests,
                        "unique_ips": unique_ips,
                        "avg_latency_ms": float(avg_latency),
                        "avg_threat_score": float(avg_threat_score),
                        "error_rate": (
                            (error_requests / total_requests * 100)
                            if total_requests > 0
                            else 0
                        ),
                        "block_rate": (
                            (blocked_requests / total_requests * 100)
                            if total_requests > 0
                            else 0
                        ),
                    }

                # Top threat actors (IPs with high threat scores)
                top_threat_actors = (
                    db.query(
                        RequestLog.ip,
                        func.avg(RequestLog.threat_score).label("avg_threat_score"),
                        func.count(RequestLog.id).label("request_count"),
                        func.sum(func.cast(RequestLog.blocked, int)).label(
                            "blocked_count"
                        ),
                    )
                    .filter(RequestLog.timestamp >= last_day)
                    .group_by(RequestLog.ip)
                    .having(func.avg(RequestLog.threat_score) > 0.5)
                    .order_by(desc("avg_threat_score"))
                    .limit(10)
                    .all()
                )

                # Recent blocked IPs
                recent_blocked = (
                    db.query(BlockedIP)
                    .filter(
                        BlockedIP.blocked_at >= last_day,
                        BlockedIP.unblocked_at.is_(None),
                    )
                    .order_by(BlockedIP.blocked_at.desc())
                    .limit(20)
                    .all()
                )

                return {
                    "timestamp": now.isoformat(),
                    "statistics": stats,
                    "top_threat_actors": [
                        {
                            "ip": ip,
                            "avg_threat_score": float(avg_threat_score),
                            "request_count": request_count,
                            "blocked_count": blocked_count,
                        }
                        for ip, avg_threat_score, request_count, blocked_count in top_threat_actors
                    ],
                    "recent_blocked_ips": [
                        {
                            "ip": blocked.ip,
                            "blocked_at": blocked.blocked_at.isoformat(),
                            "reason": blocked.reason,
                            "threat_score": blocked.threat_score,
                        }
                        for blocked in recent_blocked
                    ],
                }

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve admin statistics: {str(e)}",
            )

    @router.post("/block-ip")
    @require_admin
    async def block_ip_address(ip_data: dict[str, Any] = Body(...)):
        """Block an IP address"""
        try:
            ip = ip_data.get("ip")
            reason = ip_data.get("reason", "Manual block by admin")
            threat_score = ip_data.get("threat_score", 1.0)

            if not ip:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="IP address is required",
                )

            db = SessionLocal()
            try:
                # Check if IP is already blocked
                existing_block = (
                    db.query(BlockedIP)
                    .filter(BlockedIP.ip == ip, BlockedIP.unblocked_at.is_(None))
                    .first()
                )

                if existing_block:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"IP {ip} is already blocked",
                    )

                # Create new block
                blocked_ip = BlockedIP(
                    ip=ip,
                    blocked_at=datetime.utcnow(),
                    reason=reason,
                    threat_score=threat_score,
                )

                db.add(blocked_ip)
                db.commit()

                return {
                    "message": f"IP {ip} has been blocked",
                    "ip": ip,
                    "blocked_at": blocked_ip.blocked_at.isoformat(),
                    "reason": reason,
                    "threat_score": threat_score,
                }

            finally:
                db.close()

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to block IP: {str(e)}",
            )

    @router.post("/unblock-ip/{ip}")
    @require_admin
    async def unblock_ip_address(ip: str):
        """Unblock an IP address"""
        try:
            db = SessionLocal()
            try:
                # Find the blocked IP
                blocked_ip = (
                    db.query(BlockedIP)
                    .filter(BlockedIP.ip == ip, BlockedIP.unblocked_at.is_(None))
                    .first()
                )

                if not blocked_ip:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"IP {ip} is not currently blocked",
                    )

                # Update the record
                blocked_ip.unblocked_at = datetime.utcnow()
                blocked_ip.unblocked_by = (
                    "admin"  # In a real system, this would be the current user
                )
                db.commit()

                return {
                    "message": f"IP {ip} has been unblocked",
                    "ip": ip,
                    "unblocked_at": blocked_ip.unblocked_at.isoformat(),
                }

            finally:
                db.close()

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to unblock IP: {str(e)}",
            )

    @router.get("/blocked-ips")
    @require_admin
    async def get_blocked_ips(limit: int = 100, active_only: bool = True):
        """Get list of blocked IPs"""
        try:
            db = SessionLocal()
            try:
                query = db.query(BlockedIP)

                if active_only:
                    query = query.filter(BlockedIP.unblocked_at.is_(None))

                blocked_ips = (
                    query.order_by(BlockedIP.blocked_at.desc()).limit(limit).all()
                )

                return [
                    {
                        "ip": ip.ip,
                        "blocked_at": ip.blocked_at.isoformat(),
                        "reason": ip.reason,
                        "threat_score": ip.threat_score,
                        "unblocked_at": (
                            ip.unblocked_at.isoformat() if ip.unblocked_at else None
                        ),
                        "unblocked_by": ip.unblocked_by,
                    }
                    for ip in blocked_ips
                ]

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve blocked IPs: {str(e)}",
            )

    @router.get("/threat-scores")
    @require_admin
    async def get_threat_score_distribution(hours: int = 24):
        """Get detailed threat score distribution"""
        try:
            db = SessionLocal()
            try:
                start_time = datetime.utcnow() - timedelta(hours=hours)

                # Threat score distribution
                threat_distribution = (
                    db.query(
                        func.case(
                            (RequestLog.threat_score >= 0.9, "critical"),
                            (RequestLog.threat_score >= 0.7, "high"),
                            (RequestLog.threat_score >= 0.5, "medium"),
                            (RequestLog.threat_score >= 0.3, "low"),
                            else_="minimal",
                        ).label("threat_level"),
                        func.count(RequestLog.id).label("count"),
                        func.avg(RequestLog.threat_score).label("avg_score"),
                    )
                    .filter(RequestLog.timestamp >= start_time)
                    .group_by(
                        func.case(
                            (RequestLog.threat_score >= 0.9, "critical"),
                            (RequestLog.threat_score >= 0.7, "high"),
                            (RequestLog.threat_score >= 0.5, "medium"),
                            (RequestLog.threat_score >= 0.3, "low"),
                            else_="minimal",
                        )
                    )
                    .all()
                )

                # High threat requests
                high_threat_requests = (
                    db.query(RequestLog)
                    .filter(
                        RequestLog.timestamp >= start_time,
                        RequestLog.threat_score >= 0.7,
                    )
                    .order_by(desc(RequestLog.threat_score))
                    .limit(50)
                    .all()
                )

                return {
                    "period_hours": hours,
                    "threat_distribution": [
                        {
                            "threat_level": level,
                            "count": count,
                            "avg_score": float(avg_score) if avg_score else 0.0,
                        }
                        for level, count, avg_score in threat_distribution
                    ],
                    "high_threat_requests": [
                        {
                            "request_id": req.request_id,
                            "timestamp": req.timestamp.isoformat(),
                            "ip": req.ip,
                            "path": req.path,
                            "threat_score": req.threat_score,
                            "blocked": req.blocked,
                            "user_agent": (
                                req.user_agent[:100] if req.user_agent else None
                            ),
                        }
                        for req in high_threat_requests
                    ],
                }

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve threat scores: {str(e)}",
            )

    @router.post("/generate-test-token")
    @require_admin
    async def generate_test_token(token_data: dict[str, Any] = Body(...)):
        """Generate a test JWT token"""
        try:
            # Get JWT paths from environment
            private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "./keys/private.pem")
            public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "./keys/public.pem")

            # Create JWT manager
            jwt_manager = JWTManager(private_key_path, public_key_path)

            # Extract token claims
            user_claims = {
                "sub": token_data.get("sub", "test-user"),
                "email": token_data.get("email", "test@example.com"),
                "role": token_data.get("role", "user"),
            }

            expires_in = token_data.get("expires_in", 3600)

            # Generate token
            token = jwt_manager.create_token(user_claims, expires_in)

            return {
                "access_token": token,
                "token_type": "bearer",
                "expires_in": expires_in,
                "claims": user_claims,
            }

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate token: {str(e)}",
            )

    return router
