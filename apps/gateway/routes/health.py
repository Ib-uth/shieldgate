"""Health check and metrics endpoints"""

import time
from datetime import datetime, timedelta
from typing import Any

import redis.asyncio as redis
from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, text

from ..models.database import BlockedIP, RequestLog, get_db_session
from ..models.schemas import HealthResponse, MetricsResponse


def create_health_routes(redis_client: redis.Redis, database_engine) -> APIRouter:
    """Create health check routes"""
    router = APIRouter()

    @router.get("/", response_model=HealthResponse)
    async def health_check():
        """Comprehensive health check"""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow(),
            "version": "1.0.0",
            "services": {},
        }

        # Check Redis
        redis_status = await check_redis_health(redis_client)
        health_status["services"]["redis"] = redis_status

        # Check Database
        db_status = await check_database_health(database_engine)
        health_status["services"]["database"] = db_status

        # Check Downstream Service
        downstream_status = await check_downstream_health()
        health_status["services"]["downstream"] = downstream_status

        # Overall status
        all_healthy = all(
            service["status"] == "healthy"
            for service in health_status["services"].values()
        )

        if not all_healthy:
            health_status["status"] = "degraded"

        return HealthResponse(**health_status)

    @router.get("/detailed")
    async def detailed_health():
        """Detailed health check with additional metrics"""
        return await health_check()

    return router


def create_metrics_routes(redis_client: redis.Redis, database_engine) -> APIRouter:
    """Create metrics routes"""
    router = APIRouter()

    @router.get("/", response_model=MetricsResponse)
    async def get_metrics(hours: int = 1, limit: int = 100):
        """Get request metrics for the last N hours"""
        try:
            # Calculate time range (timezone-aware for PostgreSQL timestamptz columns)
            end_time = datetime.now(datetime.UTC)
            start_time = end_time - timedelta(hours=hours)

            # Get metrics from database
            db = get_db_session()
            try:
                # Total requests
                total_requests = (
                    db.query(RequestLog)
                    .filter(RequestLog.timestamp >= start_time)
                    .count()
                )

                # Error rate (4xx and 5xx status codes)
                error_requests = (
                    db.query(RequestLog)
                    .filter(
                        RequestLog.timestamp >= start_time,
                        RequestLog.status_code >= 400,
                    )
                    .count()
                )

                error_rate = (
                    (error_requests / total_requests * 100)
                    if total_requests > 0
                    else 0.0
                )

                # Top blocked IPs
                blocked_ips = (
                    db.query(
                        RequestLog.ip, func.count(RequestLog.id).label("blocked_count")
                    )
                    .filter(RequestLog.timestamp >= start_time, RequestLog.blocked)
                    .group_by(RequestLog.ip)
                    .order_by(func.count(RequestLog.id).desc())
                    .limit(10)
                    .all()
                )

                top_blocked_ips = [
                    {"ip": ip, "blocked_count": count} for ip, count in blocked_ips
                ]

                # Threat score distribution
                threat_scores = (
                    db.query(
                        func.case(
                            (RequestLog.threat_score >= 0.9, "critical"),
                            (RequestLog.threat_score >= 0.7, "high"),
                            (RequestLog.threat_score >= 0.5, "medium"),
                            (RequestLog.threat_score >= 0.3, "low"),
                            else_="minimal",
                        ).label("threat_level"),
                        func.count(RequestLog.id).label("count"),
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

                threat_score_distribution = {
                    str(row[0]): int(row[1]) for row in threat_scores
                }

                # Top endpoints
                top_endpoints = (
                    db.query(
                        RequestLog.path,
                        func.count(RequestLog.id).label("request_count"),
                        func.avg(RequestLog.latency_ms).label("avg_latency"),
                    )
                    .filter(RequestLog.timestamp >= start_time)
                    .group_by(RequestLog.path)
                    .order_by(func.count(RequestLog.id).desc())
                    .limit(10)
                    .all()
                )

                top_endpoints_data = [
                    {
                        "path": path,
                        "request_count": count,
                        "avg_latency_ms": float(avg_latency) if avg_latency else 0.0,
                    }
                    for path, count, avg_latency in top_endpoints
                ]

                return MetricsResponse(
                    timestamp=datetime.now(datetime.UTC),
                    period_hours=hours,
                    total_requests=total_requests,
                    error_rate=round(error_rate, 2),
                    top_blocked_ips=top_blocked_ips,
                    threat_score_distribution=threat_score_distribution,
                    top_endpoints=top_endpoints_data,
                )

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve metrics: {str(e)}",
            ) from e

    @router.get("/requests")
    async def get_recent_requests(
        limit: int = 50, offset: int = 0, blocked_only: bool = False
    ):
        """Get recent request logs"""
        try:
            db = get_db_session()
            try:
                query = db.query(RequestLog)

                if blocked_only:
                    query = query.filter(RequestLog.blocked)

                requests = (
                    query.order_by(RequestLog.timestamp.desc())
                    .offset(offset)
                    .limit(limit)
                    .all()
                )

                return [
                    {
                        "request_id": req.request_id,
                        "timestamp": req.timestamp.isoformat(),
                        "method": req.method,
                        "path": req.path,
                        "status_code": req.status_code,
                        "latency_ms": req.latency_ms,
                        "user_id": req.user_id,
                        "ip": req.ip,
                        "user_agent": req.user_agent,
                        "threat_score": req.threat_score,
                        "blocked": req.blocked,
                    }
                    for req in requests
                ]

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve requests: {str(e)}",
            ) from e

    @router.get("/blocked-ips")
    async def get_blocked_ips(limit: int = 100):
        """Get list of blocked IPs"""
        try:
            db = get_db_session()
            try:
                blocked_ips = (
                    db.query(BlockedIP)
                    .filter(BlockedIP.unblocked_at.is_(None))
                    .order_by(BlockedIP.blocked_at.desc())
                    .limit(limit)
                    .all()
                )

                return [
                    {
                        "ip": ip.ip,
                        "blocked_at": ip.blocked_at.isoformat(),
                        "reason": ip.reason,
                        "threat_score": ip.threat_score,
                    }
                    for ip in blocked_ips
                ]

            finally:
                db.close()

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to retrieve blocked IPs: {str(e)}",
            ) from e

    @router.post("/unblock-ip/{ip}")
    async def unblock_ip(ip: str):
        """Unblock an IP address"""
        try:
            db = get_db_session()
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
            ) from e

    return router


async def check_redis_health(redis_client: redis.Redis) -> dict[str, Any]:
    """Check Redis health"""
    try:
        start_time = time.time()
        await redis_client.ping()  # type: ignore[misc]
        response_time = (time.time() - start_time) * 1000

        return {
            "status": "healthy",
            "response_time_ms": round(response_time, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


async def check_database_health(database_engine) -> dict[str, Any]:
    """Check database health"""
    try:
        start_time = time.time()

        # Simple database query
        with database_engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.fetchone()

        response_time = (time.time() - start_time) * 1000

        return {
            "status": "healthy",
            "response_time_ms": round(response_time, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


async def check_downstream_health() -> dict[str, Any]:
    """Check downstream service health"""
    try:
        import httpx

        downstream_url = "http://localhost:8001"  # Default mock service URL
        start_time = time.time()

        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{downstream_url}/health")

        response_time = (time.time() - start_time) * 1000

        if response.status_code == 200:
            return {
                "status": "healthy",
                "response_time_ms": round(response_time, 2),
                "status_code": response.status_code,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            return {
                "status": "unhealthy",
                "status_code": response.status_code,
                "error": f"Downstream returned {response.status_code}",
                "timestamp": datetime.utcnow().isoformat(),
            }

    except Exception as e:
        return {
            "status": "unreachable",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
