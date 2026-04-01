"""Request proxying routes"""

import os
import uuid
from typing import Any
from urllib.parse import urljoin

import httpx
from fastapi import HTTPException, Request, Response, status

from ..middleware.auth import JWTAuthenticator


class RequestProxy:
    """Handles proxying requests to downstream services"""

    def __init__(
        self,
        downstream_url: str,
        jwt_authenticator: JWTAuthenticator,
        timeout: float = 30.0,
    ):
        self.downstream_url = downstream_url.rstrip("/")
        self.jwt_authenticator = jwt_authenticator
        self.timeout = timeout
        self._downstream_api_prefix = (
            os.getenv("DOWNSTREAM_API_PREFIX", "api/v1").strip().strip("/")
        )

    async def proxy_request(
        self, request: Request, path: str | None = None
    ) -> Response:
        """Proxy request to downstream service"""

        # Generate request ID
        request_id = str(uuid.uuid4())

        # Build target URL (/proxy/user -> {DOWNSTREAM}/api/v1/user)
        segment = (path if path is not None else request.url.path).strip("/")
        if segment:
            rel_path = f"{self._downstream_api_prefix}/{segment}"
        else:
            rel_path = self._downstream_api_prefix
        target_url = urljoin(self.downstream_url + "/", rel_path)

        # Prepare headers
        headers = self.prepare_headers(request, request_id)

        # Prepare request parameters
        method = request.method
        params = dict(request.query_params)

        # Get request body
        body = await request.body()

        try:
            # Make the downstream request (ignore HTTP_PROXY etc. so localhost downstream is never proxied)
            async with httpx.AsyncClient(
                timeout=self.timeout, trust_env=False
            ) as client:
                response = await client.request(
                    method=method,
                    url=target_url,
                    headers=headers,
                    params=params,
                    content=body if body else None,
                )

            # Prepare response headers
            response_headers = self.prepare_response_headers(response)

            # Add proxy metadata to response headers
            response_headers.update(
                {
                    "X-Request-ID": request_id,
                    "X-Proxy-Response-Time": str(response.elapsed.total_seconds()),
                    "X-Downstream-Status": str(response.status_code),
                }
            )

            # Create and return response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type"),
            )

        except httpx.TimeoutException as e:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail="Downstream service timeout",
            ) from e
        except httpx.ConnectError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cannot connect to downstream service",
            ) from e
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Downstream service error: {str(e)}",
            ) from e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Proxy error: {str(e)}",
            ) from e

    def prepare_headers(self, request: Request, request_id: str) -> dict[str, str]:
        """Prepare headers for downstream request"""
        headers = dict(request.headers)

        # Remove hop-by-hop headers
        hop_by_hop_headers = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
        }
        for header in hop_by_hop_headers:
            headers.pop(header, None)

        # Let httpx set Host from the downstream URL (incoming Host is the gateway)
        headers.pop("host", None)

        # Remove auth headers for security
        auth_headers = {"authorization", "cookie", "x-api-key"}
        for header in auth_headers:
            headers.pop(header, None)

        # Add proxy headers
        headers.update(
            {
                "X-Request-ID": request_id,
                "X-Forwarded-For": self.get_client_ip(request),
                "X-Forwarded-Proto": request.url.scheme,
                "X-Forwarded-Host": request.headers.get("host", "localhost"),
                "X-Forwarded-Path": request.url.path,
                "X-Original-Method": request.method,
                "User-Agent": f"ShieldGate/1.0 {headers.get('User-Agent', '')}",
            }
        )

        # Add user information if authenticated
        if hasattr(request.state, "user"):
            user = request.state.user
            headers.update(
                {
                    "X-User-ID": user.sub,
                    "X-User-Email": user.email,
                    "X-User-Role": user.role,
                }
            )

        return headers

    def prepare_response_headers(self, response: httpx.Response) -> dict[str, str]:
        """Prepare headers for upstream response"""
        headers = dict(response.headers)

        # Remove hop-by-hop headers
        hop_by_hop_headers = {
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
        }
        for header in hop_by_hop_headers:
            headers.pop(header, None)

        return headers

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

    async def health_check(self) -> dict[str, Any]:
        """Check downstream service health"""
        try:
            async with httpx.AsyncClient(timeout=5.0, trust_env=False) as client:
                response = await client.get(f"{self.downstream_url}/health")

                if response.status_code == 200:
                    return {
                        "status": "healthy",
                        "downstream_url": self.downstream_url,
                        "response_time": response.elapsed.total_seconds(),
                        "status_code": response.status_code,
                    }
                else:
                    return {
                        "status": "unhealthy",
                        "downstream_url": self.downstream_url,
                        "status_code": response.status_code,
                        "error": f"Downstream returned {response.status_code}",
                    }

        except Exception as e:
            return {
                "status": "unreachable",
                "downstream_url": self.downstream_url,
                "error": str(e),
            }


# Proxy route handlers
def create_proxy_routes(proxy: RequestProxy):
    """Create proxy routes"""

    async def proxy_handler(request: Request, path: str = ""):
        """Main proxy handler"""
        return await proxy.proxy_request(request, path)

    async def catch_all_proxy(request: Request):
        """Catch-all proxy handler for any path"""
        return await proxy.proxy_request(request)

    return proxy_handler, catch_all_proxy
