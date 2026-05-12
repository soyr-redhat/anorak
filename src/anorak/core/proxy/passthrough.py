"""Generic HTTP proxy for provider-agnostic LLM API forwarding."""

from typing import Optional

import httpx
from fastapi import Request, Response
from starlette.background import BackgroundTask

from anorak.exceptions.exceptions import AnorakErrorCode, ProxyException
from anorak.utils.logger import get_logger

logger = get_logger(__name__)


class ProxyPassthrough:
    """Generic HTTP proxy that forwards requests to any upstream API."""

    def __init__(self, upstream_url: str, timeout: int = 300):
        """
        Initialize proxy passthrough.

        Args:
            upstream_url: Base URL of upstream API (e.g., https://api.openai.com)
            timeout: Request timeout in seconds
        """
        self.upstream_url = upstream_url.rstrip("/")
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    async def forward_request(
        self,
        request: Request,
        path: str,
        token: str,
        additional_headers: Optional[dict] = None,
    ) -> Response:
        """
        Forward HTTP request to upstream API with injected token.

        Args:
            request: Original FastAPI request
            path: Path to forward (e.g., /v1/chat/completions)
            token: API token to inject
            additional_headers: Optional additional headers

        Returns:
            FastAPI Response with upstream response data

        Raises:
            ProxyException: If upstream request fails
        """
        # Build upstream URL
        url = f"{self.upstream_url}{path}"

        # Get request body
        body = await request.body()

        # Build headers (forward most headers, inject token)
        headers = dict(request.headers)

        # Remove hop-by-hop headers
        for header in ["host", "connection", "x-client-id", "x-response"]:
            headers.pop(header, None)

        # Inject API token (provider-specific header handling)
        # Try common patterns
        if "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {token}"
        if "x-api-key" not in headers:
            headers["x-api-key"] = token

        # Add additional headers
        if additional_headers:
            headers.update(additional_headers)

        # Log forwarding
        logger.info(
            "Forwarding request",
            method=request.method,
            path=path,
            upstream_url=url,
        )

        try:
            # Forward request to upstream
            upstream_response = await self.client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                params=request.query_params,
            )

            # Create response
            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=dict(upstream_response.headers),
                background=BackgroundTask(self._log_response, upstream_response),
            )

        except httpx.TimeoutException as e:
            logger.error("Upstream timeout", error=str(e), url=url)
            raise ProxyException(
                AnorakErrorCode.UPSTREAM_TIMEOUT,
                detail=f"Upstream API timeout: {url}",
            )
        except httpx.HTTPError as e:
            logger.error("Upstream error", error=str(e), url=url)
            raise ProxyException(
                AnorakErrorCode.UPSTREAM_ERROR,
                detail=f"Upstream API error: {str(e)}",
            )

    async def forward_streaming_request(
        self,
        request: Request,
        path: str,
        token: str,
        additional_headers: Optional[dict] = None,
    ):
        """
        Forward streaming request to upstream API.

        Args:
            request: Original FastAPI request
            path: Path to forward
            token: API token to inject
            additional_headers: Optional additional headers

        Yields:
            Chunks of streaming response data
        """
        # Build upstream URL
        url = f"{self.upstream_url}{path}"

        # Get request body
        body = await request.body()

        # Build headers
        headers = dict(request.headers)

        # Remove hop-by-hop headers
        for header in ["host", "connection", "x-client-id", "x-response"]:
            headers.pop(header, None)

        # Inject API token
        if "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {token}"
        if "x-api-key" not in headers:
            headers["x-api-key"] = token

        # Add additional headers
        if additional_headers:
            headers.update(additional_headers)

        logger.info(
            "Forwarding streaming request",
            method=request.method,
            path=path,
            upstream_url=url,
        )

        try:
            async with self.client.stream(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                params=request.query_params,
            ) as upstream_response:
                async for chunk in upstream_response.aiter_bytes():
                    yield chunk

        except httpx.TimeoutException as e:
            logger.error("Upstream streaming timeout", error=str(e), url=url)
            raise ProxyException(
                AnorakErrorCode.UPSTREAM_TIMEOUT,
                detail=f"Upstream API timeout: {url}",
            )
        except httpx.HTTPError as e:
            logger.error("Upstream streaming error", error=str(e), url=url)
            raise ProxyException(
                AnorakErrorCode.UPSTREAM_ERROR,
                detail=f"Upstream API error: {str(e)}",
            )

    async def _log_response(self, response: httpx.Response) -> None:
        """Log upstream response details."""
        logger.info(
            "Upstream response",
            status_code=response.status_code,
            headers=dict(response.headers),
        )
