"""Proxy routes for forwarding requests to upstream LLM APIs."""

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from anorak.core.proxy.middleware import reconstruct_maas_token
from anorak.core.proxy.passthrough import ProxyPassthrough
from anorak.core.proxy.streaming import stream_response
from anorak.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter()

# Global proxy passthrough (injected at startup)
_proxy: ProxyPassthrough = None


def set_proxy(proxy: ProxyPassthrough):
    """Set the global proxy passthrough."""
    global _proxy
    _proxy = proxy


@router.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_to_upstream(request: Request, path: str):
    """
    Generic proxy for all /v1/* routes to upstream API.

    This endpoint:
    1. Receives validated request (handshake already checked by middleware)
    2. Reconstructs API token from shards
    3. Forwards request to upstream API with injected token
    4. Streams response back to client
    5. Wipes token from memory

    Args:
        request: Incoming HTTP request
        path: Path after /v1/ to forward

    Returns:
        Proxied response from upstream API
    """
    logger.info("Proxy route called", path=f"/v1/{path}")

    if not _proxy:
        raise RuntimeError("Proxy not initialized")

    logger.info("About to reconstruct MaaS token")
    # Reconstruct MaaS token from shards (from Redis or env)
    token = await reconstruct_maas_token()
    logger.info("MaaS token reconstructed")

    logger.info("Proxying request", method=request.method, path=f"/v1/{path}")

    try:
        # Check if client wants streaming (common for chat completions)
        logger.info("Reading request body")
        body = await request.body()
        is_streaming = b'"stream":true' in body or b'"stream": true' in body
        logger.info("Body read", is_streaming=is_streaming)

        if is_streaming:
            # Stream response
            upstream_stream = _proxy.forward_streaming_request(
                request, f"/v1/{path}", token
            )
            return StreamingResponse(
                stream_response(upstream_stream),
                media_type="text/event-stream",
            )
        else:
            logger.info("Calling forward_request")
            # Non-streaming response
            response = await _proxy.forward_request(request, f"/v1/{path}", token)
            logger.info("Got response from forward_request", status=response.status_code if hasattr(response, 'status_code') else 'unknown')
            return response

    finally:
        # Wipe token from memory (best effort)
        token = "0" * len(token)
        del token
