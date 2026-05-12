"""Proxy routes for forwarding requests to upstream LLM APIs."""

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from anorak.core.proxy.middleware import reconstruct_api_token
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
    if not _proxy:
        raise RuntimeError("Proxy not initialized")

    # Reconstruct token from shards (from Redis or env)
    token = await reconstruct_api_token()

    logger.info("Proxying request", method=request.method, path=f"/v1/{path}")

    try:
        # Check if client wants streaming (common for chat completions)
        body = await request.body()
        is_streaming = b'"stream":true' in body or b'"stream": true' in body

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
            # Non-streaming response
            response = await _proxy.forward_request(request, f"/v1/{path}", token)
            return response

    finally:
        # Wipe token from memory (best effort)
        token = "0" * len(token)
        del token
