"""Streaming response support for SSE and WebSocket."""

from typing import AsyncGenerator


async def stream_sse_response(
    upstream_stream: AsyncGenerator[bytes, None]
) -> AsyncGenerator[bytes, None]:
    """
    Stream Server-Sent Events (SSE) from upstream API.

    This is a passthrough that preserves SSE semantics.

    Args:
        upstream_stream: Async generator of upstream response chunks

    Yields:
        SSE event chunks
    """
    async for chunk in upstream_stream:
        yield chunk


async def stream_response(
    upstream_stream: AsyncGenerator[bytes, None]
) -> AsyncGenerator[bytes, None]:
    """
    Generic streaming response passthrough.

    Args:
        upstream_stream: Async generator of upstream response chunks

    Yields:
        Response chunks
    """
    async for chunk in upstream_stream:
        if chunk:  # Only yield non-empty chunks
            yield chunk
