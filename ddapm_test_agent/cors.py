"""Shared CORS helpers for test-agent HTTP endpoints."""

import re
from typing import Awaitable
from typing import Callable
from typing import Dict

from aiohttp import web
from aiohttp.web import Request


# Allowed CORS origins: Datadog UI domains and localhost for local development.
ALLOWED_ORIGIN_PATTERN = re.compile(
    r"^https?://(localhost(:\d+)?|127\.0\.0\.1(:\d+)?|[\w.-]+\.datadoghq\.(com|eu)|[\w.-]+\.ddog-gov\.com|[\w.-]+\.datad0g\.com|[\w.-]+\.static-app\.us1\.staging\.dog)$"
)

_CORS_ALLOW_METHODS = "GET, POST, OPTIONS"
_CORS_ALLOW_HEADERS = (
    "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, "
    "X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, "
    "X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer"
)


def cors_headers(request: Request) -> Dict[str, str]:
    """Build CORS headers, only allowing known origins."""
    headers: Dict[str, str] = {
        "Access-Control-Allow-Methods": _CORS_ALLOW_METHODS,
        "Access-Control-Allow-Headers": _CORS_ALLOW_HEADERS,
        "Vary": "Origin",
    }
    origin = request.headers.get("Origin", "")
    if ALLOWED_ORIGIN_PATTERN.match(origin):
        headers["Access-Control-Allow-Origin"] = origin
    return headers


def with_cors(
    handler: Callable[[Request], Awaitable[web.StreamResponse]],
) -> Callable[[Request], Awaitable[web.StreamResponse]]:
    """Wrap a handler with CORS headers and OPTIONS preflight support."""

    async def wrapper(request: Request) -> web.StreamResponse:
        headers = cors_headers(request)
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)
        response = await handler(request)
        response.headers.update(headers)
        return response

    return wrapper
