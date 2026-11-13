"""Token auth for ``lapdog server``.

Query and admin routes need ``Authorization: Bearer <token>``. Intake also
accepts the token as ``DD-API-KEY``, so ddtrace in agentless mode only needs
``DD_API_KEY=<token>``. Preflights, ``/ping``, and ``/info`` are public.
"""

import hmac
from typing import Awaitable
from typing import Callable
from typing import FrozenSet
from typing import Optional

from aiohttp import web

from ddapm_test_agent.cors import cors_headers

from .config import ServerConfig

PUBLIC_PATHS = frozenset({"/ping", "/info"})

_Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def _request_token(request: web.Request, ingest: bool) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    if ingest:
        return request.headers.get("DD-API-KEY") or request.headers.get("X-DD-API-KEY")
    return None


def make_auth_middleware(
    config: ServerConfig, ingest_paths: FrozenSet[str]
) -> Callable[..., Awaitable[web.StreamResponse]]:
    @web.middleware
    async def auth_middleware(request: web.Request, handler: _Handler) -> web.StreamResponse:
        if config.token is None or request.method == "OPTIONS" or request.path in PUBLIC_PATHS:
            return await handler(request)
        ingest = request.path in ingest_paths
        if ingest and config.allow_unauthenticated_ingest:
            return await handler(request)
        token = _request_token(request, ingest)
        if not token or not hmac.compare_digest(token.encode(), config.token.encode()):
            return web.json_response(
                {"error": "missing or invalid lapdog server token"}, status=401, headers=cors_headers(request)
            )
        return await handler(request)

    return auth_middleware
