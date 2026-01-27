"""
LLM Observability Event Platform API
Provides Datadog Event Platform compatible endpoints for LLM Observability data.
This allows the Datadog UI to redirect requests to the test agent for local development.
"""

import functools
import logging
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import List
import uuid

from aiohttp import web
from aiohttp.web import Request

log = logging.getLogger(__name__)

# CORS headers for cross-origin requests from Datadog UI
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": (
        "Content-Type, Accept, X-Requested-With, x-csrf-token, X-CSRF-Token, "
        "Authorization, X-DD-Api-Key, X-DD-Application-Key, x-web-ui-version, "
        "X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, "
        "Origin, Referer"
    ),
}

Handler = Callable[[Request], Awaitable[web.Response]]


def with_cors(handler: Handler) -> Handler:
    """Wrap a handler to add CORS headers and handle OPTIONS preflight requests."""

    @functools.wraps(handler)
    async def wrapper(request: Request) -> web.Response:
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=CORS_HEADERS)
        response = await handler(request)
        response.headers.update(CORS_HEADERS)
        return response

    return wrapper


class LLMObsEventPlatformAPI:
    """API handler for LLM Observability Event Platform endpoints."""

    def __init__(self, agent: Any):
        self.agent = agent

    async def handle_logs_analytics_list(self, request: Request) -> web.Response:
        return web.json_response(
            {
                "data": [],
                "meta": {
                    "page": {"after": None},
                    "status": "done",
                    "request_id": "stub-request-id",
                    "elapsed": 0,
                },
            }
        )

    async def handle_logs_analytics_get(self, request: Request) -> web.Response:
        return web.json_response(
            {
                "data": [],
                "meta": {
                    "page": {"after": None},
                    "status": "done",
                    "request_id": request.match_info.get("request_id", "stub-request-id"),
                    "elapsed": 0,
                },
            }
        )

    async def handle_aggregate(self, request: Request) -> web.Response:
        try:
            body = await request.json()
            log.debug(f"aggregate request: {body}")
        except Exception:
            pass

        return web.json_response(
            {
                "elapsed": 50,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "buckets": [],
                    "count": 0,
                    "status": "done",
                },
                "status": "done",
                "type": "aggregate",
            }
        )

    async def handle_facet_info(self, request: Request) -> web.Response:
        return web.json_response({"data": []})

    async def handle_facet_range_info(self, request: Request) -> web.Response:
        try:
            body = await request.json()
            log.debug(f"facet_range_info request: {body}")

            facet_range_info = body.get("facet_range_info", {})
            facet_path = facet_range_info.get("path", "")
            log.debug(f"facet_range_info response for {facet_path}: min=0, max=0")
        except Exception as e:
            log.error(f"Error handling facet range info: {e}")

        return web.json_response(
            {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "min": 0,
                    "max": 0,
                    "status": "done",
                },
                "status": "done",
            }
        )

    async def handle_facets_list(self, request: Request) -> web.Response:
        return web.json_response({"data": []})

    async def handle_fetch_one(self, request: Request) -> web.Response:
        return web.json_response(
            {
                "data": None,
                "meta": {
                    "status": "done",
                    "request_id": "stub-request-id",
                    "elapsed": 0,
                },
            }
        )

    async def handle_trace(self, request: Request) -> web.Response:
        trace_id = request.match_info.get("trace_id", "")
        log.info(f"handle_trace called for trace_id={trace_id}")

        return web.json_response(
            {
                "data": {
                    "trace_id": trace_id,
                    "spans": [],
                },
            }
        )

    async def handle_query_scalar(self, request: Request) -> web.Response:
        try:
            body = await request.json()
            log.debug(f"query/scalar request: {body}")
        except Exception:
            pass

        return web.json_response(
            {
                "data": [
                    {
                        "type": "scalar_response",
                        "attributes": {"columns": []},
                    }
                ],
            }
        )

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API with CORS handling."""
        routes = [
            # Event Platform facets endpoint
            ("/api/ui/event-platform/llmobs/facets", "GET", self.handle_facets_list),
            # LLM Obs Query Rewriter endpoints (unstable API)
            ("/api/unstable/llm-obs-query-rewriter/list", "POST", self.handle_logs_analytics_list),
            ("/api/unstable/llm-obs-query-rewriter/list/{request_id}", "GET", self.handle_logs_analytics_get),
            ("/api/unstable/llm-obs-query-rewriter/aggregate", "POST", self.handle_aggregate),
            ("/api/unstable/llm-obs-query-rewriter/facet_info", "POST", self.handle_facet_info),
            ("/api/unstable/llm-obs-query-rewriter/facet_range_info", "POST", self.handle_facet_range_info),
            ("/api/unstable/llm-obs-query-rewriter/fetch_one", "POST", self.handle_fetch_one),
            # Logs Analytics endpoints (stable API)
            ("/api/v1/logs-analytics/list", "POST", self.handle_logs_analytics_list),
            ("/api/v1/logs-analytics/list/{request_id}", "GET", self.handle_logs_analytics_get),
            ("/api/v1/logs-analytics/aggregate", "POST", self.handle_aggregate),
            ("/api/v1/logs-analytics/fetch_one", "POST", self.handle_fetch_one),
            # LLM Obs trace endpoint
            ("/api/ui/llm-obs/v1/trace/{trace_id}", "GET", self.handle_trace),
            # Query scalar endpoint (used by histogram visualizations)
            ("/api/ui/query/scalar", "POST", self.handle_query_scalar),
        ]

        route_defs = []
        for path, method, handler in routes:
            wrapped = with_cors(handler)
            if method == "GET":
                route_defs.append(web.get(path, wrapped))
            elif method == "POST":
                route_defs.append(web.post(path, wrapped))
            # Always add OPTIONS for CORS preflight
            route_defs.append(web.options(path, wrapped))

        return route_defs
