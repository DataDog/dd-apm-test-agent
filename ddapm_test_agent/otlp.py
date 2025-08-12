from typing import Any
from typing import Awaitable
from typing import Callable

from aiohttp import ClientSession
from aiohttp import web
from aiohttp.web import HTTPException
from aiohttp.web import middleware
from aiohttp.web_request import Request
import grpc  # For StatusCode enums
from grpc import aio as grpc_aio
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse
from opentelemetry.proto.collector.logs.v1.logs_service_pb2_grpc import LogsServiceServicer
from opentelemetry.proto.collector.logs.v1.logs_service_pb2_grpc import add_LogsServiceServicer_to_server

from .utils import Handler
from .utils import session_token as _session_token


# Default ports
DEFAULT_OTLP_HTTP_PORT = 4318
DEFAULT_OTLP_GRPC_PORT = 4317


@middleware
async def session_token_middleware(request: Request, handler: Handler) -> web.Response:
    """Extract session token from the request and store it in the request.

    The token is retrieved from the headers or params of the request.
    """
    token = _session_token(request)
    request["session_token"] = token
    return await handler(request)


@middleware
async def handle_exception_middleware(request: Request, handler: Handler) -> web.Response:
    """Turn exceptions into 400s with the reason from the exception."""
    try:
        response = await handler(request)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise web.HTTPBadRequest(reason=str(e))


def make_otlp_http_app(agent: Any) -> web.Application:
    """Create a separate HTTP application for OTLP endpoints using the shared agent instance."""

    @middleware
    async def otlp_store_request_middleware(request: Request, handler: Handler) -> web.Response:
        # Always store requests for OTLP endpoints
        await agent._store_request(request)
        return await handler(request)

    app = web.Application(
        middlewares=[
            otlp_store_request_middleware,  # type: ignore
            session_token_middleware,  # type: ignore
            handle_exception_middleware,  # type: ignore
        ],
    )

    # Add only OTLP HTTP endpoints
    app.add_routes(
        [
            web.post("/v1/logs", agent.handle_v1_logs),
            web.get("/test/session/requests", agent.handle_session_requests),
            web.get("/test/session/logs", agent.handle_session_logs),
            web.get("/test/session/clear", agent.handle_session_clear),
            web.get("/test/session/start", agent.handle_session_start),
        ]
    )

    return app


async def make_otlp_grpc_server_async(agent: Any, http_port: int, grpc_port: int) -> grpc_aio.Server:
    """Create and start a separate GRPC server for OTLP endpoints that forwards to HTTP server."""
    server = grpc_aio.server()

    logs_servicer = OTLPLogsServicer(http_port)
    add_LogsServiceServicer_to_server(logs_servicer, server)

    listen_addr = f"[::]:{grpc_port}"
    server.add_insecure_port(listen_addr)
    await server.start()
    return server


class OTLPLogsServicer(LogsServiceServicer):  # type: ignore[misc]
    """GRPC servicer that forwards OTLP logs to HTTP server."""

    def __init__(self, http_port: int):
        self.http_port = http_port

    async def Export(self, request: ExportLogsServiceRequest, context: grpc_aio.ServicerContext) -> ExportLogsServiceResponse:  # type: ignore[name-defined]
        try:
            protobuf_data = request.SerializeToString()
            headers = {"Content-Type": "application/x-protobuf"}
            metadata = dict(context.invocation_metadata())
            if "session-token" in metadata:
                headers["Session-Token"] = metadata["session-token"]

            async with ClientSession() as session:
                async with session.post(
                    f"http://localhost:{self.http_port}/v1/logs", headers=headers, data=protobuf_data
                ) as resp:
                    if resp.status == 200:
                        return ExportLogsServiceResponse()  # type: ignore[name-defined]
                    if resp.status == 400:
                        await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid request")
                    await context.abort(grpc.StatusCode.INTERNAL, f"HTTP {resp.status}")
        except Exception as e:  # pragma: no cover - network failures
            await context.abort(grpc.StatusCode.INTERNAL, f"Forward failed: {str(e)}")
        # Unreachable; satisfy type checkers
        return ExportLogsServiceResponse()  # type: ignore[name-defined]
