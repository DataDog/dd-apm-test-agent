"""aiohttp application for ``lapdog server``."""

import asyncio
import contextlib
import logging
from typing import Any
from typing import AsyncIterator
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import Optional

from aiohttp import web

from ddapm_test_agent.cors import with_cors

from ..llmobs_event_platform import LLMObsEventPlatformAPI
from .auth import make_auth_middleware
from .clickhouse import CLICKHOUSE_VERSION
from .clickhouse import ClickHouseClient
from .clickhouse import ClickHouseProcess
from .config import ServerConfig
from .config import parse_settings_update
from .config import save_settings
from .config import settings_to_json
from .intake import INGEST_PATHS
from .intake import IntakeAPI
from .retention import RetentionEnforcer
from .retention import ServerState
from .schema import ensure_schema
from .store import ClickHouseSpanBackend

log = logging.getLogger(__name__)

CONFIG_KEY = "lapdog_server_config"
STATE_KEY = "lapdog_server_state"
STORE_KEY = "lapdog_server_store"
ENFORCER_KEY = "lapdog_server_enforcer"

_Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("ddapm-test-agent")
    except Exception:
        return "unknown"


@web.middleware
async def private_network_middleware(request: web.Request, handler: _Handler) -> web.StreamResponse:
    """Let the hosted UI (a public origin) reach a server on a private network address.

    Chrome's Private Network Access sends this preflight header and blocks the
    request unless the server opts in.
    """
    response = await handler(request)
    if request.method == "OPTIONS" and request.headers.get("Access-Control-Request-Private-Network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


class AdminAPI:
    def __init__(
        self,
        config: ServerConfig,
        state: ServerState,
        enforcer: RetentionEnforcer,
        intake: IntakeAPI,
        clickhouse: Optional[ClickHouseProcess],
    ) -> None:
        self.config = config
        self.state = state
        self.enforcer = enforcer
        self.intake = intake
        self.clickhouse = clickhouse

    async def handle_ping(self, request: web.Request) -> web.Response:
        return web.Response(text="ok")

    async def handle_info(self, request: web.Request) -> web.Response:
        # ddtrace reads ``endpoints`` to pick agent (EVP proxy) mode; the static app reads the rest.
        return web.json_response(
            {
                "version": _version(),
                "mode": "server",
                "endpoints": ["/evp_proxy/v2/", "/evp_proxy/v4/"],
                "auth_required": self.config.token is not None,
                "llmobs_data_forwarding": self.intake.forwarding,
                "authenticated": self.intake.forwarding,
            }
        )

    async def handle_status(self, request: web.Request) -> web.Response:
        status: Dict[str, Any] = {"settings": settings_to_json(self.state.settings)}
        status.update(await self.enforcer.status())
        ch = self.clickhouse
        status["clickhouse"] = {
            "version": CLICKHOUSE_VERSION,
            "pid": ch.pid if ch else None,
            "healthy": await self.enforcer.client.ping(),
            "restarts": ch.restarts if ch else 0,
        }
        status["forwarding_to_datadog"] = self.intake.forwarding
        return web.json_response(status)

    async def handle_settings(self, request: web.Request) -> web.Response:
        if request.method == "GET":
            return web.json_response(settings_to_json(self.state.settings))
        try:
            body = await request.json()
            settings = parse_settings_update(body, self.state.settings)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        action = await self.enforcer.apply_settings(settings)
        self.config.retention_days, self.config.max_disk_bytes = settings
        save_settings(self.config.data_dir, settings)
        return web.json_response({"settings": settings_to_json(settings), "enforcement": action})

    def get_routes(self) -> Any:
        return [
            web.get("/ping", self.handle_ping),
            web.route("*", "/info", with_cors(self.handle_info)),
            web.route("*", "/api/lapdog/server/status", with_cors(self.handle_status)),
            web.route("*", "/api/lapdog/server/settings", with_cors(self.handle_settings)),
        ]


def make_server_app(
    config: ServerConfig,
    client: ClickHouseClient,
    clickhouse: Optional[ClickHouseProcess] = None,
    enforce_interval: Optional[float] = None,
) -> web.Application:
    """Build the server app around a running ClickHouse.

    ``enforce_interval=None`` uses the default retention interval; ``0`` turns
    the background loop off (tests call ``enforce`` directly).
    """
    app = web.Application(
        client_max_size=64 * 1024 * 1024,
        middlewares=[private_network_middleware, make_auth_middleware(config, INGEST_PATHS)],
    )
    store = ClickHouseSpanBackend(client, config.database)
    state = ServerState(settings=config.settings)
    enforcer = RetentionEnforcer(client, config.database, state)
    intake = IntakeAPI(store, state, config)
    admin = AdminAPI(config, state, enforcer, intake, clickhouse)
    query_api = LLMObsEventPlatformAPI(backend=store)

    app[CONFIG_KEY] = config
    app[STATE_KEY] = state
    app[STORE_KEY] = store
    app[ENFORCER_KEY] = enforcer
    app.add_routes(admin.get_routes())
    app.add_routes(intake.get_routes())
    app.add_routes(query_api.get_routes())

    async def lifecycle(app: web.Application) -> AsyncIterator[None]:
        await ensure_schema(client, config.database, config.retention_days)
        tasks = []
        if enforce_interval != 0:
            tasks.append(asyncio.ensure_future(enforcer.run(enforce_interval or 300)))
        if clickhouse is not None:
            tasks.append(asyncio.ensure_future(clickhouse.supervise(on_restart=enforcer.trigger)))
        yield
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        await intake.close()
        await client.close()

    app.cleanup_ctx.append(lifecycle)
    return app
