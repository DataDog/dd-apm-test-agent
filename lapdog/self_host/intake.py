"""LLMObs span intake for ``lapdog server``.

Accepts both the agentless paths ddtrace uses with ``DD_LLMOBS_OVERRIDE_ORIGIN``
(``/api/v2/llmobs``) and the agent EVP-proxy paths (``/evp_proxy/v2/...``).
"""

import asyncio
import logging
from typing import Any
from typing import List
from typing import Optional
from typing import Set

import aiohttp
from aiohttp import web

from ddapm_test_agent.llmobs_trace import decode_llmobs_payload

from ..llmobs_event_platform import extract_span_updates
from ..llmobs_event_platform import extract_spans_from_events
from .clickhouse import ClickHouseError
from .config import ServerConfig
from .retention import ServerState
from .store import ClickHouseSpanBackend

log = logging.getLogger(__name__)

_SPAN_PREFIXES = ("", "/evp_proxy/v2", "/evp_proxy/v4")
SPAN_PATHS = [f"{prefix}/api/v2/llmobs" for prefix in _SPAN_PREFIXES]
UPDATE_PATHS = [f"{path}/update" for path in SPAN_PATHS]
EVAL_PATHS = [
    f"{prefix}/api/intake/llm-obs/{version}/eval-metric" for prefix in ("", "/evp_proxy/v2") for version in ("v1", "v2")
]
INGEST_PATHS = frozenset(SPAN_PATHS + UPDATE_PATHS + EVAL_PATHS)


class IntakeAPI:
    def __init__(self, store: ClickHouseSpanBackend, state: ServerState, config: ServerConfig) -> None:
        self.store = store
        self.state = state
        self.config = config
        self._session: Optional[aiohttp.ClientSession] = None
        self._forwards: Set["asyncio.Task[None]"] = set()

    @property
    def forwarding(self) -> bool:
        return self.config.forward_to_datadog and bool(self.config.dd_api_key)

    def _paused(self) -> Optional[web.Response]:
        if self.state.ingest_paused:
            return web.json_response(
                {"error": "lapdog server is at its disk cap; ingest is paused"},
                status=503,
                headers={"Retry-After": "300"},
            )
        return None

    async def handle_spans(self, request: web.Request) -> web.Response:
        paused = self._paused()
        if paused is not None:
            return paused
        data = await request.read()
        spans = extract_spans_from_events(decode_llmobs_payload(data, request.content_type or ""))
        try:
            await self.store.insert_spans(spans)
        except ClickHouseError as e:
            log.error("Failed to store %d spans: %s", len(spans), e)
            return web.json_response({"error": "failed to store spans"}, status=503)
        self._forward(data, request, f"https://llmobs-intake.{self.config.dd_site}/api/v2/llmobs")
        return web.json_response({})

    async def handle_update(self, request: web.Request) -> web.Response:
        paused = self._paused()
        if paused is not None:
            return paused
        data = await request.read()
        updates = extract_span_updates(decode_llmobs_payload(data, request.content_type or ""))
        try:
            updated = await self.store.update_spans(updates)
        except ClickHouseError as e:
            log.error("Failed to update spans: %s", e)
            return web.json_response({"error": "failed to update spans"}, status=503)
        self._forward(data, request, f"https://llmobs-intake.{self.config.dd_site}/api/v2/llmobs/update")
        return web.json_response({"updated": updated})

    async def handle_eval_metric(self, request: web.Request) -> web.Response:
        # Evaluations aren't stored yet; accept them so SDKs don't retry or log errors.
        data = await request.read()
        self._forward(data, request, f"https://api.{self.config.dd_site}/api/intake/llm-obs/v2/eval-metric")
        return web.json_response({})

    def _forward(self, data: bytes, request: web.Request, url: str) -> None:
        if not self.forwarding:
            return
        task = asyncio.ensure_future(self._send(data, request.headers.get("Content-Type", "application/json"), url))
        self._forwards.add(task)
        task.add_done_callback(self._forwards.discard)

    async def _send(self, data: bytes, content_type: str, url: str) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        try:
            async with self._session.post(
                url, data=data, headers={"Content-Type": content_type, "DD-API-KEY": self.config.dd_api_key}
            ) as resp:
                if resp.status >= 300:
                    log.warning("Forwarding to Datadog failed: %s %s", resp.status, (await resp.text())[:200])
        except aiohttp.ClientError as e:
            log.warning("Forwarding to Datadog failed: %s", e)

    async def close(self) -> None:
        if self._forwards:
            await asyncio.wait(list(self._forwards), timeout=5)
        if self._session is not None:
            await self._session.close()

    def get_routes(self) -> List[Any]:
        routes = [web.post(path, self.handle_spans) for path in SPAN_PATHS]
        routes += [web.post(path, self.handle_update) for path in UPDATE_PATHS]
        routes += [web.post(path, self.handle_eval_metric) for path in EVAL_PATHS]
        return routes
