"""Sending traces from lapdog's memory to a Self-hosted ``lapdog server`` as well.

Every trace lands in lapdog's in-memory store first. Every LLMObs payload an
instrumented app sends is then re-posted to the server; coding-agent sessions
only if the user opts in. Sending is best effort: there's no queue, so spans
sent while the server is down are lost, and the error is shown.

The Self-hosted server setting lives in ``~/.lapdog/forwarding.json``.
"""

import asyncio
from collections import OrderedDict
from collections import deque
import gzip
import json
import logging
import os
import time
from typing import Any
from typing import Deque
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Tuple
from urllib.parse import urlsplit

from aiohttp import ClientError
from aiohttp import ClientSession
from aiohttp import ClientTimeout
from aiohttp import web
import msgpack

from ddapm_test_agent.cors import ALLOWED_ORIGIN_PATTERN
from ddapm_test_agent.llmobs_trace import decode_llmobs_payload

from .paths import FORWARDING_CONFIG_FILE

log = logging.getLogger(__name__)

_WINDOW_SECONDS = 3600
_HEALTH_INTERVAL = 30.0
# While the UI polls /info, check the server this often, so a server going down shows within seconds.
_FRESH_HEALTH = 3.0
_HEALTH_TIMEOUT = 3.0
_SPANS_PATH = "/evp_proxy/v2/api/v2/llmobs"
_MAX_SPANS_PER_REQUEST = 20
# Spans remembered as stored on the Self-hosted server, so searches don't count them twice.
_MAX_FORWARDED_KEYS = 200_000


class ForwardingConfig(NamedTuple):
    self_hosted: Optional[str] = None
    # Coding-agent sessions (Claude Code, Codex, pi) go to the Self-hosted server only when opted in.
    self_hosted_coding_agents: bool = False


def normalize_server_url(raw: str) -> Optional[str]:
    """Return ``scheme://host[:port][/path]`` without a trailing slash, or None if it isn't a plain http(s) URL."""
    text = (raw or "").strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.query or parts.fragment or parts.username or parts.password:
        return None
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")


async def _probe_server(session: ClientSession, server: str) -> Tuple[Optional[str], Optional[int]]:
    """Ask ``server`` for its ``/info``: return what's wrong (None if it's a lapdog server) and its retention days."""
    try:
        async with session.get(f"{server}/info", timeout=ClientTimeout(total=_HEALTH_TIMEOUT)) as resp:
            info = await resp.json(content_type=None)
            status = resp.status
    except (ClientError, asyncio.TimeoutError, OSError):
        return f"Can't reach {server}", None
    except ValueError:
        return f"{server} isn't a lapdog server", None
    if status != 200 or not isinstance(info, dict) or info.get("mode") != "server":
        return f"{server} isn't a lapdog server", None
    days = info.get("retention_days")
    return None, days if isinstance(days, int) else None


def forwarding_config_path() -> str:
    return os.environ.get("LAPDOG_FORWARDING_CONFIG", FORWARDING_CONFIG_FILE)


def load_forwarding_config(path: Optional[str] = None) -> ForwardingConfig:
    path = path or forwarding_config_path()
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return ForwardingConfig()
    if not isinstance(data, dict):
        return ForwardingConfig()
    server = normalize_server_url(data.get("self_hosted") or "")
    return ForwardingConfig(server, bool(data.get("self_hosted_coding_agents")))


def save_forwarding_config(config: ForwardingConfig, path: Optional[str] = None) -> None:
    path = path or forwarding_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(config._asdict(), f, indent=2)
    os.replace(tmp, path)


def payload_span_keys(body: bytes, content_type: str) -> List[Tuple[str, str]]:
    """Return ``(trace_id, span_id)`` for each span in an LLMObs payload."""
    try:
        events = decode_llmobs_payload(body, content_type)
    except Exception:
        return []
    if isinstance(events, dict):
        events = [events]
    keys = []
    for event in events if isinstance(events, list) else []:
        spans = event.get("spans") if isinstance(event, dict) else None
        for span in spans if isinstance(spans, list) else []:
            if isinstance(span, dict):
                keys.append((str(span.get("trace_id", "")), str(span.get("span_id", ""))))
    return keys


def _remember(seen: "OrderedDict[Tuple[str, str], None]", keys: List[Tuple[str, str]]) -> None:
    for key in keys:
        seen[key] = None
    while len(seen) > _MAX_FORWARDED_KEYS:
        seen.popitem(last=False)


class DestinationStats:
    """Spans sent to one destination over the last hour, plus its latest error."""

    def __init__(self) -> None:
        self._sent: Deque[Tuple[float, int]] = deque()
        self.failed_requests = 0
        self.last_error: Optional[str] = None
        self.last_sent_at: Optional[float] = None
        self._error_was_unreachable = False

    def record(self, spans: int, ok: bool, error: str = "", unreachable: bool = False) -> None:
        now = time.time()
        if ok:
            self._sent.append((now, spans))
            self.last_sent_at = now
            self.last_error = None
        else:
            self.failed_requests += 1
            self.last_error = error[:300] or "request failed"
            self._error_was_unreachable = unreachable
        self._trim(now)

    def clear_unreachable_error(self) -> None:
        """Forget an error from not reaching the destination, which answers again."""
        if self._error_was_unreachable:
            self.last_error = None
            self._error_was_unreachable = False

    def _trim(self, now: float) -> None:
        while self._sent and self._sent[0][0] < now - _WINDOW_SECONDS:
            self._sent.popleft()

    def to_json(self) -> Dict[str, Any]:
        self._trim(time.time())
        return {
            "spans_last_hour": sum(n for _, n in self._sent),
            "failed_requests": self.failed_requests,
            "last_error": self.last_error,
            "last_sent_at": self.last_sent_at,
        }


class Forwarding:
    def __init__(self, config: ForwardingConfig) -> None:
        self.self_hosted: Optional[str] = None
        self.self_hosted_coding_agents = False
        self.self_hosted_stats = DestinationStats()
        self.self_hosted_reachable: Optional[bool] = None
        self.self_hosted_retention_days: Optional[int] = None
        self._forwarded: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        self._session: Optional[ClientSession] = None
        self._tasks: Set["asyncio.Future[None]"] = set()
        # Span posts still in flight; an update waits for them so it never reaches the server before its span.
        self._span_posts: Set["asyncio.Future[None]"] = set()
        self._health_task: Optional["asyncio.Task[None]"] = None
        self._last_health_check = 0.0
        self._health_checking = False
        self.configure_self_hosted(config.self_hosted, config.self_hosted_coding_agents)

    # -- configuration -----------------------------------------------------

    def configure_self_hosted(self, server: Optional[str], coding_agents: bool) -> None:
        if server != self.self_hosted:
            self.self_hosted_stats = DestinationStats()
            self._forwarded.clear()
            self.self_hosted_reachable = None
            self.self_hosted_retention_days = None
        self.self_hosted = server
        self.self_hosted_coding_agents = coding_agents
        if server and self._session is not None:
            self._spawn(self._check_self_hosted())

    def is_forwarded(self, span: Dict[str, Any]) -> bool:
        """Whether this span is stored on the Self-hosted server (so searches read it from there)."""
        return (str(span.get("trace_id", "")), str(span.get("span_id", ""))) in self._forwarded

    def info(self) -> Dict[str, Any]:
        """``/info``'s ``forwarding`` block, which the lapdog UI draws as the forwarding flow."""
        # Someone is looking: refresh reachability in the background, for their next poll.
        stale = time.monotonic() - self._last_health_check >= _FRESH_HEALTH
        if self.self_hosted and self._session is not None and stale and not self._health_checking:
            self._spawn(self._check_self_hosted())
        self_hosted: Dict[str, Any] = {
            "enabled": bool(self.self_hosted),
            "url": self.self_hosted,
            "coding_agents": self.self_hosted_coding_agents,
            "reachable": self.self_hosted_reachable,
            "retention_days": self.self_hosted_retention_days,
            **self.self_hosted_stats.to_json(),
        }
        return {"forwarding": {"self_hosted": self_hosted}}

    # -- lifecycle ---------------------------------------------------------

    async def start(self, app: web.Application) -> None:
        self._session = ClientSession(timeout=ClientTimeout(total=10))
        self._health_task = asyncio.ensure_future(self._health_loop())

    async def stop(self, app: web.Application) -> None:
        if self._health_task is not None:
            self._health_task.cancel()
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=5)
        if self._session is not None:
            await self._session.close()

    def _spawn(self, coro: Any) -> "asyncio.Future[None]":
        task: "asyncio.Future[None]" = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _spawn_post(self, path: str, body: bytes, content_type: str) -> None:
        if path.rstrip("/").endswith("/update"):
            self._spawn(self._post_after(list(self._span_posts), path, body, content_type))
            return
        task = self._spawn(self._post_self_hosted(path, body, content_type))
        self._span_posts.add(task)
        task.add_done_callback(self._span_posts.discard)

    async def _post_after(
        self, earlier: List["asyncio.Future[None]"], path: str, body: bytes, content_type: str
    ) -> None:
        if earlier:
            await asyncio.wait(earlier)
        await self._post_self_hosted(path, body, content_type)

    # -- traffic -----------------------------------------------------------

    def on_llmobs_payload(self, path: str, body: bytes, content_type: str) -> None:
        """``Agent.llmobs_payload_listener``: send what instrumented apps send to the Self-hosted server too."""
        if self.self_hosted and self._session is not None:
            self._spawn_post(path, body, content_type or "application/msgpack")

    def forward_coding_agent_spans(self, spans: List[Dict[str, Any]]) -> None:
        """Send a finished coding-agent trace to the Self-hosted server, if the user opted in."""
        if not (self.self_hosted and self.self_hosted_coding_agents and self._session is not None and spans):
            return
        for start in range(0, len(spans), _MAX_SPANS_PER_REQUEST):
            chunk = spans[start : start + _MAX_SPANS_PER_REQUEST]
            body = msgpack.packb({"_dd.stage": "raw", "event_type": "span", "spans": chunk}, use_bin_type=True)
            self._spawn_post(_SPANS_PATH, body, "application/msgpack")

    async def _post_self_hosted(self, path: str, body: bytes, content_type: str) -> None:
        server, session = self.self_hosted, self._session
        if not server or session is None:
            return
        keys = payload_span_keys(body, content_type)
        spans = len(keys)
        # ``body`` arrives decompressed; send it compressed with a matching header.
        headers = {"Content-Type": content_type, "Content-Encoding": "gzip"}
        try:
            async with session.post(f"{server}{path}", data=gzip.compress(body), headers=headers) as resp:
                text = await resp.text()
            ok = resp.status < 300
            error = "" if ok else f"HTTP {resp.status}: {text}"
            reachable: Optional[bool] = True
        except (ClientError, asyncio.TimeoutError, OSError) as e:
            ok, error, reachable = False, f"can't reach {server}: {e.__class__.__name__}", False
        if server == self.self_hosted:
            self.self_hosted_stats.record(spans, ok, error, unreachable=reachable is False)
            self.self_hosted_reachable = reachable
            if ok:
                _remember(self._forwarded, keys)
        if not ok:
            log.warning("Failed to forward %d spans to the Self-hosted server: %s", spans, error)

    async def _check_self_hosted(self) -> None:
        server, session = self.self_hosted, self._session
        if not server or session is None:
            return
        self._health_checking = True
        self._last_health_check = time.monotonic()
        try:
            problem, days = await _probe_server(session, server)
        finally:
            self._health_checking = False
        if server == self.self_hosted:
            self._record_health(problem is None, days)

    def _record_health(self, reachable: bool, days: Optional[int]) -> None:
        self.self_hosted_reachable = reachable
        self.self_hosted_retention_days = days
        if reachable:
            self.self_hosted_stats.clear_unreachable_error()

    async def _probe(self, server: str) -> Tuple[Optional[str], Optional[int]]:
        if self._session is not None:
            return await _probe_server(self._session, server)
        async with ClientSession() as session:
            return await _probe_server(session, server)

    async def _health_loop(self) -> None:
        while True:
            await self._check_self_hosted()
            await asyncio.sleep(_HEALTH_INTERVAL)

    # -- API -----------------------------------------------------------------

    async def handle_forwarding(self, request: web.Request) -> web.Response:
        """GET the forwarding state, or POST ``{self_hosted, self_hosted_coding_agents}`` to change it.

        The lapdog UI and ``lapdog forward`` both use this. Changes need a JSON body and, from a
        browser, an allowed origin, so other web pages can't redirect your traces.
        """
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin is not None and not ALLOWED_ORIGIN_PATTERN.match(origin):
                return web.json_response({"error": "origin not allowed"}, status=403)
            if request.content_type != "application/json":
                return web.json_response({"error": "expected application/json"}, status=415)
            try:
                body = await request.json()
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return web.json_response({"error": "expected a JSON object"}, status=400)
            if "self_hosted" in body or "self_hosted_coding_agents" in body:
                raw = body.get("self_hosted", self.self_hosted)
                server = normalize_server_url(raw) if raw else None
                if raw and server is None:
                    return web.json_response({"error": f"not an http(s) URL: {raw}"}, status=400)
                days: Optional[int] = None
                if server is not None and server != self.self_hosted:
                    # Only accept a new server that answers as one, so a typo can't silently drop traces.
                    problem, days = await self._probe(server)
                    if problem is not None:
                        return web.json_response({"error": problem}, status=400)
                coding_agents = bool(body.get("self_hosted_coding_agents", self.self_hosted_coding_agents))
                changed = server != self.self_hosted
                self.configure_self_hosted(server, coding_agents)
                if server is not None and changed:
                    self._record_health(True, days)
                save_forwarding_config(ForwardingConfig(server, coding_agents))
        return web.json_response(self.info()["forwarding"])
