"""Answer the lapdog UI's searches from this lapdog's memory *and* the Self-hosted server.

With Self-hosted forwarding on, a span lives in one place for search purposes:
spans this lapdog forwarded successfully are read from the Self-hosted server
(which also has everyone else's), and everything else (traces from before
forwarding was on, coding-agent sessions that stay local) is read from memory.
The two sets don't overlap, so results are merged without double counting:

- lists are merged in time order, with a cursor that tracks both sides;
- aggregate groups, facet counts, and scalar rows are combined by key
  (sums and counts add up exactly; averages and percentiles across both
  sides are approximate);
- a trace or span is read from whichever side has it.

Each listed span is labelled with where it was read from (``@lapdog.source``:
``laptop`` or ``self-hosted``) and whether Datadog accepted it from this
lapdog (``@lapdog.in_datadog``), so the UI can show where each trace lives.
Lists answered from memory alone are labelled too.

If the Self-hosted server can't be reached, answers come from memory alone
(including forwarded spans), as if forwarding were off.
"""

import asyncio
import base64
import binascii
import copy
import json
import logging
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Tuple
import uuid

from aiohttp import ClientError
from aiohttp import ClientTimeout
from aiohttp import web

from ddapm_test_agent.cors import cors_headers
from ddapm_test_agent.cors import with_cors

from .forwarding import Forwarding
from .llmobs_event_platform import InMemorySpanBackend
from .llmobs_event_platform import LLMObsEventPlatformAPI
from .llmobs_event_platform import build_event_platform_list_response
from .llmobs_event_platform import parse_list_params

log = logging.getLogger(__name__)

_Handler = Callable[[web.Request], Awaitable[web.StreamResponse]]
_CURSOR_PREFIX = "fed."
_END = "end"
_MAX_STORED_RESULTS = 200


class _SelfHostedUnavailable(Exception):
    pass


class LocalOnlyBackend(InMemorySpanBackend):
    """This lapdog's in-memory spans, minus the ones the Self-hosted server already has."""

    def __init__(self, inner: InMemorySpanBackend, is_forwarded: Callable[[Dict[str, Any]], bool]) -> None:
        super().__init__(inner.agent)
        self._inner = inner
        self._is_forwarded = is_forwarded
        self._locally_priced_spans = inner._locally_priced_spans

    def get_llmobs_spans(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        return [s for s in self._inner.get_llmobs_spans(token) if not self._is_forwarded(s)]


class _Cursor(NamedTuple):
    local: Optional[str]
    remote: Optional[str]


def _decode_cursor(paging: Any) -> _Cursor:
    after = paging.get("after") if isinstance(paging, dict) else None
    if not after:
        return _Cursor(None, None)
    if not isinstance(after, str) or not after.startswith(_CURSOR_PREFIX):
        raise ValueError("Invalid list paging cursor")
    try:
        data = json.loads(base64.urlsafe_b64decode(after[len(_CURSOR_PREFIX) :].encode()).decode())
        return _Cursor(data.get("l"), data.get("r"))
    except (ValueError, UnicodeError, binascii.Error, AttributeError) as exc:
        raise ValueError("Invalid list paging cursor") from exc


def _encode_cursor(cursor: _Cursor) -> str:
    raw = json.dumps({"l": cursor.local, "r": cursor.remote}, separators=(",", ":")).encode()
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(raw).decode()


def _event_key(event: Dict[str, Any]) -> Tuple[int, str, str]:
    custom = event.get("event", {}).get("custom", {})
    return int(custom.get("start_ns", 0) or 0), str(custom.get("trace_id", "")), str(custom.get("span_id", ""))


def _span_cursor(key: Tuple[int, str, str]) -> str:
    """Return a cursor that continues after ``key``, in the format both backends' list paging accepts."""
    return base64.urlsafe_b64encode(json.dumps([*key, 0], separators=(",", ":")).encode()).decode()


def _next_side_cursor(
    events: List[Dict[str, Any]], taken: List[Dict[str, Any]], previous: Optional[str], side_next: Optional[str]
) -> str:
    if len(taken) < len(events):
        # Some of this side's page didn't make the merged page: resume right after the last one used.
        return _span_cursor(_event_key(taken[-1])) if taken else (previous or "")
    return side_next or _END


def _merge_metric(aggregation: Optional[str], a: Any, b: Any) -> Any:
    if isinstance(a, list) and isinstance(b, list):
        return a + b
    if not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return a if a not in ("", None) else b
    if aggregation == "min":
        return min(a, b)
    if aggregation == "max":
        return max(a, b)
    if aggregation == "avg":
        return (a + b) / 2
    return a + b


def _merge_scalar_columns(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine two scalar responses' columns; rows with the same group values add up."""
    if not a:
        return b
    if not b:
        return a
    group_names = [c["name"] for c in a if c.get("type") == "group"]
    number_names = [c["name"] for c in a if c.get("type") != "group"]
    rows: Dict[Tuple[str, ...], Dict[str, float]] = {}
    for columns in (a, b):
        by_name = {c["name"]: c for c in columns}
        if any(name not in by_name for name in group_names + number_names):
            continue
        row_count = len(by_name[number_names[0]]["values"]) if number_names else 0
        for i in range(row_count):
            key = tuple(json.dumps(by_name[g]["values"][i]) for g in group_names)
            row = rows.setdefault(key, {name: 0.0 for name in number_names})
            for name in number_names:
                value = by_name[name]["values"][i]
                row[name] += value if isinstance(value, (int, float)) else 0
    merged = []
    for g_index, name in enumerate(group_names):
        merged.append({**next(c for c in a if c["name"] == name), "values": [json.loads(k[g_index]) for k in rows]})
    for name in number_names:
        merged.append({**next(c for c in a if c["name"] == name), "values": [row[name] for row in rows.values()]})
    return merged


class FederatedSearch:
    def __init__(self, full_api: LLMObsEventPlatformAPI, forwarding: Forwarding) -> None:
        self.full_api = full_api
        self.forwarding = forwarding
        self.local_api = LLMObsEventPlatformAPI(backend=LocalOnlyBackend(full_api._memory, forwarding.is_forwarded))
        self._results: Dict[str, Dict[str, Any]] = {}

    def get_routes(self) -> List[web.RouteDef]:
        """Return the query routes, searching memory and the Self-hosted server while forwarding there is on."""
        kinds = {
            "list": self._list,
            "aggregate": self._aggregate,
            "facet_info": self._facet_info,
            "facet_range_info": self._facet_range,
            "scalar": self._scalar,
            "fetch_one": self._fetch_one,
        }
        routes = []
        for route in self.full_api.get_routes():
            path = route.path
            last = path.rstrip("/").split("/")[-1]
            # Lists answered from memory alone still get their rows labelled.
            if last in ("list", "{request_id}"):
                local_handler = self._labelled_local(route.handler)
            else:
                local_handler = route.handler
            if path.startswith("/api/ui/llm-obs/v1/trace/"):
                federated: Optional[_Handler] = self._trace
            elif path.endswith("/{request_id}"):
                federated = self._stored_list
            else:
                federated = kinds.get(last)
            handler = local_handler if federated is None else self._wrap(local_handler, federated)
            routes.append(web.route(route.method, path, handler, **route.kwargs))
        return routes

    def _labelled_local(self, local_handler: _Handler) -> _Handler:
        """Answer a list from memory, labelling each row as this laptop's."""

        async def handler(request: web.Request) -> web.StreamResponse:
            response = await local_handler(request)
            if not isinstance(response, web.Response) or response.status != 200 or response.text is None:
                return response
            try:
                data = json.loads(response.text)
            except ValueError:
                return response
            for event in (data.get("result") or {}).get("events", []) if isinstance(data, dict) else []:
                self._label(event, "laptop")
            response.text = json.dumps(data)
            return response

        return handler

    def _wrap(self, local_handler: _Handler, federated: _Handler) -> _Handler:
        federated_with_cors = with_cors(federated)

        async def handler(request: web.Request) -> web.StreamResponse:
            if not self.forwarding.self_hosted or request.method == "OPTIONS":
                return await local_handler(request)
            try:
                return await federated_with_cors(request)
            except _SelfHostedUnavailable:
                return await local_handler(request)
            except ValueError as exc:
                return web.json_response({"error": str(exc)}, status=400, headers=cors_headers(request))

        return handler

    # -- talking to both sides -----------------------------------------------

    async def _remote(self, request: web.Request, body: Optional[bytes] = None, lookup: bool = False) -> Any:
        """Ask the Self-hosted server the same question; for a ``lookup`` (one trace or span), 404 means "not here"."""
        session, server = self.forwarding._session, self.forwarding.self_hosted
        if session is None or not server:
            raise _SelfHostedUnavailable
        headers = {"Content-Type": request.headers.get("Content-Type", "application/json")}
        data = body if body is not None else await request.read()
        try:
            async with session.request(
                request.method,
                f"{server}{request.path_qs}",
                data=data or None,
                headers=headers,
                timeout=ClientTimeout(total=15),
            ) as resp:
                if resp.status == 404 and lookup:
                    return None
                if resp.status >= 400:
                    raise _SelfHostedUnavailable
                return await resp.json(content_type=None)
        except (ClientError, OSError, ValueError, asyncio.TimeoutError) as e:
            log.warning("Searching the Self-hosted server failed, using this lapdog's memory only: %s", e)
            raise _SelfHostedUnavailable from e

    @staticmethod
    async def _local(handler: _Handler, request: web.Request) -> Any:
        response = await handler(request)
        if not isinstance(response, web.Response) or response.status == 404 or response.text is None:
            return None
        data = json.loads(response.text)
        if response.status >= 400:
            raise ValueError(data.get("error", "invalid request"))
        return data

    # -- endpoints -----------------------------------------------------------

    async def _list(self, request: web.Request) -> web.Response:
        body = await request.json()
        params = parse_list_params(body)
        cursor = _decode_cursor(params.paging)

        local_events: List[Dict[str, Any]] = []
        local_next: Optional[str] = None
        local_hits = 0
        if cursor.local != _END:
            page = await self.local_api.backend.list_spans(
                params.query,
                params.limit,
                {"after": cursor.local} if cursor.local else None,
                params.sort_order,
                time_window=params.time_window,
            )
            built = build_event_platform_list_response(
                page.spans,
                "",
                params.limit,
                paging=page.next_paging,
                hit_count=page.hit_count,
                children_by_trace=page.children_by_trace,
                trace_aggregates=page.trace_aggregates,
            )
            local_events = built["result"]["events"]
            local_next = (page.next_paging or {}).get("after")
            local_hits = page.hit_count

        remote_events: List[Dict[str, Any]] = []
        remote_next: Optional[str] = None
        remote_hits = 0
        if cursor.remote != _END:
            remote_body = copy.deepcopy(body)
            list_params = remote_body.setdefault("list", {})
            if cursor.remote:
                list_params["paging"] = {"after": cursor.remote}
            else:
                list_params.pop("paging", None)
            remote = await self._remote(request, json.dumps(remote_body).encode()) or {}
            remote_events = remote.get("result", {}).get("events", [])
            remote_next = (remote.get("result", {}).get("paging") or {}).get("after")
            remote_hits = int(remote.get("hitCount", len(remote_events)))

        for events, source in ((remote_events, "self-hosted"), (local_events, "laptop")):
            for event in events:
                self._label(event, source)

        descending = params.sort_order != "asc"
        tagged = [(e, "remote") for e in remote_events] + [(e, "local") for e in local_events]
        tagged.sort(key=lambda item: _event_key(item[0]), reverse=descending)
        taken = tagged[: params.limit]
        taken_remote = [e for e, side in taken if side == "remote"]
        taken_local = [e for e, side in taken if side == "local"]

        next_cursor = _Cursor(
            _next_side_cursor(local_events, taken_local, cursor.local, local_next) if cursor.local != _END else _END,
            (
                _next_side_cursor(remote_events, taken_remote, cursor.remote, remote_next)
                if cursor.remote != _END
                else _END
            ),
        )
        request_id = str(uuid.uuid4())
        result: Dict[str, Any] = {"events": [e for e, _ in taken], "count": len(taken)}
        if next_cursor != _Cursor(_END, _END):
            result["paging"] = {"after": _encode_cursor(next_cursor)}
        response = {
            "elapsed": 23,
            "hitCount": local_hits + remote_hits,
            "requestId": request_id,
            "result": result,
            "status": "done",
            "type": "status",
        }
        self._results[request_id] = response
        while len(self._results) > _MAX_STORED_RESULTS:
            self._results.pop(next(iter(self._results)))
        return web.json_response(response)

    def _label(self, event: Dict[str, Any], source: str) -> None:
        custom = event.get("event", {}).get("custom")
        if not isinstance(custom, dict):
            return
        trace_id, span_id = str(custom.get("trace_id", "")), str(custom.get("span_id", ""))
        custom["lapdog"] = {"source": source, "in_datadog": self.forwarding.is_in_datadog(trace_id, span_id)}

    async def _stored_list(self, request: web.Request) -> web.Response:
        request_id = request.match_info.get("request_id", "")
        if request_id in self._results:
            return web.json_response(self._results[request_id])
        raise _SelfHostedUnavailable  # not a federated result; let the local handler answer

    async def _aggregate(self, request: web.Request) -> web.Response:
        body = await request.json()
        agg = body.get("aggregate", {}) if isinstance(body, dict) else {}
        local = await self._local(self.local_api.handle_aggregate, request) or {}
        remote = await self._remote(request) or {}

        field = ((agg.get("groupBy") or [{}])[0] or {}).get("field", {}) or {}
        output = field.get("output", str(field.get("id", "")).lstrip("@"))
        limit = int(field.get("limit", 50)) if agg.get("groupBy") else 1
        descending = ((field.get("sort") or {}).get("metric") or {}).get("order", "desc") != "asc"
        aggregations = {
            c["total"].get("output"): c["total"].get("aggregation") for c in agg.get("compute", []) if "total" in c
        }

        merged: Dict[str, Dict[str, Any]] = {}
        for value in remote.get("result", {}).get("values", []) + local.get("result", {}).get("values", []):
            key = json.dumps(value.get("by"), sort_keys=True)
            if key not in merged:
                merged[key] = copy.deepcopy(value)
                continue
            into = merged[key]
            for name, metric in value.get("metrics", {}).items():
                into["metrics"][name] = _merge_metric(aggregations.get(name), into["metrics"].get(name), metric)
            if "_order_ns" in value:
                pick = max if descending else min
                into["_order_ns"] = pick(into.get("_order_ns", value["_order_ns"]), value["_order_ns"])
        ordered = sorted(merged.values(), key=lambda v: int(v.get("_order_ns", 0)), reverse=descending)
        page = ordered[:limit]
        result: Dict[str, Any] = {"values": page}
        side_has_more = bool(local.get("result", {}).get("paging") or remote.get("result", {}).get("paging"))
        if output and (len(ordered) > limit or side_has_more):
            seen = list(((agg.get("paging") or {}).get("after") or {}).get(output, []))
            result["paging"] = {"after": {output: seen + [str(v.get("by", {}).get(output)) for v in page]}}
        return web.json_response(
            {"elapsed": 50, "requestId": "federated", "result": result, "status": "done", "type": "aggregate"}
        )

    async def _facet_info(self, request: web.Request) -> web.Response:
        body = await request.json()
        limit = int((body.get("facet_info") or {}).get("limit", 10)) if isinstance(body, dict) else 10
        local = await self._local(self.local_api.handle_facet_info, request) or {}
        remote = await self._remote(request) or {}
        counts: Dict[str, int] = {}
        for item in remote.get("result", {}).get("fields", []) + local.get("result", {}).get("fields", []):
            counts[str(item.get("field"))] = counts.get(str(item.get("field")), 0) + int(item.get("value", 0))
        fields = [{"field": f, "value": c} for f, c in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]]
        result = {"fields": fields, "status": "done"}
        return web.json_response({"elapsed": 10, "requestId": "federated", "result": result, "status": "done"})

    async def _facet_range(self, request: web.Request) -> web.Response:
        local = await self._local(self.local_api.handle_facet_range_info, request) or {}
        remote = await self._remote(request) or {}
        ranges = [
            (r["min"], r["max"])
            for r in (local.get("result", {}), remote.get("result", {}))
            if "min" in r and (r["min"], r["max"]) != (0, 0)
        ]
        lo, hi = (min(r[0] for r in ranges), max(r[1] for r in ranges)) if ranges else (0, 0)
        result = {"min": lo, "max": hi, "status": "done"}
        return web.json_response({"elapsed": 10, "requestId": "federated", "result": result, "status": "done"})

    async def _scalar(self, request: web.Request) -> web.Response:
        local = await self._local(self.local_api.handle_query_scalar, request) or {}
        remote = await self._remote(request) or {}
        local_data, remote_data = local.get("data", []), remote.get("data", [])
        data = []
        for i in range(max(len(local_data), len(remote_data))):
            a = remote_data[i]["attributes"]["columns"] if i < len(remote_data) else []
            b = local_data[i]["attributes"]["columns"] if i < len(local_data) else []
            data.append({"type": "scalar_response", "attributes": {"columns": _merge_scalar_columns(a, b)}})
        return web.json_response({"data": data})

    def _local_has(self, predicate: Callable[[Dict[str, Any]], bool]) -> bool:
        return any(predicate(span) for span in self.local_api.backend.get_llmobs_spans())  # type: ignore[attr-defined]

    async def _trace(self, request: web.Request) -> web.Response:
        trace_id = request.match_info.get("trace_id", "")
        if self._local_has(lambda s: str(s.get("trace_id", "")) == trace_id):
            return await self.local_api.handle_trace(request)
        remote = await self._remote(request, lookup=True)
        if remote is None:
            raise _SelfHostedUnavailable
        return web.json_response(remote)

    async def _fetch_one(self, request: web.Request) -> web.Response:
        body = await request.json()
        event_id = str((body.get("eventId", "") or body.get("fetch_one", {}).get("id", "")) if body else "")
        if event_id and self._local_has(lambda s: event_id.endswith(str(s.get("span_id", "")) or "\0")):
            return await self.local_api.handle_fetch_one(request)
        remote = await self._remote(request, lookup=True)
        if remote is None:
            raise _SelfHostedUnavailable
        return web.json_response(remote)
