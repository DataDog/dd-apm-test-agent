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
``laptop`` or ``self-hosted``), so the UI can show where each trace lives.
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
from typing import cast
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
from .llmobs_event_platform import _query_column_name
from .llmobs_event_platform import _query_compute_spec
from .llmobs_event_platform import _query_group_by_fields
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
    # Right after the last event listed so far, for continuing from memory alone if Self-hosted goes away.
    position: Optional[str] = None


def _decode_cursor(paging: Any) -> Tuple[_Cursor, str]:
    """Return the cursor and its mode: ``after`` (exclusive) or ``from`` (inclusive), as both backends accept."""
    after = paging.get("after") if isinstance(paging, dict) else None
    from_cursor = paging.get("from") if isinstance(paging, dict) else None
    if after and from_cursor:
        raise ValueError("List paging accepts either after or from")
    raw, mode = (after, "after") if after else (from_cursor, "from")
    if not raw:
        return _Cursor(None, None), "after"
    if not isinstance(raw, str) or not raw.startswith(_CURSOR_PREFIX):
        raise ValueError("Invalid list paging cursor")
    try:
        data = json.loads(base64.urlsafe_b64decode(raw[len(_CURSOR_PREFIX) :].encode()).decode())
        return _Cursor(data.get("l"), data.get("r"), data.get("p")), mode
    except (ValueError, UnicodeError, binascii.Error, AttributeError) as exc:
        raise ValueError("Invalid list paging cursor") from exc


def _encode_cursor(cursor: _Cursor) -> str:
    raw = json.dumps({"l": cursor.local, "r": cursor.remote, "p": cursor.position}, separators=(",", ":")).encode()
    return _CURSOR_PREFIX + base64.urlsafe_b64encode(raw).decode()


class _WithBody:
    """``request`` asking a different JSON question, for handing a changed request to a local handler."""

    def __init__(self, request: web.Request, body: Any) -> None:
        self._request = request
        self._body = body

    async def json(self) -> Any:
        return copy.deepcopy(self._body)

    async def read(self) -> bytes:
        return json.dumps(self._body).encode()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._request, name)


def _with_body(request: web.Request, body: Any) -> web.Request:
    return cast(web.Request, _WithBody(request, body))


def _event_key(event: Dict[str, Any]) -> Tuple[int, str, str]:
    custom = event.get("event", {}).get("custom", {})
    return int(custom.get("start_ns", 0) or 0), str(custom.get("trace_id", "")), str(custom.get("span_id", ""))


def _span_cursor(key: Tuple[int, str, str]) -> str:
    """Return a cursor that continues after ``key``, in the format both backends' list paging accepts."""
    return base64.urlsafe_b64encode(json.dumps([*key, 0], separators=(",", ":")).encode()).decode()


def _merge_traces(trace_id: str, local: Dict[str, Any], remote: Dict[str, Any]) -> Dict[str, Any]:
    """Combine one trace's spans read from memory and from the Self-hosted server."""
    local_attrs = local.get("data", {}).get("attributes", {})
    # Like memory, the server answers an unknown trace with its newest span; that one isn't part of this trace.
    remote_spans = {
        span_id: span
        for span_id, span in (remote.get("data", {}).get("attributes", {}).get("spans", {}) or {}).items()
        if str(span.get("trace_id", "")) == trace_id
    }
    spans = {**copy.deepcopy(remote_spans), **local_attrs.get("spans", {})}
    for span_id, span in spans.items():
        children = list(span.get("children_ids") or []) + list(remote_spans.get(span_id, {}).get("children_ids") or [])
        children += [cid for cid, child in spans.items() if child.get("parent_id") == span_id]
        span["children_ids"] = list(dict.fromkeys(children))
    roots = [sid for sid, span in spans.items() if span.get("parent_id") in (None, "", "undefined", "0")]
    merged = copy.deepcopy(local)
    attributes = merged["data"]["attributes"]
    attributes["spans"] = spans
    attributes["root_id"] = roots[0] if roots else local_attrs.get("root_id")
    return merged


def _merge_metric(aggregation: Optional[str], a: Any, b: Any) -> Any:
    """Combine one statistic from both sides. ``earliest``/``latest`` need timestamps, so callers pick those."""
    if isinstance(a, list) and isinstance(b, list):
        return a + b
    if aggregation in ("earliest", "latest") or not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
        return a if a not in ("", None) else b
    if aggregation == "min":
        return min(a, b)
    if aggregation == "max":
        return max(a, b)
    if aggregation == "avg":
        return (a + b) / 2
    return a + b


_HIDDEN = "__lapdog_"
# Statistics that can't be combined from the two sides' values alone.
_NEEDS_COUNT = {"min", "max", "avg", "median", "pc75", "pc90", "pc95", "pc99", "earliest", "latest"}


class _ScalarColumn(NamedTuple):
    aggregation: str
    count_column: Optional[str]  # hidden column with this column's span count on each row
    time_column: Optional[str]  # hidden column with its earliest (or latest) span time, for earliest/latest


def _scalar_plan(attributes: Any) -> Tuple[Dict[str, Any], Dict[str, _ScalarColumn]]:
    """Return the scalar request with hidden helper queries added, and how to merge each column.

    Combining a minimum, average, or latest value from both sides needs to know how many spans each
    side's value covers (a side with none returns a placeholder 0) and, for earliest/latest, when.
    """
    if not isinstance(attributes, dict):
        return {}, {}
    augmented = copy.deepcopy(attributes)
    queries = [q for q in augmented.get("queries") or [] if isinstance(q, dict)]
    formulas = [f for f in augmented.get("formulas") or [] if isinstance(f, dict)]
    by_query: Dict[str, _ScalarColumn] = {}
    hidden_queries: List[Dict[str, Any]] = []
    for i, query in enumerate(queries):
        name = str(query.get("name") or f"query{i + 1}")
        aggregation = str(_query_compute_spec(query)["aggregation"])
        count = time = None
        if aggregation in _NEEDS_COUNT:
            count = f"{_HIDDEN}n_{name}"
            hidden_queries.append({**copy.deepcopy(query), "name": count, "compute": {"aggregation": "count"}})
        if aggregation in ("earliest", "latest"):
            time = f"{_HIDDEN}t_{name}"
            stat = "min" if aggregation == "earliest" else "max"
            hidden_queries.append(
                {**copy.deepcopy(query), "name": time, "compute": {"aggregation": stat, "metric": "@timestamp"}}
            )
        by_query[name] = _ScalarColumn(aggregation, count, time)
    columns: Dict[str, _ScalarColumn] = {}
    if formulas:
        for formula in formulas:
            ref = str(formula.get("formula") or "")
            if ref in by_query:
                columns[str(formula.get("alias") or ref)] = by_query[ref]
        formulas += [{"formula": q["name"], "alias": q["name"]} for q in hidden_queries]
        augmented["formulas"] = formulas
    else:
        for i, query in enumerate(queries):
            columns[_query_column_name(query)] = by_query[str(query.get("name") or f"query{i + 1}")]
    augmented["queries"] = queries + hidden_queries
    return augmented, columns


def _scalar_rows(columns: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index a scalar response's rows by their group values."""
    groups = [c for c in columns if c.get("type") == "group"]
    numbers = [c for c in columns if c.get("type") != "group"]
    count = len(numbers[0]["values"]) if numbers else (len(groups[0]["values"]) if groups else 0)
    rows: Dict[str, Dict[str, Any]] = {}
    for i in range(count):
        key = json.dumps([g["values"][i] for g in groups])
        rows[key] = {c["name"]: c["values"][i] if i < len(c["values"]) else 0 for c in numbers}
    return rows


def _merge_scalar_row(into: Dict[str, Any], row: Dict[str, Any], plan: Dict[str, _ScalarColumn]) -> None:
    for name, value in row.items():
        if name.startswith(_HIDDEN):
            continue
        if name not in into:
            into[name] = value
            continue
        column = plan.get(name)
        if column is None or column.count_column is None:
            into[name] = _merge_metric(column.aggregation if column else None, into[name], value)
            continue
        mine, theirs = into.get(column.count_column) or 0, row.get(column.count_column) or 0
        if not theirs:
            continue
        if not mine:
            into[name] = value
        elif column.aggregation == "avg":
            into[name] = (into[name] * mine + value * theirs) / (mine + theirs)
        elif column.time_column is not None:
            earlier = (row.get(column.time_column) or 0) < (into.get(column.time_column) or 0)
            if earlier == (column.aggregation == "earliest"):
                into[name] = value
        else:
            into[name] = _merge_metric(column.aggregation, into[name], value)
    for column in set(plan.values()):
        count_name, time_name = column.count_column, column.time_column
        if count_name is None:
            continue
        mine, theirs = into.get(count_name) or 0, row.get(count_name) or 0
        if time_name is not None and theirs:
            pick = min if column.aggregation == "earliest" else max
            into[time_name] = pick(into[time_name], row[time_name]) if mine else row[time_name]
        into[count_name] = mine + theirs


def _merge_scalar_columns(
    a: List[Dict[str, Any]], b: List[Dict[str, Any]], plan: Dict[str, _ScalarColumn], keep_hidden: bool = False
) -> List[Dict[str, Any]]:
    """Combine two scalar responses' columns; rows with the same group values merge per column statistic."""
    template = a or b
    rows: Dict[str, Dict[str, Any]] = {}
    for columns in (a, b):
        for key, row in _scalar_rows(columns).items():
            if key in rows:
                _merge_scalar_row(rows[key], row, plan)
            else:
                rows[key] = dict(row)
    merged = []
    for g_index, column in enumerate(c for c in template if c.get("type") == "group"):
        merged.append({**column, "values": [json.loads(k)[g_index] for k in rows]})
    for column in template:
        if column.get("type") != "group" and (keep_hidden or not str(column["name"]).startswith(_HIDDEN)):
            merged.append({**column, "values": [row.get(column["name"], 0) for row in rows.values()]})
    return merged


def _top_scalar_rows(columns: List[Dict[str, Any]], descending: bool, limit: int) -> List[Dict[str, Any]]:
    """Keep the ``limit`` rows with the largest (or smallest) first value, as each backend does."""
    numbers = [c for c in columns if c.get("type") != "group" and not str(c["name"]).startswith(_HIDDEN)]
    if not numbers:
        return columns
    primary = numbers[0]["values"]
    order = sorted(range(len(primary)), key=lambda i: primary[i] or 0, reverse=descending)[:limit]
    return [{**c, "values": [c["values"][i] for i in order]} for c in columns]


def _merge_aggregate_values(
    merged: Dict[str, Dict[str, Any]], values: List[Dict[str, Any]], aggregations: Dict[str, Any], descending: bool
) -> None:
    """Fold one side's aggregate groups into ``merged``, keyed by group."""
    for value in values:
        key = json.dumps(value.get("by"), sort_keys=True)
        if key not in merged:
            merged[key] = copy.deepcopy(value)
            continue
        into = merged[key]
        for name, metric in value.get("metrics", {}).items():
            aggregation = aggregations.get(name)
            if aggregation == "earliest" and "_earliest_ns" in value and "_earliest_ns" in into:
                if value["_earliest_ns"] < into["_earliest_ns"]:
                    into["metrics"][name] = metric
            elif aggregation == "latest" and "_latest_ns" in value and "_latest_ns" in into:
                if value["_latest_ns"] > into["_latest_ns"]:
                    into["metrics"][name] = metric
            else:
                into["metrics"][name] = _merge_metric(aggregation, into["metrics"].get(name), metric)
        if "_order_ns" in value:
            pick = max if descending else min
            into["_order_ns"] = pick(into.get("_order_ns", value["_order_ns"]), value["_order_ns"])
        if "_earliest_ns" in value:
            into["_earliest_ns"] = min(into.get("_earliest_ns", value["_earliest_ns"]), value["_earliest_ns"])
        if "_latest_ns" in value:
            into["_latest_ns"] = max(into.get("_latest_ns", value["_latest_ns"]), value["_latest_ns"])


def _groups_query(query: str, field_id: str, keys: List[str]) -> Optional[str]:
    """``query`` narrowed to the given groups, or None if a key can't be written as a query value."""
    if not field_id or any(not key or '"' in key or "\\" in key for key in keys):
        return None
    groups = " OR ".join(f'{field_id}:"{key}"' for key in keys)
    return f"({query}) AND ({groups})" if query.strip() else f"({groups})"


class FederatedSearch:
    def __init__(self, full_api: LLMObsEventPlatformAPI, forwarding: Forwarding) -> None:
        self.full_api = full_api
        self.forwarding = forwarding
        self.local_api = LLMObsEventPlatformAPI(backend=LocalOnlyBackend(full_api._memory, forwarding.is_forwarded))
        self._results: Dict[str, Dict[str, Any]] = {}
        self._memory_list: Optional[_Handler] = None

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
                if last == "list":
                    self._memory_list = local_handler
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

    async def _list(self, request: web.Request) -> web.StreamResponse:
        body = await request.json()
        params = parse_list_params(body)
        paging = params.paging if isinstance(params.paging, dict) else {}
        raw_cursor = paging.get("after") or paging.get("from")
        if isinstance(raw_cursor, str) and not raw_cursor.startswith(_CURSOR_PREFIX) and self._memory_list:
            # Memory's own cursor, from a page answered by memory alone after Self-hosted went away:
            # keep paging memory so this listing stays consistent.
            return await self._memory_list(request)
        cursor, mode = _decode_cursor(params.paging)
        # Inclusive paging starts at the last event listed overall, not at each side's last one.
        local_start, remote_start = cursor.local, cursor.remote
        if mode == "from" and cursor.position:
            local_start = cursor.position if cursor.local != _END else _END
            remote_start = cursor.position if cursor.remote != _END else _END

        def side_paging(side_cursor: Optional[str]) -> Optional[Dict[str, str]]:
            return {mode: side_cursor} if side_cursor else None

        local_events: List[Dict[str, Any]] = []
        local_next: Optional[str] = None
        local_hits = 0
        if cursor.local != _END:
            page = await self.local_api.backend.list_spans(
                params.query, params.limit, side_paging(local_start), params.sort_order, time_window=params.time_window
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
            if remote_start:
                list_params["paging"] = {mode: remote_start}
            else:
                list_params.pop("paging", None)
            try:
                remote = await self._remote(request, json.dumps(remote_body).encode()) or {}
            except _SelfHostedUnavailable:
                if cursor == _Cursor(None, None):
                    raise
                return await self._continue_from_memory(request, body, cursor)
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

        next_local: Optional[str] = _END
        if cursor.local != _END:
            next_local = local_next or _END
            if len(taken_local) < len(local_events):
                # Only part of memory's page made the merged page. Ask memory for exactly that part, so its
                # cursor counts repeated copies of a span the way memory paging does.
                if taken_local:
                    part = await self.local_api.backend.list_spans(
                        params.query,
                        len(taken_local),
                        side_paging(local_start),
                        params.sort_order,
                        time_window=params.time_window,
                    )
                    next_local = (part.next_paging or {}).get("after") or _END
                else:
                    next_local = cursor.local
        next_remote: Optional[str] = _END
        if cursor.remote != _END:
            next_remote = remote_next or _END
            if len(taken_remote) < len(remote_events):
                # The server stores one copy of each span, so a span's key alone marks the position.
                next_remote = _span_cursor(_event_key(taken_remote[-1])) if taken_remote else cursor.remote

        position = _span_cursor(_event_key(taken[-1][0])) if taken else cursor.position
        next_cursor = _Cursor(next_local, next_remote, position)
        request_id = str(uuid.uuid4())
        result: Dict[str, Any] = {"events": [e for e, _ in taken], "count": len(taken)}
        if (next_cursor.local, next_cursor.remote) != (_END, _END):
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

    async def _continue_from_memory(self, request: web.Request, body: Any, cursor: _Cursor) -> web.StreamResponse:
        """Self-hosted went away mid-paging: carry on from memory alone, after the last event listed."""
        if self._memory_list is None:
            raise _SelfHostedUnavailable
        memory_body = copy.deepcopy(body)
        list_params = memory_body.setdefault("list", {})
        if cursor.position:
            list_params["paging"] = {"after": cursor.position}
        else:
            list_params.pop("paging", None)
        return await self._memory_list(_with_body(request, memory_body))

    def _label(self, event: Dict[str, Any], source: str) -> None:
        custom = event.get("event", {}).get("custom")
        if not isinstance(custom, dict):
            return
        custom["lapdog"] = {"source": source}

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
        field_id = str(field.get("id", ""))
        output = field.get("output", field_id)
        limit = int(field.get("limit", 50)) if agg.get("groupBy") else 1
        descending = ((field.get("sort") or {}).get("metric") or {}).get("order", "desc") != "asc"
        aggregations = {
            c["total"].get("output"): c["total"].get("aggregation") for c in agg.get("compute", []) if "total" in c
        }

        def order(values: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
            return sorted(values.values(), key=lambda v: int(v.get("_order_ns", 0)), reverse=descending)

        sides = [(remote, False), (local, True)]
        merged: Dict[str, Dict[str, Any]] = {}
        for side, _ in sides:
            _merge_aggregate_values(merged, side.get("result", {}).get("values", []), aggregations, descending)
        ordered = order(merged)
        page = ordered[:limit]

        # Each side returned only its own top groups, so a group on this page may have more spans on a side
        # that stopped before reaching it. Ask that side for just those groups to complete their numbers.
        if output and field_id:
            for side, is_local in sides:
                if not side.get("result", {}).get("paging"):
                    continue
                have = {json.dumps(v.get("by"), sort_keys=True) for v in side.get("result", {}).get("values", [])}
                missing = [v for v in page if json.dumps(v.get("by"), sort_keys=True) not in have]
                keys = [str((v.get("by") or {}).get(output, "")) for v in missing]
                query = _groups_query(str((agg.get("search") or {}).get("query", "")), field_id, keys)
                if not missing or query is None:
                    continue
                extra_body = copy.deepcopy(body)
                extra_agg = extra_body["aggregate"]
                extra_agg.setdefault("search", {})["query"] = query
                extra_agg.pop("paging", None)
                extra_agg["groupBy"][0]["field"]["limit"] = len(missing)
                if is_local:
                    extra = await self._local(self.local_api.handle_aggregate, _with_body(request, extra_body)) or {}
                else:
                    extra = await self._remote(request, json.dumps(extra_body).encode()) or {}
                page_keys = {json.dumps(v.get("by"), sort_keys=True) for v in missing}
                values = [
                    v
                    for v in extra.get("result", {}).get("values", [])
                    if json.dumps(v.get("by"), sort_keys=True) in page_keys
                ]
                _merge_aggregate_values(merged, values, aggregations, descending)
            ordered = order(merged)
            page_keys = {json.dumps(v.get("by"), sort_keys=True) for v in page}
            page = [v for v in ordered if json.dumps(v.get("by"), sort_keys=True) in page_keys]

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
        facet = (body.get("facet_info") or {}) if isinstance(body, dict) else {}
        limit = int(facet.get("limit", 10))
        sides = [
            (await self._remote(request) or {}, False),
            (await self._local(self.local_api.handle_facet_info, request) or {}, True),
        ]

        def counts_of(response: Dict[str, Any]) -> Dict[str, int]:
            return {str(i.get("field")): int(i.get("value", 0)) for i in response.get("result", {}).get("fields", [])}

        side_counts = [counts_of(side) for side, _ in sides]
        counts: Dict[str, int] = {}
        for side in side_counts:
            for value, count in side.items():
                counts[value] = counts.get(value, 0) + count
        top = [v for v, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:limit]]
        # Each side returned only its own top values; count the rest of a top value's spans on a side that
        # stopped before reaching it.
        for (side, is_local), have in zip(sides, side_counts):
            missing = [v for v in top if v not in have]
            search = str((facet.get("search") or {}).get("query", ""))
            query = _groups_query(search, str(facet.get("path", "")), missing)
            if len(have) < limit or not missing or query is None:
                continue
            extra_body = copy.deepcopy(body)
            extra_body["facet_info"].setdefault("search", {})["query"] = query
            extra_body["facet_info"]["limit"] = len(missing)
            if is_local:
                extra = await self._local(self.local_api.handle_facet_info, _with_body(request, extra_body)) or {}
            else:
                extra = await self._remote(request, json.dumps(extra_body).encode()) or {}
            for value, count in counts_of(extra).items():
                if value in missing:
                    counts[value] = counts.get(value, 0) + count
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
        body = await request.json()
        requests = (body.get("data") if isinstance(body, dict) else None) or []
        augmented_body = copy.deepcopy(body) if isinstance(body, dict) else {}
        plans: List[Dict[str, _ScalarColumn]] = []
        for i, item in enumerate(requests):
            attributes, plan = _scalar_plan(item.get("attributes") if isinstance(item, dict) else None)
            if attributes:
                augmented_body["data"][i]["attributes"] = attributes
            plans.append(plan)
        local = await self._local(self.local_api.handle_query_scalar, _with_body(request, augmented_body)) or {}
        remote = await self._remote(request, json.dumps(augmented_body).encode()) or {}
        local_data, remote_data = local.get("data", []), remote.get("data", [])
        data = []
        for i in range(max(len(local_data), len(remote_data))):
            a = remote_data[i]["attributes"]["columns"] if i < len(remote_data) else []
            b = local_data[i]["attributes"]["columns"] if i < len(local_data) else []
            item = augmented_body["data"][i] if i < len(requests) else None
            columns = await self._merge_scalar_sides(request, item, a, b, plans[i] if i < len(plans) else {})
            data.append({"type": "scalar_response", "attributes": {"columns": columns}})
        return web.json_response({"data": data})

    async def _merge_scalar_sides(
        self,
        request: web.Request,
        item: Optional[Dict[str, Any]],
        remote: List[Dict[str, Any]],
        local: List[Dict[str, Any]],
        plan: Dict[str, _ScalarColumn],
    ) -> List[Dict[str, Any]]:
        """Merge one scalar request's columns, completing top groups that a side's row limit cut off."""
        attributes = (item or {}).get("attributes") or {}
        queries = [q for q in attributes.get("queries") or [] if isinstance(q, dict)]
        group_defs = _query_group_by_fields(queries[0]) if queries else []
        if len(group_defs) != 1:
            return _merge_scalar_columns(remote, local, plan)
        group = group_defs[0]
        limit = group["limit"] if isinstance(group.get("limit"), int) else 50
        descending = group["sort_order"] == "desc"
        top = _top_scalar_rows(_merge_scalar_columns(remote, local, plan, keep_hidden=True), descending, limit)
        top_keys = list(_scalar_rows(top))
        sides = [remote, local]
        for index, is_local in ((0, False), (1, True)):
            have = _scalar_rows(sides[index])
            missing_keys = [k for k in top_keys if k not in have]
            values = [str((json.loads(k) or [[""]])[0][0]) for k in missing_keys]
            if len(have) < limit or not missing_keys:
                continue
            extra_attributes = copy.deepcopy(attributes)
            narrowed = True
            for query in extra_attributes.get("queries") or []:
                search = str((query.get("search") or {}).get("query", ""))
                query_text = _groups_query(search, "@" + str(group["field"]), values)
                if query_text is None:
                    narrowed = False
                    break
                query.setdefault("search", {})["query"] = query_text
                for group_by in query.get("group_by") or []:
                    if isinstance(group_by, dict):
                        group_by["limit"] = len(values)
            if not narrowed:
                continue
            extra_body = {"data": [{**(item or {}), "attributes": extra_attributes}]}
            if is_local:
                extra = await self._local(self.local_api.handle_query_scalar, _with_body(request, extra_body)) or {}
            else:
                extra = await self._remote(request, json.dumps(extra_body).encode()) or {}
            extra_columns = (extra.get("data") or [{}])[0].get("attributes", {}).get("columns", [])
            sides[index] = _merge_scalar_columns(sides[index], extra_columns, plan, keep_hidden=True)
        merged = _merge_scalar_columns(sides[0], sides[1], plan, keep_hidden=True)
        top = _top_scalar_rows(merged, descending, limit)
        return [c for c in top if c.get("type") == "group" or not str(c["name"]).startswith(_HIDDEN)]

    def _local_has(self, predicate: Callable[[Dict[str, Any]], bool]) -> bool:
        return any(predicate(span) for span in self.local_api.backend.get_llmobs_spans())  # type: ignore[attr-defined]

    async def _trace(self, request: web.Request) -> web.Response:
        trace_id = request.match_info.get("trace_id", "")
        local = None
        if self._local_has(lambda s: str(s.get("trace_id", "")) == trace_id):
            local = await self._local(self.local_api.handle_trace, request)
        # A trace can be split: spans from before forwarding was on, or a payload that failed to forward,
        # stay in memory while the rest are on the server.
        remote = await self._remote(request, lookup=True)
        if local is not None and remote is not None:
            return web.json_response(_merge_traces(trace_id, local, remote))
        if local is None and remote is None:
            raise _SelfHostedUnavailable
        return web.json_response(local if local is not None else remote)

    async def _fetch_one(self, request: web.Request) -> web.Response:
        body = await request.json()
        event_id = str((body.get("eventId", "") or body.get("fetch_one", {}).get("id", "")) if body else "")
        if event_id and self._local_has(lambda s: event_id.endswith(str(s.get("span_id", "")) or "\0")):
            return await self.local_api.handle_fetch_one(request)
        remote = await self._remote(request, lookup=True)
        if remote is None:
            raise _SelfHostedUnavailable
        return web.json_response(remote)
