"""ClickHouse-backed span storage and queries for ``lapdog server``.

``ClickHouseSpanBackend`` implements the same ``SpanBackend`` contract as the
in-memory backend, so the Event Platform handlers and response shapes are
shared. Known differences from in-memory mode:

- Spans are keyed by (trace_id, span_id): re-sending a span replaces it
  instead of adding a duplicate row.
- A span without ``start_ns`` is stamped with its ingest time, so retention
  applies to it.
- Numbers are stringified by ClickHouse, so a float facet value reads ``5``
  where Python would print ``5.0``.
"""

import base64
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Sequence
from typing import Tuple

from ..llmobs_event_platform import AggregateRequest
from ..llmobs_event_platform import AggregateResult
from ..llmobs_event_platform import ListResult
from ..llmobs_event_platform import TimeWindow
from ..llmobs_event_platform import _LLMOBS_SCALAR_DATA_SOURCES
from ..llmobs_event_platform import _decode_list_cursor
from ..llmobs_event_platform import _list_compute_sort_order
from ..llmobs_event_platform import _query_column_name
from ..llmobs_event_platform import _query_compute_spec
from ..llmobs_event_platform import _query_group_by_fields
from ..llmobs_event_platform import children_ids_by_trace
from ..llmobs_event_platform import merge_span_update
from ..model_pricing import COST_METRIC_KEYS
from ..model_pricing import estimate_span_cost
from .clickhouse import ClickHouseClient
from .clickhouse import quote
from .clickhouse import quote_identifier
from .schema import next_version
from .schema import span_to_row
from .sql import TRACE_ALIAS
from .sql import compile_query
from .sql import group_key
from .sql import resolve_field

log = logging.getLogger(__name__)

# Marks spans whose cost lapdog estimated, so an update with new token counts re-prices them.
LOCALLY_PRICED_KEY = "_lapdog_locally_priced"
# Cap on rows a ``list`` compute returns per aggregate group.
LIST_COMPUTE_LIMIT = 10_000


def _in_list(values: Sequence[Any]) -> str:
    return "(" + ", ".join(quote(v) for v in values) + ")"


def _encode_cursor(row: Dict[str, Any]) -> str:
    key = [int(row["start_ns"]), str(row["trace_id"]), str(row["span_id"]), 0]
    return base64.urlsafe_b64encode(json.dumps(key, separators=(",", ":")).encode()).decode()


def _price_new_span(span: Dict[str, Any]) -> None:
    if estimate_span_cost(span):
        span[LOCALLY_PRICED_KEY] = True


class ClickHouseSpanBackend:
    """Stores spans in ClickHouse and answers Event Platform queries in SQL."""

    def __init__(self, client: ClickHouseClient, database: str) -> None:
        self.client = client
        self.database = database
        self.table = f"{quote_identifier(database)}.spans"

    # -- writes ------------------------------------------------------------

    async def insert_spans(self, spans: List[Dict[str, Any]]) -> int:
        for span in spans:
            _price_new_span(span)
        await self.client.insert(self.table, [span_to_row(span, next_version()) for span in spans])
        return len(spans)

    async def update_spans(self, updates: List[Dict[str, Any]]) -> int:
        """Merge partial updates into stored spans (matched by span_id); unknown span_ids are dropped."""
        span_ids = sorted({str(u["span_id"]) for u in updates if u.get("span_id")})
        if not span_ids:
            return 0
        rows = await self.client.query(
            f"SELECT span_id, span_json FROM {self.table} FINAL WHERE span_id IN {_in_list(span_ids)} "
            "ORDER BY start_ns DESC LIMIT 1 BY span_id"
        )
        existing = {row["span_id"]: json.loads(row["span_json"]) for row in rows}
        changed: Dict[str, Dict[str, Any]] = {}
        updated = 0
        for update in updates:
            span = changed.get(str(update.get("span_id"))) or existing.get(str(update.get("span_id")))
            if span is None:
                continue
            if span.get(LOCALLY_PRICED_KEY):
                for key in COST_METRIC_KEYS:
                    span.get("metrics", {}).pop(key, None)
            merge_span_update(update, span)
            if any(key in (update.get("metrics") or {}) for key in COST_METRIC_KEYS):
                span.pop(LOCALLY_PRICED_KEY, None)
            elif estimate_span_cost(span):
                span[LOCALLY_PRICED_KEY] = True
            changed[str(span.get("span_id"))] = span
            updated += 1
        if changed:
            await self.client.insert(self.table, [span_to_row(span, next_version()) for span in changed.values()])
        return updated

    # -- shared SQL pieces -------------------------------------------------

    def _trace_aggregates_sql(self, where: str = "1") -> str:
        """Per-trace rollups, mirroring ``_build_trace_aggregates`` (computed over each whole trace)."""
        return (
            "SELECT trace_id AS ta_trace_id, "
            "sum(num_evals_failed) AS num_evaluations_failed, "
            "countIf(status = 'error') AS number_of_errors, "
            "sumIf(metrics['input_tokens'], kind = 'llm') AS input_tokens, "
            "sumIf(metrics['output_tokens'], kind = 'llm') AS output_tokens, "
            "sumIf(metrics['total_tokens'], kind = 'llm') AS total_tokens, "
            "sumIf(metrics['estimated_total_cost'], kind = 'llm') AS estimated_total_cost "
            f"FROM {self.table} FINAL WHERE {where} GROUP BY trace_id"
        )

    def _source(self, trace_join: bool) -> str:
        source = f"{self.table} AS s FINAL"
        if trace_join:
            source += f" LEFT JOIN ({self._trace_aggregates_sql()}) AS {TRACE_ALIAS} ON {TRACE_ALIAS}.ta_trace_id = s.trace_id"
        return source

    @staticmethod
    def _where(query: str, time_window: Optional[TimeWindow]) -> str:
        where = compile_query(query)
        if time_window is None:
            return where
        start_ns, end_ns = time_window
        return f"({where}) AND start_ns BETWEEN {int(start_ns)} AND {int(end_ns)}"

    async def _spans(self, sql: str) -> List[Dict[str, Any]]:
        return [json.loads(row["span_json"]) for row in await self.client.query(sql)]

    # -- SpanBackend -------------------------------------------------------

    async def list_spans(
        self,
        query: str,
        limit: int,
        paging: Optional[Any],
        sort_order: str,
        time_window: Optional[TimeWindow] = None,
    ) -> ListResult:
        where = self._where(query, time_window)
        direction = "ASC" if sort_order == "asc" else "DESC"
        cursor_sql = ""
        if paging is not None and not isinstance(paging, dict):
            raise ValueError("Invalid list paging cursor")
        if paging:
            after = paging.get("after")
            from_cursor = paging.get("from")
            if after and from_cursor:
                raise ValueError("List paging accepts either after or from")
            cursor = after or from_cursor
            if cursor:
                if not isinstance(cursor, str):
                    raise ValueError("Invalid list paging cursor")
                start_ns, trace_id, span_id, occurrence = _decode_list_cursor(cursor)
                key = f"({quote(start_ns)}, {quote(trace_id)}, {quote(span_id)})"
                op = ">" if direction == "ASC" else "<"
                # Stored spans are unique per key, so each has occurrence 0.
                inclusive = bool(from_cursor) or (direction == "DESC" and occurrence > 0)
                cursor_sql = f" AND (start_ns, trace_id, span_id) {op}{'=' if inclusive else ''} {key}"

        hit_rows = await self.client.query(f"SELECT count() AS c FROM {self.table} FINAL WHERE {where}")
        hit_count = int(hit_rows[0]["c"]) if hit_rows else 0
        rows: List[Dict[str, Any]] = []
        if limit > 0:
            rows = await self.client.query(
                f"SELECT span_json, start_ns, trace_id, span_id FROM {self.table} FINAL "
                f"WHERE {where}{cursor_sql} "
                f"ORDER BY start_ns {direction}, trace_id {direction}, span_id {direction} LIMIT {limit + 1}"
            )
        page_rows = rows[:limit]
        next_paging = {"after": _encode_cursor(page_rows[-1])} if page_rows and len(rows) > limit else None
        spans = [json.loads(row["span_json"]) for row in page_rows]

        trace_ids = sorted({str(span.get("trace_id", "")) for span in spans})
        children: Dict[str, Dict[str, List[str]]] = {}
        aggregates: Dict[str, Dict[str, Any]] = {}
        if trace_ids:
            in_traces = f"trace_id IN {_in_list(trace_ids)}"
            links = await self.client.query(
                f"SELECT trace_id, span_id, parent_id FROM {self.table} FINAL WHERE {in_traces} ORDER BY start_ns DESC"
            )
            children = children_ids_by_trace(links)
            for row in await self.client.query(self._trace_aggregates_sql(in_traces)):
                tid = row.pop("ta_trace_id")
                aggregates[tid] = row
        return ListResult(spans, next_paging, hit_count, children, aggregates)

    def _aggregate_metric_sql(self, compute_item: Dict[str, Any]) -> Optional[str]:
        if "total" in compute_item:
            cfg = compute_item["total"]
            aggregation = cfg.get("aggregation", "")
            field = resolve_field(cfg.get("metric", ""))
            if aggregation == "count":
                return "count()"
            if aggregation == "earliest":
                return f"ifNull(argMin(tuple({field.text}), start_ns).1, '')"
            if aggregation == "latest":
                return f"ifNull(argMax(tuple({field.text}), start_ns).1, '')"
            if aggregation in ("min", "max", "sum", "avg"):
                return f"ifNull({aggregation}({field.number}), 0)"
            return None
        if "list" in compute_item:
            cfg = compute_item["list"]
            columns = [group_key(col) for col in cfg.get("columns", [])]
            pairs = f"groupArray({LIST_COMPUTE_LIMIT})(tuple(start_ns, [{', '.join(columns)}]))"
            ordered = f"arrayMap(x -> x.2, arraySort(x -> x.1, {pairs}))"
            return ordered if _list_compute_sort_order(cfg) == "asc" else f"arrayReverse({ordered})"
        return None

    async def aggregate(self, request: AggregateRequest) -> AggregateResult:
        where = self._where(request.query, request.time_window)
        key = group_key(request.group_by_field)
        selects = [f"{key} AS k", "max(start_ns) AS latest_ns", "min(start_ns) AS earliest_ns"]
        outputs: List[Tuple[str, str]] = []
        for i, item in enumerate(request.compute):
            sql = self._aggregate_metric_sql(item)
            if sql is not None:
                cfg = item.get("total") or item.get("list") or {}
                selects.append(f"{sql} AS m{i}")
                outputs.append((f"m{i}", cfg.get("output", "")))
        having = f"HAVING k NOT IN {_in_list(request.seen_groups)}" if request.seen_groups else ""
        order = "latest_ns DESC" if request.sort_order == "desc" else "earliest_ns ASC"
        rows = await self.client.query(
            f"SELECT {', '.join(selects)} FROM {self.table} FINAL WHERE {where} "
            f"GROUP BY k {having} ORDER BY {order}, k LIMIT {int(request.limit) + 1}"
        )
        groups = [(str(row["k"]), {output: row[column] for column, output in outputs}) for row in rows[: request.limit]]
        return AggregateResult(groups, len(rows) > request.limit)

    async def fetch_one(self, event_id: str) -> Optional[Dict[str, Any]]:
        spans = await self._spans(
            f"SELECT span_json FROM {self.table} FINAL WHERE span_id = {quote(event_id)} ORDER BY start_ns DESC LIMIT 1"
        )
        if not spans:
            spans = await self._spans(
                f"SELECT span_json FROM {self.table} FINAL "
                f"ORDER BY endsWith({quote(event_id)}, span_id) DESC, start_ns DESC LIMIT 1"
            )
        return spans[0] if spans else None

    async def trace_spans(self, trace_id: str, span_id_filter: str) -> List[Dict[str, Any]]:
        spans = await self._spans(
            f"SELECT span_json FROM {self.table} FINAL WHERE trace_id = {quote(trace_id)} ORDER BY start_ns DESC"
        )
        if not spans and span_id_filter:
            spans = await self._spans(
                f"SELECT span_json FROM {self.table} FINAL WHERE span_id = {quote(span_id_filter)} "
                "ORDER BY start_ns DESC"
            )
        if not spans:
            spans = await self._spans(f"SELECT span_json FROM {self.table} FINAL ORDER BY start_ns DESC LIMIT 1")
        return spans

    async def facet_values(
        self, field: str, query: str, limit: int, term_search: str, time_window: Optional[TimeWindow] = None
    ) -> List[Tuple[str, int]]:
        resolved = resolve_field(field)
        rows = await self.client.query(
            f"SELECT {resolved.text} AS v, count() AS c, max(start_ns) AS latest FROM {self.table} FINAL "
            f"WHERE ({self._where(query, time_window)}) AND v IS NOT NULL GROUP BY v ORDER BY c DESC, latest DESC "
            f"LIMIT {int(limit)}"
        )
        values = [(str(row["v"]), int(row["c"])) for row in rows]
        if term_search:
            term_lower = term_search.lower()
            values = [(v, c) for v, c in values if term_lower in v.lower()][:limit]
        return values

    async def facet_range(
        self, field: str, query: str, time_window: Optional[TimeWindow] = None
    ) -> Tuple[float, float]:
        number = resolve_field(field).number
        rows = await self.client.query(
            f"SELECT min({number}) AS lo, max({number}) AS hi, count({number}) AS n FROM {self.table} FINAL "
            f"WHERE {self._where(query, time_window)}"
        )
        if not rows or not rows[0]["n"]:
            return (0, 0)
        return (rows[0]["lo"], rows[0]["hi"])

    # -- scalar ------------------------------------------------------------

    @staticmethod
    def _value_sql(aggregation: str, number: str, text: str, ts: str) -> str:
        """Return SQL for ``_scalar_compute``'s aggregations over a group (number/text are per-row SQL)."""
        agg = (aggregation or "count").lower()
        if agg == "count":
            return "toFloat64(count())"
        if agg == "cardinality":
            return f"toFloat64(uniqExact({text}))"
        if agg == "latest":
            return f"ifNull(argMax(tuple({number}), {ts}).1, 0)"
        if agg == "earliest":
            return f"ifNull(argMin(tuple({number}), {ts}).1, 0)"
        if agg in ("sum", "avg", "min", "max"):
            return f"ifNull(toFloat64({agg}({number})), 0)"
        sorted_values = f"arraySort(groupArray({number}))"
        n = f"length({sorted_values})"
        if agg == "median":
            mid = f"intDiv({n}, 2)"
            return (
                f"if({n} = 0, 0, if({n} % 2 = 1, {sorted_values}[{mid} + 1], "
                f"({sorted_values}[{mid}] + {sorted_values}[{mid} + 1]) / 2))"
            )
        if agg.startswith("pc"):
            try:
                pct = int(agg[2:])
            except ValueError:
                return "0"
            index = f"greatest(0, least({n} - 1, toInt64(roundBankers({pct / 100.0} * ({n} - 1)))))"
            return f"if({n} = 0, 0, {sorted_values}[{index} + 1])"
        return "0"

    async def _scalar_groups(
        self, query: Dict[str, Any], group_fields: List[str], first: bool, row_limit: int, sort_desc: bool
    ) -> List[Tuple[Tuple[str, ...], float]]:
        spec = _query_compute_spec(query)
        aggregation = str(spec["aggregation"] or "count").lower()
        metric = spec["metric"]
        supported = (query.get("data_source") or "").lower() in _LLMOBS_SCALAR_DATA_SOURCES
        if not supported:
            return [((), 0.0)] if not group_fields else []
        search = query.get("search")
        where = compile_query((search.get("query") or "") if isinstance(search, dict) else "")

        field = str(metric).lstrip("@") if metric else ""
        is_trace_field = field.startswith("trace.")
        trace_join = is_trace_field or any(f.lstrip("@").startswith("trace.") for f in group_fields)
        keys = [f"{group_key(f, trace_join=trace_join)} AS k{i}" for i, f in enumerate(group_fields)]
        key_names = [f"k{i}" for i in range(len(group_fields))]
        source = self._source(trace_join)

        if aggregation != "count" and not metric:
            value = "toFloat64(0)"
            inner = None
        elif is_trace_field and aggregation != "count":
            # Trace rollups are one value per trace; dedupe per group before aggregating.
            resolved = resolve_field(field, trace_join=True)
            group_cols = ", ".join(key_names + ["s.trace_id"])
            inner = (
                f"SELECT {', '.join(keys + ['s.trace_id AS tid'])}, any({resolved.number}) AS tv, "
                f"any({resolved.text}) AS tt, max(start_ns) AS ts "
                f"FROM {source} WHERE {where} GROUP BY {group_cols}"
            )
            value = self._value_sql(aggregation, "tv", "tt", "ts")
        else:
            resolved = resolve_field(field or "span_id", trace_join=trace_join)
            value = self._value_sql(aggregation, resolved.number, resolved.text, "start_ns")
            inner = None

        if inner is not None:
            group_by = f"GROUP BY {', '.join(key_names)}" if key_names else ""
            sql = f"SELECT {', '.join(key_names + [f'{value} AS v', 'max(ts) AS latest'])} FROM ({inner}) {group_by}"
        else:
            select = keys + [f"{value} AS v", "max(start_ns) AS latest"]
            group_by = f"GROUP BY {', '.join(key_names)}" if key_names else ""
            sql = f"SELECT {', '.join(select)} FROM {source} WHERE {where} {group_by}"
        if first and key_names:
            sql += f" ORDER BY v {'DESC' if sort_desc else 'ASC'}, latest DESC LIMIT {int(row_limit)}"

        rows = await self.client.query(sql)
        if not key_names:
            return [((), float(rows[0]["v"]) if rows else 0.0)]
        return [(tuple(str(row[k]) for k in key_names), float(row["v"])) for row in rows]

    async def scalar_columns(
        self, queries: List[Dict[str, Any]], formulas: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Compute the same columns as ``_build_scalar_columns``, in ClickHouse."""
        if not queries:
            return []
        group_defs = _query_group_by_fields(queries[0])
        group_fields = [gd["field"] for gd in group_defs]
        columns: List[Dict[str, Any]] = []

        def number_column(name: str, values: List[float]) -> Dict[str, Any]:
            return {"name": name, "type": "number", "meta": {"unit": None}, "values": values}

        if not group_defs:
            values_by_query: Dict[str, float] = {}
            for i, q in enumerate(queries):
                groups = await self._scalar_groups(q, [], first=True, row_limit=1, sort_desc=True)
                val = groups[0][1] if groups else 0.0
                values_by_query[str(q.get("name") or f"query{i + 1}")] = val
                if not formulas:
                    columns.append(number_column(_query_column_name(q), [val]))
            for f in formulas:
                ref = str(f.get("formula") or "")
                columns.append(number_column(str(f.get("alias") or ref), [values_by_query.get(ref, 0.0)]))
            return columns

        row_limit = min((gd["limit"] for gd in group_defs if isinstance(gd.get("limit"), int)), default=50)
        sort_desc = group_defs[0]["sort_order"] == "desc"
        first = await self._scalar_groups(
            queries[0], group_fields, first=True, row_limit=row_limit, sort_desc=sort_desc
        )
        order = [key for key, _ in first]
        per_query_values: List[List[float]] = [[value for _, value in first]]
        for q in queries[1:]:
            values = dict(await self._scalar_groups(q, group_fields, first=False, row_limit=0, sort_desc=sort_desc))
            per_query_values.append([values.get(key, 0.0) for key in order])

        for i, gd in enumerate(group_defs):
            columns.append({"name": gd["name"], "type": "group", "meta": None, "values": [[k[i]] for k in order]})
        if formulas:
            name_to_idx = {str(q.get("name") or f"query{i + 1}"): i for i, q in enumerate(queries)}
            for f in formulas:
                ref = str(f.get("formula") or "")
                idx = name_to_idx.get(ref)
                vals = per_query_values[idx] if idx is not None else [0.0 for _ in order]
                columns.append(number_column(str(f.get("alias") or ref), vals))
        else:
            for qi, q in enumerate(queries):
                columns.append(number_column(_query_column_name(q), per_query_values[qi]))
        return columns
