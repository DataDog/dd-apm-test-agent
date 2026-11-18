"""Compile lapdog's LLMObs search queries into ClickHouse SQL.

The in-memory backend evaluates ``llmobs_query_parser`` ASTs against span dicts
via ``get_span_field_value``. This module produces SQL with the same semantics
against the ``spans`` table: each field resolves to a ``Nullable(String)``
expression mirroring ``str(value)`` (NULL where Python sees ``None``) and a
``Nullable(Float64)`` expression for numeric comparisons and aggregations.
"""

import re
from typing import Any
from typing import List
from typing import NamedTuple
from typing import Optional

from .. import llmobs_query_parser as qp
from ..llmobs_event_platform import parse_duration_to_nanoseconds
from .clickhouse import quote

TRACE_ALIAS = "ta"
TRACE_FIELDS = (
    "num_evaluations_failed",
    "number_of_errors",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "estimated_total_cost",
)

_STRING_COLUMNS = {
    "ml_app": "ml_app",
    "status": "status",
    "name": "name",
    "trace_id": "trace_id",
    "span_id": "span_id",
    "service": "service",
    "env": "env",
    "session_id": "session_id",
    "hostname": "hostname",
    "meta.model_name": "model_name",
    "meta.model_provider": "model_provider",
    "meta.span.kind": "kind",
}
_JSON_KEY = re.compile(r"^[^.\s]+$")


class Field(NamedTuple):
    """SQL for one field: ``text`` mirrors ``str(value)``; ``number`` mirrors ``float(value)``."""

    text: str
    number: str
    numeric: bool


def _string_field(expr: str) -> Field:
    return Field(expr, f"toFloat64OrNull(toString({expr}))", False)


def _numeric_field(expr: str) -> Field:
    return Field(f"toString({expr})", expr, True)


def tag_value(key: str) -> str:
    """Return SQL for the first ``key:`` tag's value, or NULL (``SpanMatcher.get_tag_value``)."""
    prefix = quote(f"{key}:")
    return (
        f"if(arrayExists(t -> startsWith(t, {prefix}), tags), "
        f"substring(arrayFirst(t -> startsWith(t, {prefix}), tags), {len(key) + 2}), NULL)"
    )


def _json_path(parts: List[str]) -> Optional[str]:
    if not parts or not all(_JSON_KEY.match(part) for part in parts):
        return None
    args = ", ".join(quote(part) for part in parts)
    return (
        f"multiIf(NOT JSONHas(span_json, {args}), NULL, "
        f"JSONType(span_json, {args}) = 'Null', NULL, "
        f"JSONType(span_json, {args}) = 'String', JSONExtractString(span_json, {args}), "
        f"JSONExtractRaw(span_json, {args}))"
    )


def resolve_field(field: str, trace_join: bool = False) -> Field:
    """Return SQL for ``get_span_field_value(span, field)`` (``_resolve_field_value`` with ``trace_join``)."""
    field = field.lstrip("@")
    if trace_join and field.startswith("trace."):
        name = field[len("trace.") :]
        if name in TRACE_FIELDS:
            return _numeric_field(f"{TRACE_ALIAS}.{name}")
        return Field("CAST(NULL, 'Nullable(String)')", "CAST(NULL, 'Nullable(Float64)')", True)
    if field == "event_type":
        return _string_field("'span'")
    if field == "parent_id":
        return _string_field("if(parent_id IN ('', '0'), 'undefined', parent_id)")
    if field == "duration":
        return _numeric_field("duration")
    if field == "timestamp":
        return _numeric_field("start_ns / 1000000")
    if field in _STRING_COLUMNS:
        return _string_field(_STRING_COLUMNS[field])
    if field.startswith("metrics.") and field.count(".") == 1:
        key = quote(field[len("metrics.") :])
        return _numeric_field(f"if(mapContains(metrics, {key}), metrics[{key}], NULL)")
    if field.startswith("meta.") or field.startswith("metrics."):
        path = _json_path(field.split("."))
        if path is None:
            return _string_field("CAST(NULL, 'Nullable(String)')")
        return _string_field(path)
    return _string_field(tag_value(field))


def group_key(field: Optional[str], trace_join: bool = False) -> str:
    """Return SQL for ``str(value or "")``: NULL, empty, and numeric zero all become ``''``."""
    if not field:
        return "''"
    resolved = resolve_field(field, trace_join)
    if resolved.numeric:
        return f"if(ifNull({resolved.number}, 0) = 0, '', {resolved.text})"
    return f"ifNull({resolved.text}, '')"


def like_pattern(pattern: str) -> str:
    """Convert a ``*``/``?`` wildcard pattern into a LIKE pattern."""
    out = []
    for ch in pattern:
        if ch in ("\\", "%", "_"):
            out.append("\\" + ch)
        elif ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        else:
            out.append(ch)
    return "".join(out)


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _compile_filter(spec: dict) -> str:  # type: ignore[type-arg]
    field = spec["field"]
    operator = spec.get("operator")
    resolved = resolve_field(field)
    tag = tag_value(field)

    if operator in ("exists", "missing"):
        exists = f"({resolved.text} IS NOT NULL OR {tag} IS NOT NULL)"
        return exists if operator == "exists" else f"NOT {exists}"

    value_sql = tag if spec.get("type") == "tag" else resolved.text
    number_sql = f"toFloat64OrNull({tag})" if spec.get("type") == "tag" else resolved.number

    if operator == "range":
        lo, hi = spec.get("min"), spec.get("max")
        # A non-numeric bound makes the Python comparison raise, so nothing matches.
        if (lo is not None and _number(lo) is None) or (hi is not None and _number(hi) is None):
            return "0"
        conds = [f"{number_sql} IS NOT NULL"]
        if lo is not None:
            conds.append(f"{number_sql} >= {quote(_number(lo))}")
        if hi is not None:
            conds.append(f"{number_sql} <= {quote(_number(hi))}")
        return "ifNull(" + " AND ".join(conds) + ", 0)"

    if operator in ("gte", "lte", "gt", "lt"):
        cmp = _number(spec.get("value"))
        if cmp is None:
            return "0"
        sym = {"gte": ">=", "lte": "<=", "gt": ">", "lt": "<"}[operator]
        return f"ifNull({number_sql} {sym} {quote(cmp)}, 0)"

    if operator == "in":
        values = [str(v) for v in spec.get("values", [])]
        if not values:
            return "0"
        return f"ifNull({value_sql} IN ({', '.join(quote(v) for v in values)}), 0)"

    value = spec.get("value")
    if value is None or value == "*":
        return f"{value_sql} IS NOT NULL"
    value = str(value)
    if "*" not in value and "?" not in value:
        return f"ifNull({value_sql} = {quote(value)}, 0)"
    return f"ifNull({value_sql} LIKE {quote(like_pattern(value))}, 0)"


def compile_ast(node: Optional[qp.QueryNode]) -> str:
    if node is None:
        return "1"
    if isinstance(node, qp.FilterNode):
        return _compile_filter(node.filter)
    if isinstance(node, qp.BooleanNode):
        if not node.children:
            return "1" if node.operator == "AND" else "0"
        joiner = " AND " if node.operator == "AND" else " OR "
        return "(" + joiner.join(compile_ast(child) for child in node.children) + ")"
    if isinstance(node, qp.NotNode):
        return f"NOT ({compile_ast(node.child)})"
    if isinstance(node, qp.FreeTextNode):
        return f"arrayExists(b -> position(b, {quote(node.text.lower())}) > 0, search_blobs)"
    raise ValueError(f"unsupported query node {type(node).__name__}")


def compile_query(query: str) -> str:
    """WHERE clause for a search query; a query that doesn't parse matches nothing, like ``apply_filters``."""
    if not query or not query.strip():
        return "1"
    ast = qp.parse_query_to_ast(query, duration_parser=parse_duration_to_nanoseconds)
    if ast is None:
        return "0"
    return compile_ast(ast)
