"""ClickHouse schema for ``lapdog server`` and the span-to-row mapping."""

import json
import threading
import time
from typing import Any
from typing import Dict
from typing import List

from ..llmobs_event_platform import _resolve_span_kind
from .clickhouse import ClickHouseClient
from .clickhouse import quote_identifier

SCHEMA_VERSION = 1


def spans_ttl(retention_days: int) -> str:
    return f"toDateTime(start_time) + INTERVAL {int(retention_days)} DAY DELETE"


def spans_ddl(database: str, retention_days: int) -> str:
    # ReplacingMergeTree keeps the highest ``version`` per (trace_id, span_id), so
    # a span update is a new row; reads use FINAL to see the merged result.
    # Daily partitions make retention and the disk cap cheap whole-day drops.
    return f"""
CREATE TABLE IF NOT EXISTS {quote_identifier(database)}.spans
(
    start_ns Int64,
    start_time DateTime64(9, 'UTC') DEFAULT fromUnixTimestamp64Nano(start_ns, 'UTC'),
    duration Float64,
    trace_id String,
    span_id String,
    parent_id String,
    name Nullable(String),
    status LowCardinality(Nullable(String)),
    kind LowCardinality(String),
    ml_app LowCardinality(String),
    service LowCardinality(String),
    env LowCardinality(String),
    session_id String,
    hostname String,
    model_name LowCardinality(Nullable(String)),
    model_provider LowCardinality(Nullable(String)),
    metrics Map(String, Float64),
    tags Array(String),
    search_blobs Array(String) CODEC(ZSTD(3)),
    span_json String CODEC(ZSTD(3)),
    num_evals_failed UInt32,
    version UInt64,
    INDEX idx_start start_ns TYPE minmax GRANULARITY 1,
    INDEX idx_session session_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_span span_id TYPE bloom_filter GRANULARITY 4
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toDate(start_time)
ORDER BY (trace_id, span_id)
TTL {spans_ttl(retention_days)}
SETTINGS ttl_only_drop_parts = 1
"""


async def ensure_schema(client: ClickHouseClient, database: str, retention_days: int) -> None:
    db = quote_identifier(database)
    await client.command(f"CREATE DATABASE IF NOT EXISTS {db}")
    await client.command(spans_ddl(database, retention_days))
    # CREATE TABLE IF NOT EXISTS keeps an existing table's TTL, so apply a changed retention here.
    await client.command(
        f"ALTER TABLE {db}.spans MODIFY TTL {spans_ttl(retention_days)}",
        {"materialize_ttl_after_modify": 0},
    )
    await client.command(
        f"CREATE TABLE IF NOT EXISTS {db}.schema_version (version UInt32, applied_at DateTime DEFAULT now()) "
        "ENGINE = MergeTree ORDER BY version"
    )
    rows = await client.query(f"SELECT max(version) AS v FROM {db}.schema_version")
    if not rows or not rows[0].get("v"):
        await client.insert(f"{db}.schema_version", [{"version": SCHEMA_VERSION}])


class _VersionClock:
    """Monotonic row versions, so a later write of the same span always wins."""

    def __init__(self) -> None:
        self._last = 0
        self._lock = threading.Lock()

    def next_version(self) -> int:
        with self._lock:
            self._last = max(time.time_ns(), self._last + 1)
            return self._last


next_version = _VersionClock().next_version


def _str_or_empty(value: Any) -> str:
    return "" if value is None else str(value)


def _optional_str(value: Any) -> Any:
    return None if value is None else str(value)


def search_blobs(span: Dict[str, Any]) -> List[str]:
    """Lower-cased strings that free-text search matches, mirroring ``text_search_span``."""
    blobs = [str(span.get("name", "")).lower()]
    meta = span.get("meta") or {}
    for key in ("input", "output"):
        data = meta.get(key) or {}
        if not isinstance(data, dict):
            continue
        blobs.append(str(data.get("value", "")).lower())
        for msg in data.get("messages") or []:
            if isinstance(msg, dict):
                blobs.append(str(msg.get("content", "")).lower())
    blobs.extend(tag.lower() for tag in span.get("tags", []) if isinstance(tag, str))
    return [blob for blob in blobs if blob]


def count_failed_evaluations(span: Dict[str, Any]) -> int:
    evaluation = span.get("evaluation") or {}
    if not isinstance(evaluation, dict):
        return 0
    return sum(1 for metric in evaluation.values() if isinstance(metric, dict) and metric.get("assessment") == "fail")


def span_to_row(span: Dict[str, Any], version: int) -> Dict[str, Any]:
    """Map a remapped span dict (as the in-memory store holds it) to a ``spans`` row.

    The full span is kept in ``span_json`` for building responses; the other
    columns exist to filter, group, and aggregate in SQL.
    """
    if not isinstance(span.get("start_ns"), (int, float)) or isinstance(span.get("start_ns"), bool):
        span["start_ns"] = time.time_ns()
    span["start_ns"] = int(span["start_ns"])
    meta = span.get("meta") or {}
    metadata = meta.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    metrics = {
        str(key): float(value)
        for key, value in (span.get("metrics") or {}).items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    duration = span.get("duration", 0)
    return {
        "start_ns": span["start_ns"],
        "duration": float(duration) if isinstance(duration, (int, float)) and not isinstance(duration, bool) else 0.0,
        "trace_id": _str_or_empty(span.get("trace_id")),
        "span_id": _str_or_empty(span.get("span_id")),
        "parent_id": _str_or_empty(span.get("parent_id")),
        "name": _optional_str(span.get("name")),
        "status": _optional_str(span.get("status", "ok")),
        "kind": _resolve_span_kind(span),
        "ml_app": _str_or_empty(span.get("ml_app", span.get("_ui_ml_app"))),
        "service": _str_or_empty(span.get("service")),
        "env": _str_or_empty(span.get("env")),
        "session_id": _str_or_empty(span.get("session_id")),
        "hostname": _str_or_empty(span.get("hostname")),
        "model_name": _optional_str(meta.get("model_name") or metadata.get("model_name")),
        "model_provider": _optional_str(meta.get("model_provider") or metadata.get("model_provider")),
        "metrics": metrics,
        "tags": [tag for tag in span.get("tags", []) if isinstance(tag, str)],
        "search_blobs": search_blobs(span),
        "span_json": json.dumps(span, separators=(",", ":"), default=str),
        "num_evals_failed": count_failed_evaluations(span),
        "version": version,
    }
