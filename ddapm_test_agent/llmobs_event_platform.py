"""LLM Observability Event Platform API."""

from datetime import datetime
import gzip
import json
import logging
import re
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
import uuid

from aiohttp import web
from aiohttp.web import Request
import msgpack


log = logging.getLogger(__name__)

# CORS headers for cross-origin requests from Datadog UI
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, "
    "X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, "
    "X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
}


def _make_facet(
    path: str,
    name: str,
    groups: List[str],
    source: str = "log",
    facet_type: str = "list",
    data_type: str = "string",
    unit_family: str = "",
    unit_name: str = "",
    description: str = "",
) -> Dict[str, Any]:
    """Create a facet definition with standard defaults."""
    prefix = "tag" if source == "tag" else "log"
    return {
        "id": f"{prefix}_{path}",
        "path": path,
        "name": name,
        "description": description or name,
        "source": source,
        "type": data_type,
        "facetType": facet_type,
        "values": [],
        "defaultValues": [],
        "groups": groups,
        "editable": False,
        "bounded": False,
        "bundled": True,
        "bundledAndUsed": True,
        "rumV2": False,
        "unit": {"family": unit_family, "name": unit_name},
    }


# Facet definitions for LLMObs explorer sidebar
LLMOBS_FACETS = [
    _make_facet("ml_app", "ML Application", ["core"]),
    _make_facet("status", "Status", ["core"], description="Denotes the status"),
    _make_facet("meta.span.kind", "Span Kind", ["llm"], description="Type of work unit handled by the span"),
    _make_facet("name", "Span Name", ["llm"], description="Name of the span event"),
    _make_facet("meta.model_name", "Model Name", ["llm"]),
    _make_facet("meta.model_provider", "Model Provider", ["llm"]),
    _make_facet("service", "Service", ["core"], source="tag", description="Service name for this application."),
    _make_facet("env", "Env", ["core"], source="tag", description="Environment"),
    _make_facet(
        "duration",
        "Duration",
        ["core"],
        facet_type="range",
        data_type="double",
        unit_family="time",
        unit_name="nanosecond",
    ),
    _make_facet(
        "metrics.input_tokens", "Input Tokens", ["cost"], facet_type="range", data_type="integer", description=""
    ),
    _make_facet(
        "metrics.output_tokens", "Output Tokens", ["cost"], facet_type="range", data_type="integer", description=""
    ),
    _make_facet(
        "metrics.total_tokens", "Total Tokens", ["cost"], facet_type="range", data_type="integer", description=""
    ),
    _make_facet(
        "metrics.estimated_total_cost",
        "Estimated Total Cost",
        ["cost"],
        facet_type="range",
        data_type="integer",
        unit_family="money",
        unit_name="nanodollar",
        description="",
    ),
    _make_facet("session_id", "Session ID", ["other"]),
    _make_facet("meta.error.type", "Error Type", ["core"]),
]


def decode_llmobs_payload(data: bytes, content_type: str) -> List[Dict[str, Any]]:
    """Decode LLMObs payload (gzip+msgpack or JSON)."""
    events = []
    try:
        if content_type and "gzip" in content_type.lower():
            data = gzip.decompress(data)

        if content_type and "msgpack" in content_type.lower():
            payload = msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                payload = msgpack.unpackb(data, raw=False, strict_map_key=False)

        if isinstance(payload, list):
            events.extend(payload)
        else:
            events.append(payload)
    except Exception as e:
        log.warning(f"Failed to decode LLMObs payload: {e}")
    return events


def extract_spans_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract individual spans from LLMObs event payloads."""
    spans = []
    for event in events:
        event_ml_app = event.get("ml_app", "")
        event_tags = event.get("tags", [])

        for span in event.get("spans", []):
            span_tags = span.get("tags", [])
            if event_tags:
                span_tags = list(set(span_tags + event_tags))
            span["tags"] = span_tags
            span = remap_sdk_span_to_ui_format(span, event_ml_app)
            spans.append(span)
    return spans


def remap_sdk_span_to_ui_format(span: Dict[str, Any], event_ml_app: str = "") -> Dict[str, Any]:
    """Remap span from SDK format to UI-expected format (extract ml_app, service, env from tags)."""
    tags = span.get("tags", [])
    extracted = extract_fields_from_tags(tags)

    ml_app = extracted.get("ml_app") or event_ml_app or span.get("ml_app", "unknown")
    span["ml_app"] = ml_app

    if "service" not in span or not span["service"]:
        span["service"] = extracted.get("service", "")
    if "env" not in span or not span["env"]:
        span["env"] = extracted.get("env", "")

    meta = span.get("meta", {})
    span_kind = meta.get("span", {}).get("kind", "llm")

    if "meta" not in span:
        span["meta"] = {}
    if "span" not in span["meta"]:
        span["meta"]["span"] = {}
    span["meta"]["span"]["kind"] = span_kind
    span["_ui_kind"] = span_kind
    span["_ui_ml_app"] = ml_app

    return span


def extract_fields_from_tags(tags: List[str]) -> Dict[str, str]:
    """Extract ml_app, service, env, etc. from tags array."""
    result = {}
    fields_to_extract = ["ml_app", "service", "env", "version", "source", "language"]
    for tag in tags:
        if not isinstance(tag, str) or ":" not in tag:
            continue
        key, value = tag.split(":", 1)
        if key in fields_to_extract:
            result[key] = value
    return result


DURATION_MULTIPLIERS = {
    "ns": 1,
    "us": 1_000,
    "μs": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}


def parse_duration_to_nanoseconds(duration_str: str) -> Optional[float]:
    """Parse duration string (e.g., '5.5s', '100ms') to nanoseconds."""
    duration_str = duration_str.strip()
    match = re.match(r"^([0-9]*\.?[0-9]+)(ns|μs|us|ms|s|m|h)$", duration_str, re.IGNORECASE)

    if not match:
        try:
            return float(duration_str)
        except ValueError:
            return None

    value = float(match.group(1))
    unit = match.group(2).lower()
    return value * DURATION_MULTIPLIERS.get(unit, 1)


def parse_filter_query(query: str) -> Dict[str, Any]:
    """Parse filter query string into filters and text search."""
    result: Dict[str, Any] = {"filters": [], "text_search": ""}
    if not query:
        return result

    remaining = query

    # Range filters: @field:[min TO max]
    for field, min_val, max_val in re.findall(r"@([\w.]+):\[([^\]]+)\s+TO\s+([^\]]+)\]", remaining, re.IGNORECASE):
        f: Dict[str, Any] = {"field": field, "type": "facet", "operator": "range"}
        if field == "duration":
            min_ns, max_ns = parse_duration_to_nanoseconds(min_val.strip()), parse_duration_to_nanoseconds(
                max_val.strip()
            )
            if min_ns is not None:
                f["min"] = min_ns
            if max_ns is not None:
                f["max"] = max_ns
        else:
            try:
                f["min"] = float(min_val.strip())
            except ValueError:
                f["min"] = min_val.strip()
            try:
                f["max"] = float(max_val.strip())
            except ValueError:
                f["max"] = max_val.strip()
        result["filters"].append(f)
    remaining = re.sub(r"@([\w.]+):\[([^\]]+)\s+TO\s+([^\]]+)\]", "", remaining, flags=re.IGNORECASE)

    # Comparison filters: @field:>=value, @field:<=value, etc.
    op_map = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
    for field, op, value in re.findall(r"@([\w.]+):(>=|<=|>|<)([^\s]+)", remaining):
        f = {"field": field, "type": "facet", "operator": op_map[op]}
        if field == "duration":
            parsed = parse_duration_to_nanoseconds(value)
            if parsed is not None:
                f["value"] = parsed
        else:
            try:
                f["value"] = float(value)
            except ValueError:
                f["value"] = value
        result["filters"].append(f)
    remaining = re.sub(r"@([\w.]+):(>=|<=|>|<)([^\s]+)", "", remaining)

    # Facet filters: @field:value
    for field, value in re.findall(r"@([\w.]+):([^\s\[]+)", remaining):
        if not value.startswith((">=", "<=", ">", "<")):
            result["filters"].append({"field": field, "value": value, "type": "facet"})
    remaining = re.sub(r"@([\w.]+):([^\s\[]+)", "", remaining)

    # Tag filters: field:value (without @)
    for field, value in re.findall(r"(?<!\S)([\w.]+):([^\s]+)", remaining):
        result["filters"].append({"field": field, "value": value, "type": "tag"})
    remaining = re.sub(r"(?<!\S)([\w.]+):([^\s]+)", "", remaining)

    result["text_search"] = remaining.strip()
    return result


def match_wildcard(value: str, pattern: str) -> bool:
    """Match value against pattern with wildcard support (*). Case-insensitive."""
    v, p = value.lower(), pattern.lower()
    if p == "*":
        return True
    if p.startswith("*") and p.endswith("*"):
        return p[1:-1] in v
    if p.startswith("*"):
        return v.endswith(p[1:])
    if p.endswith("*"):
        return v.startswith(p[:-1])
    return v == p


def apply_filters(spans: List[Dict[str, Any]], parsed_query: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply filter conditions and text search to spans."""
    filters = parsed_query.get("filters", [])
    text_search = parsed_query.get("text_search", "").lower()

    if not filters and not text_search:
        return spans

    filtered = []
    for span in spans:
        if not _span_matches_filters(span, filters):
            continue
        if text_search and not text_search_span(span, text_search):
            continue
        filtered.append(span)
    return filtered


def _span_matches_filters(span: Dict[str, Any], filters: List[Dict[str, Any]]) -> bool:
    """Check if span matches all filters."""
    for f in filters:
        field = f["field"]
        operator = f.get("operator")
        span_value = get_span_field_value(span, field)

        if operator == "range":
            if span_value is None:
                return False
            try:
                num = float(span_value)
                if f.get("min") is not None and num < f["min"]:
                    return False
                if f.get("max") is not None and num > f["max"]:
                    return False
            except (ValueError, TypeError):
                return False

        elif operator in ("gte", "lte", "gt", "lt"):
            if span_value is None or f.get("value") is None:
                return False
            try:
                num, cmp = float(span_value), f["value"]
                if operator == "gte" and num < cmp:
                    return False
                if operator == "lte" and num > cmp:
                    return False
                if operator == "gt" and num <= cmp:
                    return False
                if operator == "lt" and num >= cmp:
                    return False
            except (ValueError, TypeError):
                return False

        else:
            value = f.get("value")
            if value is None or value == "*":
                continue
            if span_value is None:
                return False
            if not match_wildcard(str(span_value), str(value)):
                return False

    return True


def text_search_span(span: Dict[str, Any], search_text: str) -> bool:
    """Check if span matches free text search (name, input, output, tags)."""
    s = search_text.lower()

    if s in span.get("name", "").lower():
        return True

    meta = span.get("meta", {})
    for key in ("input", "output"):
        data = meta.get(key, {})
        if s in str(data.get("value", "")).lower():
            return True
        for msg in data.get("messages", []):
            if isinstance(msg, dict) and s in str(msg.get("content", "")).lower():
                return True

    for tag in span.get("tags", []):
        if isinstance(tag, str) and s in tag.lower():
            return True

    return False


def compute_children_ids(spans: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Compute children_ids from parent_id relationships."""
    children_map: Dict[str, List[str]] = {span.get("span_id", ""): [] for span in spans if span.get("span_id")}

    for span in spans:
        span_id = span.get("span_id", "")
        parent_id = span.get("parent_id", "")
        if parent_id and parent_id != "undefined":
            if parent_id not in children_map:
                children_map[parent_id] = []
            children_map[parent_id].append(span_id)

    return children_map


def get_span_field_value(span: Dict[str, Any], field: str) -> Optional[Any]:
    """Get field value from span (handles nested paths like meta.span.kind)."""
    # Direct top-level fields
    direct_fields = {
        "ml_app": lambda s: s.get("ml_app", s.get("_ui_ml_app")),
        "event_type": lambda s: "span",
        "parent_id": lambda s: (
            "undefined" if not s.get("parent_id") or s.get("parent_id") in ("0", "") else str(s["parent_id"])
        ),
        "status": lambda s: s.get("status", "ok"),
        "name": lambda s: s.get("name"),
        "trace_id": lambda s: s.get("trace_id"),
        "span_id": lambda s: s.get("span_id"),
        "service": lambda s: s.get("service"),
        "env": lambda s: s.get("env"),
        "duration": lambda s: s.get("duration", 0),
    }
    if field in direct_fields:
        return direct_fields[field](span)

    meta = span.get("meta", {})

    # Model fields with fallback to SDK format
    if field == "meta.model_name":
        return meta.get("model_name") or meta.get("metadata", {}).get("model_name")
    if field == "meta.model_provider":
        return meta.get("model_provider") or meta.get("metadata", {}).get("model_provider")

    # Nested fields with dot notation
    if field.startswith("meta.") or field.startswith("metrics."):
        parts = field.split(".")
        value = span.get(parts[0], {})
        for part in parts[1:]:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    # Check in tags
    for tag in span.get("tags", []):
        if isinstance(tag, str) and tag.startswith(f"{field}:"):
            return tag.split(":", 1)[1]

    return None


def _tags_to_dict(tags: List[str]) -> Dict[str, Any]:
    """Convert tags array to dict, handling multiple values per key."""
    tag_obj: Dict[str, Any] = {}
    for tag in tags:
        if isinstance(tag, str) and ":" in tag:
            k, v = tag.split(":", 1)
            if k in tag_obj:
                if isinstance(tag_obj[k], list):
                    tag_obj[k].append(v)
                else:
                    tag_obj[k] = [tag_obj[k], v]
            else:
                tag_obj[k] = v
    return tag_obj


def build_event_platform_list_response(
    spans: List[Dict[str, Any]],
    request_id: str,
    limit: int = 100,
) -> Dict[str, Any]:
    """Build Event Platform list response from spans."""
    children_map = compute_children_ids(spans[:limit])
    events = []

    for span in spans[:limit]:
        meta = span.get("meta", {})
        metrics = span.get("metrics", {})
        span_id = span.get("span_id", str(uuid.uuid4()))
        trace_id = span.get("trace_id", "")
        status = span.get("status", "ok")
        name = span.get("name", "")
        duration = span.get("duration", 0)
        start_ns = span.get("start_ns", int(time.time() * 1_000_000_000))
        tags = span.get("tags", [])
        span_kind = meta.get("span", {}).get("kind", "llm")
        ml_app = span.get("ml_app", span.get("_ui_ml_app", "unknown"))
        service = span.get("service", "")
        env = span.get("env", "")
        children_ids = children_map.get(span_id, [])
        span_links = span.get("span_links", [])
        tag_obj = _tags_to_dict(tags)

        event_id = f"AZ{uuid.uuid4().hex[:20]}"
        timestamp_ms = start_ns // 1_000_000
        timestamp_iso = datetime.utcfromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Get model metadata
        model_metadata = meta.get("metadata", {})
        model_name = model_metadata.get("model_name", meta.get("model_name", ""))
        model_provider = model_metadata.get("model_provider", meta.get("model_provider", ""))

        # Compute start and end timestamps in milliseconds
        end_ns = start_ns + duration
        start_ms = start_ns // 1_000_000
        end_ms = end_ns // 1_000_000

        # Build the custom object (this is where the actual span data lives)
        # The UI accesses this via getMlObsAttrs(event) which returns event.custom
        custom_data = {
            "_dd": {
                "apm_trace_id": trace_id,
                "ootb_status": "success" if status == "ok" else "error",
                "stage": "processed",
                "document_version": 3,
            },
            "duration": duration,
            "start": start_ms,
            "end": end_ms,
            "event_type": "span",
            "kind": span_kind,  # Also at top level for easier access
            "meta": {
                "span": {
                    "kind": span_kind,
                },
                "kind": span_kind,  # Also directly in meta
                "input": meta.get("input", {}),
                "output": meta.get("output", {}),
                "error": meta.get("error") if status == "error" else None,
                "model_name": model_name,
                "model_provider": model_provider,
            },
            "metrics": {
                "input_tokens": metrics.get("input_tokens", 0),
                "output_tokens": metrics.get("output_tokens", 0),
                "total_tokens": metrics.get("total_tokens", 0),
                "estimated_input_cost": 0,
                "estimated_output_cost": 0,
                "estimated_total_cost": 0,
            },
            "ml_app": ml_app,
            "name": name,
            "resource": name,  # Usually same as name
            "parent_id": span.get("parent_id", "undefined"),
            "children_ids": children_ids,  # Computed from parent relationships
            "span_links": span_links,  # From SDK for agentic execution graph
            "span_id": span_id,
            "start_ns": start_ns,
            "status": status,
            "error": 1 if status == "error" else 0,
            "tags": tags,
            "trace_id": trace_id,
            "service": service,
            "env": env,
            "trace": {
                "estimated_total_cost": 0,
            },
        }

        # Build columns array [status, ?, ?, ml_app, service, ?, ?, duration]
        columns = [
            status,
            None,
            None,
            ml_app,
            service,
            None,
            None,
            duration,
        ]

        events.append(
            {
                "columns": columns,
                "datadog.index": "llmobs",
                "event": {
                    "custom": custom_data,
                    "discovery_timestamp": timestamp_ms,
                    "env": env,
                    "id": event_id,
                    "parent_id": span.get("parent_id", "undefined"),
                    "service": service,
                    "source": "integration",
                    "span_id": span_id,
                    "status": "info",
                    "tag": tag_obj,
                    "tags": tags,
                    "tiebreaker": hash(span_id) % 2147483647,
                    "timestamp": timestamp_iso,
                    "trace_id": trace_id,
                    "version": "",
                },
                "event_id": event_id,
                "id": f"AwAAA{uuid.uuid4().hex[:40]}",
            }
        )

    return {
        "elapsed": 23,
        "hitCount": len(events),
        "requestId": request_id,
        "result": {
            "events": events,
        },
        "status": "done",
        "type": "status",
    }


class LLMObsEventPlatformAPI:
    """Handler for Event Platform API requests.

    Provides endpoints that mimic Datadog's Event Platform API,
    allowing the Chrome extension to redirect UI requests here.
    """

    def __init__(self, agent: Any):
        self.agent = agent
        # Store active multi-step query results
        self._query_results: Dict[str, Dict[str, Any]] = {}
        # Cache for extracted spans (invalidated when request count changes)
        self._spans_cache: List[Dict[str, Any]] = []
        self._spans_cache_request_count: int = 0
        # Pre-computed facet values cache
        self._facet_values_cache: Dict[str, Dict[str, int]] = {}
        self._facet_range_cache: Dict[str, Dict[str, float]] = {}

    def _invalidate_cache_if_needed(self) -> bool:
        """Check if cache needs to be invalidated due to new requests."""
        current_count = len(self.agent._requests)
        if current_count != self._spans_cache_request_count:
            self._spans_cache = []
            self._facet_values_cache = {}
            self._facet_range_cache = {}
            self._spans_cache_request_count = current_count
            return True
        return False

    def get_llmobs_spans(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all LLMObs spans from stored requests with caching."""
        # For token-specific requests, don't use cache
        if token:
            return self._fetch_spans_from_requests(self.agent._requests_by_session(token))

        # Check if cache is still valid
        self._invalidate_cache_if_needed()

        # Return cached spans if available
        if self._spans_cache:
            return self._spans_cache

        # Fetch and cache spans
        self._spans_cache = self._fetch_spans_from_requests(self.agent._requests)
        return self._spans_cache

    def _fetch_spans_from_requests(self, requests) -> List[Dict[str, Any]]:
        """Fetch spans from requests without caching."""
        all_spans = []

        for req in requests:
            # Check if this is an LLMObs request
            if req.path == "/evp_proxy/v2/api/v2/llmobs":
                try:
                    data = self.agent._request_data(req)
                    content_type = req.content_type or ""
                    events = decode_llmobs_payload(data, content_type)
                    spans = extract_spans_from_events(events)
                    all_spans.extend(spans)
                except Exception as e:
                    log.warning(f"Failed to extract spans from request: {e}")

        # Sort by start time (most recent first)
        all_spans.sort(key=lambda s: s.get("start_ns", 0), reverse=True)

        return all_spans

    def get_facet_values(self, field_path: str, limit: int = 10) -> List[tuple]:
        """Get facet values with caching."""
        self._invalidate_cache_if_needed()

        # Check cache
        if field_path in self._facet_values_cache:
            cached = self._facet_values_cache[field_path]
            sorted_values = sorted(cached.items(), key=lambda x: -x[1])[:limit]
            return sorted_values

        # Compute facet values
        spans = self.get_llmobs_spans()
        value_counts: Dict[str, int] = {}

        for span in spans:
            value = get_span_field_value(span, field_path)
            if value is not None:
                value_str = str(value)
                value_counts[value_str] = value_counts.get(value_str, 0) + 1

        # Cache and return
        self._facet_values_cache[field_path] = value_counts
        sorted_values = sorted(value_counts.items(), key=lambda x: -x[1])[:limit]
        return sorted_values

    def get_facet_range(self, field_path: str) -> Dict[str, float]:
        """Get facet range (min/max) with caching."""
        self._invalidate_cache_if_needed()

        # Check cache
        if field_path in self._facet_range_cache:
            return self._facet_range_cache[field_path]

        # Compute range
        spans = self.get_llmobs_spans()
        values = []

        for span in spans:
            value = get_span_field_value(span, field_path)
            if value is not None:
                try:
                    values.append(float(value))
                except (ValueError, TypeError):
                    pass

        result = {
            "min": min(values) if values else 0,
            "max": max(values) if values else 0,
        }

        # Cache and return
        self._facet_range_cache[field_path] = result
        return result

    async def handle_logs_analytics_list(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/list endpoint.

        This is the main entry point for LLM Obs list queries.
        """
        # Add CORS headers for cross-origin requests from Datadog
        headers = CORS_HEADERS

        # Handle OPTIONS preflight
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            # Parse query type from URL
            query_type = request.query.get("type", "")

            # Only handle llmobs queries
            if query_type != "llmobs":
                return web.json_response(
                    {"error": "Only llmobs queries are supported"},
                    status=400,
                    headers=headers,
                )

            # Parse request body
            body = await request.json()
            log.info(f"Event Platform list query: {json.dumps(body, indent=2)[:500]}")

            # Extract query parameters
            list_params = body.get("list", {})
            limit = list_params.get("limit", 100)

            # Extract filter query string from list.search.query
            search_params = list_params.get("search", {})
            query_str = search_params.get("query", "")

            # Get spans from stored requests
            spans = self.get_llmobs_spans()

            # Apply filters if query is provided
            if query_str:
                parsed_query = parse_filter_query(query_str)
                spans = apply_filters(spans, parsed_query)

            # Generate request ID for multi-step queries
            request_id = str(uuid.uuid4())

            # Build and return response
            response = build_event_platform_list_response(spans, request_id, limit)

            # Store for potential subsequent GET requests
            self._query_results[request_id] = response

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling llm-obs list: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_logs_analytics_get(self, request: Request) -> web.Response:
        """Handle GET /api/unstable/llm-obs-query-rewriter/list/{requestId} endpoint.

        This is for multi-step query polling.
        """
        headers = CORS_HEADERS

        # Handle OPTIONS preflight
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            request_id = request.match_info.get("request_id", "")

            if request_id in self._query_results:
                response = self._query_results[request_id]
                return web.json_response(response, headers=headers)
            else:
                # Request ID not found or expired
                return web.Response(status=410, headers=headers)  # Gone

        except Exception as e:
            log.error(f"Error handling llm-obs get: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_aggregate(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/aggregate endpoint.

        Returns aggregated metrics for LLM Observability data.
        """
        headers = CORS_HEADERS

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            body = await request.json()
            log.info(f"Event Platform aggregate query: {json.dumps(body, indent=2)[:500]}")

            # Get spans from stored requests
            spans = self.get_llmobs_spans()

            # Build a simple aggregate response
            # The UI uses this for counts and facet values
            response = {
                "elapsed": 50,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "buckets": [{"computes": {"c0": len(spans)}}],  # Total count
                    "status": "done",
                },
                "status": "done",
                "type": "aggregate",
            }

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling aggregate: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_facet_info(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/facet_info endpoint.

        Returns facet values with counts for the specified facet path.
        """
        headers = CORS_HEADERS

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            body = await request.json()
            log.debug(f"facet_info request: {json.dumps(body, indent=2)[:500]}")

            facet_info = body.get("facet_info", {})
            facet_path = facet_info.get("path", "")
            limit = facet_info.get("limit", 10)
            term_search = facet_info.get("termSearch", {}).get("query", "")

            # Strip @ prefix for field lookup
            field_path = facet_path.lstrip("@")

            # Use cached facet values for fast response
            sorted_values = self.get_facet_values(field_path, limit)

            # Apply term search filter if provided
            if term_search:
                term_lower = term_search.lower()
                sorted_values = [(v, c) for v, c in sorted_values if term_lower in v.lower()][:limit]

            # Build response
            fields = [{"field": value, "value": count} for value, count in sorted_values]

            response = {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "fields": fields,
                    "status": "done",
                },
                "status": "done",
            }

            log.debug(f"facet_info response for {facet_path}: {len(fields)} values")
            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling facet info: {e}")
            import traceback

            traceback.print_exc()
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_facet_range_info(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/facet_range_info endpoint.

        Returns min/max values for range facets like duration, tokens, cost.
        """
        headers = CORS_HEADERS

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            body = await request.json()
            log.debug(f"facet_range_info request: {json.dumps(body, indent=2)[:500]}")

            facet_range_info = body.get("facet_range_info", {})
            facet_path = facet_range_info.get("path", "")

            # Strip @ prefix for field lookup
            field_path = facet_path.lstrip("@")

            # Use cached facet range for fast response
            range_data = self.get_facet_range(field_path)

            response = {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "min": range_data["min"],
                    "max": range_data["max"],
                    "status": "done",
                },
                "status": "done",
            }

            log.debug(f"facet_range_info response for {facet_path}: min={range_data['min']}, max={range_data['max']}")
            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling facet range info: {e}")
            import traceback

            traceback.print_exc()
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_facets_list(self, request: Request) -> web.Response:
        """Handle GET /api/ui/event-platform/llmobs/facets endpoint.

        Returns the list of available facets for the LLMObs explorer sidebar.
        Format matches the Datadog backend response exactly.
        """
        headers = CORS_HEADERS

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            return web.json_response({"facets": {"llmobs": LLMOBS_FACETS}}, headers=headers)
        except Exception as e:
            log.error(f"Error handling facets list: {e}")
            return web.json_response({"error": str(e)}, status=500, headers=headers)

    async def handle_fetch_one(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/fetch_one endpoint."""
        headers = CORS_HEADERS

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            body = await request.json()
            log.info(f"fetch_one request: {json.dumps(body, indent=2)[:500]}")

            # Extract the event ID from the request
            event_id = body.get("eventId", "")
            # The eventId might be in format like "AwAAA..." or just the span_id

            # Get all spans and find the matching one
            spans = self.get_llmobs_spans()

            # Try to find the span by span_id
            found_span = None
            for span in spans:
                span_id = span.get("span_id", "")
                if span_id == event_id or event_id.endswith(span_id):
                    found_span = span
                    break

            if not found_span:
                # If not found by exact match, return the first span for now
                # (the UI might be using a different ID format)
                if spans:
                    found_span = spans[0]
                    log.warning(f"Span not found by ID {event_id}, returning first span")
                else:
                    return web.json_response(
                        {"error": "Span not found"},
                        status=404,
                        headers=headers,
                    )

            # Build the response in the same format as list response but for single event
            meta = found_span.get("meta", {})
            metrics = found_span.get("metrics", {})
            span_id = found_span.get("span_id", str(uuid.uuid4()))
            trace_id = found_span.get("trace_id", "")
            status = found_span.get("status", "ok")
            name = found_span.get("name", "")
            duration = found_span.get("duration", 0)
            start_ns = found_span.get("start_ns", int(time.time() * 1_000_000_000))
            tags = found_span.get("tags", [])

            # Get span kind from meta.span.kind (SDK format)
            span_meta = meta.get("span", {})
            span_kind = span_meta.get("kind", "llm")

            # Get ml_app from remapped top-level field
            ml_app = found_span.get("ml_app", found_span.get("_ui_ml_app", "unknown"))

            # Get service and env (remapped from tags)
            service = found_span.get("service", "")
            env = found_span.get("env", "")

            # Build tag object
            tag_obj = {}
            for tag in tags:
                if isinstance(tag, str) and ":" in tag:
                    k, v = tag.split(":", 1)
                    tag_obj[k] = v

            timestamp_ms = start_ns // 1_000_000
            timestamp_iso = datetime.utcfromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            log.info(f"fetch_one: name={name}, kind={span_kind}, ml_app={ml_app}")

            # Get model metadata
            model_metadata = meta.get("metadata", {})
            model_name = model_metadata.get("model_name", meta.get("model_name", ""))
            model_provider = model_metadata.get("model_provider", meta.get("model_provider", ""))

            custom_data = {
                "_dd": {
                    "apm_trace_id": trace_id,
                    "ootb_status": "success" if status == "ok" else "error",
                    "stage": "processed",
                    "document_version": 3,
                },
                "duration": duration,
                "event_type": "span",
                "kind": span_kind,  # Also at top level
                "meta": {
                    "span": {
                        "kind": span_kind,
                    },
                    "kind": span_kind,  # Also directly in meta
                    "input": meta.get("input", {}),
                    "output": meta.get("output", {}),
                    "error": meta.get("error") if status == "error" else None,
                    "model_name": model_name,
                    "model_provider": model_provider,
                },
                "metrics": {
                    "input_tokens": metrics.get("input_tokens", 0),
                    "output_tokens": metrics.get("output_tokens", 0),
                    "total_tokens": metrics.get("total_tokens", 0),
                },
                "ml_app": ml_app,
                "name": name,
                "parent_id": found_span.get("parent_id", "undefined"),
                "span_id": span_id,
                "start_ns": start_ns,
                "status": status,
                "tags": tags,
                "trace_id": trace_id,
            }

            response = {
                "type": "status",
                "requestId": str(uuid.uuid4()),
                "status": "done",
                "elapsed": 21,
                "hitCount": 1,
                "result": {
                    "trace_id": trace_id,
                    "span_id": span_id,
                    "custom": custom_data,
                    "trace_id_low": trace_id,
                    "source": "integration",
                    "tiebreaker": hash(span_id) % 2147483647,
                    "env": env,
                    "version": "",
                    "discovery_timestamp": timestamp_ms,
                    "tags": tags,
                    "event_id": event_id,
                    "service": service,
                    "parent_id": found_span.get("parent_id", "undefined"),
                    "datadog.index": "llmobs",
                    "id": event_id,
                    "tag": tag_obj,
                    "timestamp": timestamp_iso,
                    "status": "info",
                },
            }

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling fetch_one: {e}")
            import traceback

            traceback.print_exc()
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_trace(self, request: Request) -> web.Response:
        """Handle GET /api/ui/llm-obs/v1/trace/{trace_id} endpoint.

        Returns full trace data with all spans for the trace detail view.
        """
        headers = CORS_HEADERS

        log.info(f"handle_trace called: method={request.method}, path={request.path}, query={request.query_string}")

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            trace_id = request.match_info.get("trace_id", "")
            span_id_filter = request.query.get("filter[span_id]", "")

            log.info(f"trace request: trace_id={trace_id}, span_id={span_id_filter}")

            # Get all spans and filter by trace_id
            all_spans = self.get_llmobs_spans()
            trace_spans = [s for s in all_spans if s.get("trace_id") == trace_id]

            # If no spans found for trace_id, try to find by span_id
            if not trace_spans and span_id_filter:
                trace_spans = [s for s in all_spans if s.get("span_id") == span_id_filter]

            # If still nothing, return first span as fallback
            if not trace_spans and all_spans:
                trace_spans = [all_spans[0]]
                log.warning(f"Trace {trace_id} not found, returning first span")

            if not trace_spans:
                return web.json_response(
                    {"error": "Trace not found"},
                    status=404,
                    headers=headers,
                )

            # Compute children_ids from parent_id relationships
            children_map = compute_children_ids(trace_spans)

            # Build spans dict keyed by span_id
            spans_dict = {}
            root_id = None

            for span in trace_spans:
                span_id = span.get("span_id", "")
                meta = span.get("meta", {})
                metrics = span.get("metrics", {})
                tags = span.get("tags", [])

                # Get span kind from meta.span.kind (SDK format)
                span_meta = meta.get("span", {})
                span_kind = span_meta.get("kind", "llm")

                # Get ml_app from remapped top-level field
                ml_app = span.get("ml_app", span.get("_ui_ml_app", "unknown"))

                # Get service (remapped from tags)
                service = span.get("service", "")

                # Get children_ids from computed map
                children_ids = children_map.get(span_id, [])

                # Get span_links from SDK (for cross-span relationships)
                span_links = span.get("span_links", [])

                # Debug log
                log.info(
                    f"Trace span: span_id={span_id}, name={span.get('name')}, kind={span_kind}, ml_app={ml_app}, children={children_ids}"
                )

                # Determine root span (no parent or parent is "undefined")
                parent_id = span.get("parent_id", "undefined")
                if not root_id and (not parent_id or parent_id == "undefined"):
                    root_id = span_id

                # Get model metadata
                model_metadata = meta.get("metadata", {})
                model_name = model_metadata.get("model_name", meta.get("model_name", ""))
                model_provider = model_metadata.get("model_provider", meta.get("model_provider", ""))

                # Compute start and end timestamps in milliseconds
                start_ns = span.get("start_ns", 0)
                duration_ns = span.get("duration", 0)
                start_ms = start_ns // 1_000_000
                end_ms = (start_ns + duration_ns) // 1_000_000

                spans_dict[span_id] = {
                    "trace_id": span.get("trace_id", ""),
                    "span_id": span_id,
                    "parent_id": parent_id,
                    "children_ids": children_ids,  # Computed from parent relationships
                    "span_links": span_links,  # From SDK for cross-span relationships
                    "name": span.get("name", ""),
                    "resource": span.get("name", ""),  # Usually same as name
                    "tags": tags,
                    "status": span.get("status", "ok"),
                    "error": 1 if span.get("status") == "error" else 0,
                    "start": start_ms,
                    "end": end_ms,
                    "duration": duration_ns,
                    "service": service,
                    "env": span.get("env", ""),
                    "ml_app": ml_app,
                    "kind": span_kind,  # Also at top level
                    "meta": {
                        "ml_app": ml_app,
                        "kind": span_kind,  # Also directly in meta
                        "span": {
                            "kind": span_kind,
                        },
                        "error": meta.get("error", {}),
                        "input": meta.get("input", {}),
                        "output": meta.get("output", {}),
                        "expected_output": {},
                        "model_name": model_name,
                        "model_provider": model_provider,
                    },
                    "metrics": metrics,
                    "_dd": {
                        "apm_trace_id": span.get("trace_id", ""),
                    },
                }

            # If no root found, use first span
            if not root_id and spans_dict:
                root_id = list(spans_dict.keys())[0]

            response = {
                "data": {
                    "id": str(uuid.uuid4()),
                    "type": "trace",
                    "attributes": {
                        "root_id": root_id,
                        "spans": spans_dict,
                        "trace_state": {
                            "Error": "",
                            "warnings": None,
                            "convention_violations": {},
                        },
                    },
                },
            }

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling trace: {e}")
            import traceback

            traceback.print_exc()
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        return [
            # Facets list endpoint (returns available facets for sidebar)
            web.get("/api/ui/event-platform/llmobs/facets", self.handle_facets_list),
            web.options("/api/ui/event-platform/llmobs/facets", self.handle_facets_list),
            # New LLM Obs query rewriter endpoints (used by Datadog UI)
            web.post("/api/unstable/llm-obs-query-rewriter/list", self.handle_logs_analytics_list),
            web.get("/api/unstable/llm-obs-query-rewriter/list/{request_id}", self.handle_logs_analytics_get),
            web.options("/api/unstable/llm-obs-query-rewriter/list", self.handle_logs_analytics_list),
            web.options("/api/unstable/llm-obs-query-rewriter/list/{request_id}", self.handle_logs_analytics_get),
            web.post("/api/unstable/llm-obs-query-rewriter/aggregate", self.handle_aggregate),
            web.options("/api/unstable/llm-obs-query-rewriter/aggregate", self.handle_aggregate),
            web.post("/api/unstable/llm-obs-query-rewriter/facet_info", self.handle_facet_info),
            web.options("/api/unstable/llm-obs-query-rewriter/facet_info", self.handle_facet_info),
            web.post("/api/unstable/llm-obs-query-rewriter/facet_range_info", self.handle_facet_range_info),
            web.options("/api/unstable/llm-obs-query-rewriter/facet_range_info", self.handle_facet_range_info),
            # Fetch one endpoint for detail view
            web.post("/api/unstable/llm-obs-query-rewriter/fetch_one", self.handle_fetch_one),
            web.options("/api/unstable/llm-obs-query-rewriter/fetch_one", self.handle_fetch_one),
            # Legacy logs-analytics endpoints (fallback)
            web.post("/api/v1/logs-analytics/list", self.handle_logs_analytics_list),
            web.get("/api/v1/logs-analytics/list/{request_id}", self.handle_logs_analytics_get),
            web.options("/api/v1/logs-analytics/list", self.handle_logs_analytics_list),
            web.options("/api/v1/logs-analytics/list/{request_id}", self.handle_logs_analytics_get),
            web.post("/api/v1/logs-analytics/aggregate", self.handle_aggregate),
            web.options("/api/v1/logs-analytics/aggregate", self.handle_aggregate),
            web.post("/api/v1/logs-analytics/fetch_one", self.handle_fetch_one),
            web.options("/api/v1/logs-analytics/fetch_one", self.handle_fetch_one),
            # LLM Obs trace endpoint for detail view
            web.get("/api/ui/llm-obs/v1/trace/{trace_id}", self.handle_trace),
            web.options("/api/ui/llm-obs/v1/trace/{trace_id}", self.handle_trace),
        ]
