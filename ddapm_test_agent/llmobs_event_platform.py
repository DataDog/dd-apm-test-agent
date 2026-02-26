"""LLM Observability Event Platform API."""

from datetime import datetime
import gzip
import json
import logging
import re
import time
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
import uuid

from aiohttp import web
from aiohttp.web import Request
import msgpack

from . import llmobs_query_parser

if TYPE_CHECKING:
    from .agent import Agent
    from .claude_hooks import ClaudeHooksAPI

log = logging.getLogger(__name__)

# CORS headers for cross-origin requests from Datadog UI
CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, "
    "X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, "
    "X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
}


def with_cors(
    handler: Callable[[Request], Awaitable[web.StreamResponse]],
) -> Callable[[Request], Awaitable[web.StreamResponse]]:
    """Wrap handler to add CORS headers and handle OPTIONS preflight."""

    async def wrapper(request: Request) -> web.StreamResponse:
        if request.method == "OPTIONS":
            return web.Response(status=200, headers=CORS_HEADERS)
        response = await handler(request)
        response.headers.update(CORS_HEADERS)
        return response

    return wrapper


def _deep_merge(source: Dict[str, Any], target: Dict[str, Any]) -> None:
    """Recursively merge source into target. Overwrites non-dict values."""
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            _deep_merge(value, target[key])
        else:
            target[key] = value


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
    """Remap span from SDK format to UI-expected format (extract ml_app, service, env, session_id from tags)."""
    tags = span.get("tags", [])
    extracted = extract_fields_from_tags(tags)

    ml_app = extracted.get("ml_app") or event_ml_app or span.get("ml_app", "unknown")
    span["ml_app"] = ml_app

    if "service" not in span or not span["service"]:
        span["service"] = extracted.get("service", "")
    if "env" not in span or not span["env"]:
        span["env"] = extracted.get("env", "")

    # session_id: prefer top-level field, fall back to tag extraction
    if "session_id" not in span or not span["session_id"]:
        span["session_id"] = extracted.get("session_id", "")

    # hostname: prefer top-level field, fall back to tag extraction
    if "hostname" not in span or not span["hostname"]:
        span["hostname"] = extracted.get("hostname", "")

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
    """Extract ml_app, service, env, session_id, etc. from tags array."""
    result = {}
    fields_to_extract = ["ml_app", "service", "env", "version", "source", "language", "session_id", "hostname"]
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


# ============================================================================
# Span Matcher Helper - Provides methods for AST evaluation
# ============================================================================


class SpanMatcher:
    """Helper class for AST query evaluation against spans."""

    def get_field_value(self, span: Dict[str, Any], field: str) -> Optional[Any]:
        """Get a field value from a span (facet/attribute)."""
        return get_span_field_value(span, field)

    def get_tag_value(self, span: Dict[str, Any], field: str) -> Optional[str]:
        """Get a tag value from a span."""
        for tag in span.get("tags", []):
            if isinstance(tag, str) and tag.startswith(f"{field}:"):
                return tag.split(":", 1)[1]
        return None

    def field_exists(self, span: Dict[str, Any], field: str) -> bool:
        """Check if a field exists in the span."""
        value = self.get_field_value(span, field)
        if value is not None:
            return True
        # Also check tags
        return self.get_tag_value(span, field) is not None

    def match_wildcard(self, value: str, pattern: str) -> bool:
        """Match wildcard pattern (supports * and ?, case-sensitive by default)."""
        return llmobs_query_parser.match_wildcard(value, pattern, case_sensitive=True)

    def text_search(self, span: Dict[str, Any], text: str) -> bool:
        """Check if span matches free text search."""
        return text_search_span(span, text)


# Global span matcher instance
_span_matcher = SpanMatcher()


def parse_filter_query(query: str) -> Dict[str, Any]:
    """Parse filter query string into AST and text search.

    Returns a dict with:
        - "ast": QueryNode AST for structured queries (supports AND/OR/NOT)
        - "text_search": Free text search string (remaining unmatched text)
        - "filters": Legacy filter list (empty for backward compatibility)

    Supports full Datadog query syntax:
        - Boolean operators: AND, OR, NOT
        - Parentheses grouping: (expr1 OR expr2) AND expr3
        - Attributes: @field:value
        - Tags: field:value
        - Ranges: @field:[min TO max]
        - Comparisons: @field:>value, @field:>=value, etc.
        - Wildcards: * (zero or more), ? (exactly one char)
        - Existence: _exists_:field, _missing_:field
        - IN operator: @field IN [val1, val2, val3]
    """
    result: Dict[str, Any] = {"ast": None, "filters": [], "text_search": "", "has_query": False}
    if not query:
        return result

    result["has_query"] = bool(query.strip())

    # Parse query into AST using new parser
    ast = llmobs_query_parser.parse_query_to_ast(query, duration_parser=parse_duration_to_nanoseconds)
    result["ast"] = ast

    # Text search is no longer extracted - all structured queries go through AST
    # For backward compatibility, text_search remains empty
    result["text_search"] = ""

    return result


def match_wildcard(value: str, pattern: str, case_sensitive: bool = True) -> bool:
    """Match value against pattern with wildcard support.

    Supports:
    - * : matches zero or more characters
    - ? : matches exactly one character

    Args:
        value: The value to match
        pattern: The pattern with wildcards
        case_sensitive: Whether matching is case-sensitive (default: True)

    Examples:
        >>> match_wildcard("gpt-4", "gpt*")
        True
        >>> match_wildcard("user1", "user?")
        True
    """
    return llmobs_query_parser.match_wildcard(value, pattern, case_sensitive=case_sensitive)


def apply_filters(spans: List[Dict[str, Any]], parsed_query: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply filter conditions to spans using AST evaluation.

    Args:
        spans: List of spans to filter
        parsed_query: Parsed query dict with "ast" and "text_search" keys

    Returns:
        Filtered list of spans matching the query
    """
    ast = parsed_query.get("ast")
    text_search = parsed_query.get("text_search", "").lower()

    # Legacy support: if no AST but has filters list, use old method
    filters = parsed_query.get("filters", [])
    if not ast and filters:
        return _apply_filters_legacy(spans, filters, text_search)

    # If no query at all, return all spans; if a query was given but produced no AST, return none
    if not ast and not text_search:
        return [] if parsed_query.get("has_query") else spans

    # Filter using AST evaluation
    filtered = []
    for span in spans:
        # Evaluate AST against span
        if ast and not ast.evaluate(span, _span_matcher):
            continue

        # Apply text search if present
        if text_search and not text_search_span(span, text_search):
            continue

        filtered.append(span)

    return filtered


def _apply_filters_legacy(
    spans: List[Dict[str, Any]], filters: List[Dict[str, Any]], text_search: str
) -> List[Dict[str, Any]]:
    """Legacy filter application for backward compatibility."""
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
        "session_id": lambda s: s.get("session_id", ""),
        "hostname": lambda s: s.get("hostname", ""),
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
        session_id = span.get("session_id", "")
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
        # Ensure session_id is always in the tag dict for the web-ui
        if session_id and "session_id" not in tag_obj:
            tag_obj["session_id"] = session_id

        event_id = span_id
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
                "metadata": meta.get("metadata", {}),
                "model_name": model_name,
                "model_provider": model_provider,
            },
            "metrics": {
                "input_tokens": metrics.get("input_tokens", 0),
                "output_tokens": metrics.get("output_tokens", 0),
                "total_tokens": metrics.get("total_tokens", 0),
                "cache_read_input_tokens": metrics.get("cache_read_input_tokens", 0),
                "cache_write_input_tokens": metrics.get("cache_write_input_tokens", 0),
                "non_cached_input_tokens": metrics.get("non_cached_input_tokens", 0),
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
            "session_id": session_id,
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
                "id": event_id,
            }
        )

    return {
        "elapsed": 23,
        "hitCount": len(events),
        "requestId": request_id,
        "result": {
            "events": events,
            "count": len(events),
        },
        "status": "done",
        "type": "status",
    }


class LLMObsEventPlatformAPI:
    """Handler for Event Platform API requests."""

    def __init__(self, agent: "Agent"):
        self.agent = agent
        self._query_results: Dict[str, Dict[str, Any]] = {}
        self.decoded_llmobs_span_events: Dict[int, List[Dict[str, Any]]] = {}
        self._claude_hooks_api: Optional["ClaudeHooksAPI"] = None

    def set_claude_hooks_api(self, api: "ClaudeHooksAPI") -> None:
        """Wire up the Claude hooks API so its spans appear in LLMObs queries."""
        self._claude_hooks_api = api

    def get_llmobs_spans(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all LLMObs spans from stored requests."""
        requests = self.agent._requests_by_session(token) if token else self.agent._requests
        all_spans = []

        for req in requests:
            if req.path in ("/evp_proxy/v2/api/v2/llmobs", "/evp_proxy/v4/api/v2/llmobs"):
                try:
                    data = self.agent._request_data(req)
                    content_type = req.content_type or ""
                    req_id = id(req)  # only brittle if agent requests are cleared
                    if req_id not in self.decoded_llmobs_span_events:
                        events = decode_llmobs_payload(data, content_type)
                        spans = extract_spans_from_events(events)
                        self.decoded_llmobs_span_events[req_id] = spans
                    else:
                        spans = self.decoded_llmobs_span_events[req_id]
                    all_spans.extend(spans)
                except Exception as e:
                    log.warning(f"Failed to extract spans from request: {e}")

        if self._claude_hooks_api:
            all_spans.extend(self._claude_hooks_api._assembled_spans)

        all_spans.sort(key=lambda s: s.get("start_ns", 0), reverse=True)
        return all_spans

    def update_spans(self, update_data: bytes, content_type: str) -> int:
        """Update existing spans by span_id. Accepts same payload format as creation."""
        events = decode_llmobs_payload(update_data, content_type)
        update_span_list = extract_spans_from_events(events)

        # Build index of all existing spans (stored requests + hooks assembled)
        all_spans = self.get_llmobs_spans()
        span_index = {s.get("span_id"): s for s in all_spans}

        updated = 0
        for update in update_span_list:
            sid = update.get("span_id")
            existing = span_index.get(sid)
            if existing:
                _deep_merge(update, existing)
                updated += 1
        return updated

    async def handle_llmobs_update(self, request: Request) -> web.Response:
        """Handle POST /evp_proxy/v2/api/v2/llmobs/update — update existing spans."""
        data = await request.read()
        content_type = request.content_type or ""
        updated = self.update_spans(data, content_type)
        return web.json_response({"updated": updated})

    async def handle_logs_analytics_list(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/list endpoint."""
        try:
            # Only require type=llmobs for the query-rewriter endpoint
            if "/llm-obs-query-rewriter/" in request.path:
                query_type = request.query.get("type", "")
                if query_type != "llmobs":
                    return web.json_response({"error": "Only llmobs queries are supported"}, status=400)

            body = await request.json()
            list_params = body.get("list", {})
            limit = list_params.get("limit", 100)
            query_str = list_params.get("search", {}).get("query", "")

            spans = self.get_llmobs_spans()
            if query_str:
                spans = apply_filters(spans, parse_filter_query(query_str))

            # Handle sort order (default is descending by start_ns from get_llmobs_spans)
            sort_params = list_params.get("sort", {})
            sort_order = sort_params.get("time", {}).get("order", "desc") if isinstance(sort_params, dict) else "desc"
            if sort_order == "asc":
                spans = list(reversed(spans))

            request_id = str(uuid.uuid4())
            response = build_event_platform_list_response(spans, request_id, limit)
            self._query_results[request_id] = response

            return web.json_response(response)
        except Exception as e:
            log.error(f"Error handling llm-obs list: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_logs_analytics_get(self, request: Request) -> web.Response:
        """Handle GET /api/unstable/llm-obs-query-rewriter/list/{requestId} endpoint."""
        try:
            request_id = request.match_info.get("request_id", "")
            if request_id in self._query_results:
                return web.json_response(self._query_results[request_id])
            return web.Response(status=410)  # Gone
        except Exception as e:
            log.error(f"Error handling llm-obs get: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_aggregate(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/aggregate endpoint."""
        try:
            spans = self.get_llmobs_spans()
            response = {
                "elapsed": 50,
                "requestId": str(uuid.uuid4()),
                "result": {"buckets": [{"computes": {"c0": len(spans)}}], "status": "done"},
                "status": "done",
                "type": "aggregate",
            }
            return web.json_response(response)
        except Exception as e:
            log.error(f"Error handling aggregate: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_fetch_one(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/fetch_one endpoint."""
        try:
            body = await request.json()
            event_id = body.get("eventId", "") or body.get("fetch_one", {}).get("id", "")
            spans = self.get_llmobs_spans()

            found_span = None
            for span in spans:
                span_id = span.get("span_id", "")
                if span_id == event_id or event_id.endswith(span_id):
                    found_span = span
                    break

            if not found_span:
                if spans:
                    found_span = spans[0]
                else:
                    return web.json_response({"error": "Span not found"}, status=404)

            meta = found_span.get("meta", {})
            metrics = found_span.get("metrics", {})
            span_id = found_span.get("span_id", str(uuid.uuid4()))
            trace_id = found_span.get("trace_id", "")
            session_id = found_span.get("session_id", "")
            status = found_span.get("status", "ok")
            name = found_span.get("name", "")
            duration = found_span.get("duration", 0)
            start_ns = found_span.get("start_ns", int(time.time() * 1_000_000_000))
            tags = found_span.get("tags", [])
            span_kind = meta.get("span", {}).get("kind", "llm")
            ml_app = found_span.get("ml_app", found_span.get("_ui_ml_app", "unknown"))
            service = found_span.get("service", "")
            env = found_span.get("env", "")

            tag_obj = {}
            for tag in tags:
                if isinstance(tag, str) and ":" in tag:
                    k, v = tag.split(":", 1)
                    tag_obj[k] = v
            # Ensure session_id is always in the tag dict for the web-ui
            if session_id and "session_id" not in tag_obj:
                tag_obj["session_id"] = session_id

            timestamp_ms = start_ns // 1_000_000
            timestamp_iso = datetime.utcfromtimestamp(timestamp_ms / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

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
                "kind": span_kind,
                "meta": {
                    "span": {"kind": span_kind},
                    "kind": span_kind,
                    "input": meta.get("input", {}),
                    "output": meta.get("output", {}),
                    "error": meta.get("error") if status == "error" else None,
                    "metadata": meta.get("metadata", {}),
                    "model_name": model_name,
                    "model_provider": model_provider,
                },
                "metrics": {
                    "input_tokens": metrics.get("input_tokens", 0),
                    "output_tokens": metrics.get("output_tokens", 0),
                    "total_tokens": metrics.get("total_tokens", 0),
                    "cache_read_input_tokens": metrics.get("cache_read_input_tokens", 0),
                    "cache_write_input_tokens": metrics.get("cache_write_input_tokens", 0),
                    "non_cached_input_tokens": metrics.get("non_cached_input_tokens", 0),
                },
                "ml_app": ml_app,
                "name": name,
                "parent_id": found_span.get("parent_id", "undefined"),
                "session_id": session_id,
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

            return web.json_response(response)
        except Exception as e:
            log.error(f"Error handling fetch_one: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_trace(self, request: Request) -> web.Response:
        """Handle GET /api/ui/llm-obs/v1/trace/{trace_id} endpoint."""
        try:
            trace_id = request.match_info.get("trace_id", "")
            span_id_filter = request.query.get("filter[span_id]", "")

            all_spans = self.get_llmobs_spans()
            trace_spans = [s for s in all_spans if s.get("trace_id") == trace_id]

            if not trace_spans and span_id_filter:
                trace_spans = [s for s in all_spans if s.get("span_id") == span_id_filter]

            if not trace_spans and all_spans:
                trace_spans = [all_spans[0]]

            if not trace_spans:
                return web.json_response({"error": "Trace not found"}, status=404)

            children_map = compute_children_ids(trace_spans)
            spans_dict = {}
            root_id = None

            for span in trace_spans:
                span_id = span.get("span_id", "")
                session_id = span.get("session_id", "")
                meta = span.get("meta", {})
                metrics = span.get("metrics", {})
                tags = span.get("tags", [])
                span_kind = meta.get("span", {}).get("kind", "llm")
                ml_app = span.get("ml_app", span.get("_ui_ml_app", "unknown"))
                service = span.get("service", "")
                children_ids = children_map.get(span_id, [])
                span_links = span.get("span_links", [])

                parent_id = span.get("parent_id", "undefined")
                if not root_id and (not parent_id or parent_id == "undefined"):
                    root_id = span_id

                model_metadata = meta.get("metadata", {})
                model_name = model_metadata.get("model_name", meta.get("model_name", ""))
                model_provider = model_metadata.get("model_provider", meta.get("model_provider", ""))

                start_ns = span.get("start_ns", 0)
                duration_ns = span.get("duration", 0)

                spans_dict[span_id] = {
                    "trace_id": span.get("trace_id", ""),
                    "span_id": span_id,
                    "session_id": session_id,
                    "parent_id": parent_id,
                    "children_ids": children_ids,
                    "span_links": span_links,
                    "name": span.get("name", ""),
                    "resource": span.get("name", ""),
                    "tags": tags,
                    "status": span.get("status", "ok"),
                    "error": 1 if span.get("status") == "error" else 0,
                    "start": start_ns // 1_000_000,
                    "end": (start_ns + duration_ns) // 1_000_000,
                    "duration": duration_ns,
                    "service": service,
                    "env": span.get("env", ""),
                    "ml_app": ml_app,
                    "kind": span_kind,
                    "meta": {
                        "ml_app": ml_app,
                        "kind": span_kind,
                        "span": {"kind": span_kind},
                        "error": meta.get("error", {}),
                        "input": meta.get("input", {}),
                        "output": meta.get("output", {}),
                        "expected_output": {},
                        "metadata": meta.get("metadata", {}),
                        "model_name": model_name,
                        "model_provider": model_provider,
                    },
                    "metrics": metrics,
                    "_dd": {"apm_trace_id": span.get("trace_id", "")},
                }

            if not root_id and spans_dict:
                root_id = list(spans_dict.keys())[0]

            response = {
                "data": {
                    "id": str(uuid.uuid4()),
                    "type": "trace",
                    "attributes": {
                        "root_id": root_id,
                        "spans": spans_dict,
                        "trace_state": {"Error": "", "warnings": None, "convention_violations": {}},
                    },
                },
            }

            return web.json_response(response)
        except Exception as e:
            log.error(f"Error handling trace: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_facets_list(self, request: Request) -> web.Response:
        """Handle GET /api/ui/event-platform/llmobs/facets endpoint (stub)."""
        return web.json_response({"facets": {"llmobs": []}})

    async def handle_facet_info(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/facet_info endpoint.

        Returns facet values with counts for the specified facet path.
        Supports optional search/filter query to compute values from filtered spans.
        """
        try:
            body = await request.json()
            log.debug(f"facet_info request: {json.dumps(body, indent=2)[:500]}")

            facet_info = body.get("facet_info", {})
            facet_path = facet_info.get("path", "")
            limit = facet_info.get("limit", 10)
            term_search = facet_info.get("termSearch", {}).get("query", "")
            search_query = facet_info.get("search", {}).get("query", "")

            # Strip @ prefix for field lookup
            field_path = facet_path.lstrip("@")

            # Get spans, optionally filtered by search query
            spans = self.get_llmobs_spans()
            if search_query:
                parsed_query = parse_filter_query(search_query)
                spans = apply_filters(spans, parsed_query)

            # Compute facet values from spans
            value_counts: Dict[str, int] = {}
            for span in spans:
                value = get_span_field_value(span, field_path)
                if value is not None:
                    value_str = str(value)
                    value_counts[value_str] = value_counts.get(value_str, 0) + 1

            # Sort by count descending and limit
            sorted_values = sorted(value_counts.items(), key=lambda x: -x[1])[:limit]

            # Apply term search filter if provided
            if term_search:
                term_lower = term_search.lower()
                sorted_values = [(v, c) for v, c in sorted_values if term_lower in v.lower()][:limit]

            # Build response
            fields = [{"field": value, "value": count} for value, count in sorted_values]

            response = {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {"fields": fields, "status": "done"},
                "status": "done",
            }

            log.debug(f"facet_info response for {facet_path}: {len(fields)} values")
            return web.json_response(response)

        except Exception as e:
            log.error(f"Error handling facet info: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_facet_range_info(self, request: Request) -> web.Response:
        """Handle POST /api/unstable/llm-obs-query-rewriter/facet_range_info endpoint.

        Returns min/max values for range facets like duration, tokens, cost.
        Supports optional search/filter query to compute range from filtered spans.
        """
        try:
            body = await request.json()
            log.debug(f"facet_range_info request: {json.dumps(body, indent=2)[:500]}")

            facet_range_info = body.get("facet_range_info", {})
            facet_path = facet_range_info.get("path", "")
            search_query = facet_range_info.get("search", {}).get("query", "")

            # Strip @ prefix for field lookup
            field_path = facet_path.lstrip("@")

            # Get spans, optionally filtered by search query
            spans = self.get_llmobs_spans()
            if search_query:
                parsed_query = parse_filter_query(search_query)
                spans = apply_filters(spans, parsed_query)

            # Compute range from spans
            values = []
            for span in spans:
                value = get_span_field_value(span, field_path)
                if value is not None:
                    try:
                        values.append(float(value))
                    except (ValueError, TypeError):
                        pass

            range_data = {
                "min": min(values) if values else 0,
                "max": max(values) if values else 0,
            }

            response = {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {"min": range_data["min"], "max": range_data["max"], "status": "done"},
                "status": "done",
            }

            log.debug(f"facet_range_info response for {facet_path}: min={range_data['min']}, max={range_data['max']}")
            return web.json_response(response)

        except Exception as e:
            log.error(f"Error handling facet range info: {e}")
            return web.json_response({"error": str(e)}, status=500)

    async def handle_query_scalar(self, request: Request) -> web.Response:
        """Handle POST /api/ui/query/scalar endpoint."""
        return web.json_response(
            {
                "data": [
                    {
                        "type": "scalar_response",
                        "attributes": {
                            "columns": [],
                        },
                    }
                ],
            }
        )

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API (all handlers wrapped with CORS support)."""
        return [
            # LLM Obs query rewriter endpoints
            web.route("*", "/api/unstable/llm-obs-query-rewriter/list", with_cors(self.handle_logs_analytics_list)),
            web.route(
                "*", "/api/unstable/llm-obs-query-rewriter/list/{request_id}", with_cors(self.handle_logs_analytics_get)
            ),
            web.route("*", "/api/unstable/llm-obs-query-rewriter/aggregate", with_cors(self.handle_aggregate)),
            web.route("*", "/api/unstable/llm-obs-query-rewriter/fetch_one", with_cors(self.handle_fetch_one)),
            web.route("*", "/api/unstable/llm-obs-query-rewriter/facet_info", with_cors(self.handle_facet_info)),
            web.route(
                "*", "/api/unstable/llm-obs-query-rewriter/facet_range_info", with_cors(self.handle_facet_range_info)
            ),
            # Facets list endpoint
            web.route("*", "/api/ui/event-platform/llmobs/facets", with_cors(self.handle_facets_list)),
            # Legacy logs-analytics endpoints
            web.route("*", "/api/v1/logs-analytics/list", with_cors(self.handle_logs_analytics_list)),
            web.route("*", "/api/v1/logs-analytics/list/{request_id}", with_cors(self.handle_logs_analytics_get)),
            web.route("*", "/api/v1/logs-analytics/aggregate", with_cors(self.handle_aggregate)),
            web.route("*", "/api/v1/logs-analytics/fetch_one", with_cors(self.handle_fetch_one)),
            # LLM Obs trace endpoint
            web.route("*", "/api/ui/llm-obs/v1/trace/{trace_id}", with_cors(self.handle_trace)),
            # Query scalar endpoint
            web.route("*", "/api/ui/query/scalar", with_cors(self.handle_query_scalar)),
        ]
