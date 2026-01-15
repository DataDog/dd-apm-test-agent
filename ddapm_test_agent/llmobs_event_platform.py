"""
LLM Observability Event Platform API
Provides Datadog Event Platform compatible endpoints for LLM Observability data.
This allows the Chrome extension to redirect Datadog UI requests to the test agent.
"""

import gzip
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

import msgpack
from aiohttp import web
from aiohttp.web import Request

log = logging.getLogger(__name__)


def decode_llmobs_payload(data: bytes, content_type: str) -> List[Dict[str, Any]]:
    """Decode LLMObs payload from request data.

    Handles both gzip+msgpack and JSON formats.
    Returns a list of span event payloads.
    """
    events = []

    try:
        # Check for gzip encoding
        if content_type and "gzip" in content_type.lower():
            data = gzip.decompress(data)

        # Try msgpack first (most common from tracers)
        if content_type and "msgpack" in content_type.lower():
            payload = msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            # Fall back to JSON
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                # Try msgpack as fallback
                payload = msgpack.unpackb(data, raw=False, strict_map_key=False)

        # Handle both list format [{"spans": [...]}] and dict format {"spans": [...]}
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
        log.debug(f"Event keys: {list(event.keys())}")
        event_spans = event.get("spans", [])
        event_ml_app = event.get("ml_app", "")
        event_tags = event.get("tags", [])

        for span in event_spans:
            # Merge top-level tags with span tags
            span_tags = span.get("tags", [])
            if event_tags:
                span_tags = list(set(span_tags + event_tags))
            span["tags"] = span_tags

            # Remap SDK format to UI format
            span = remap_sdk_span_to_ui_format(span, event_ml_app)
            spans.append(span)

    return spans


def remap_sdk_span_to_ui_format(span: Dict[str, Any], event_ml_app: str = "") -> Dict[str, Any]:
    """Remap span from SDK format to UI-expected format.

    The Datadog backend does transformations when ingesting LLMObs data.
    This function replicates those transformations:

    SDK sends:
    - span kind at: meta.span.kind
    - ml_app in: tags array as "ml_app:value"
    - service in: tags array as "service:value"
    - env in: tags array as "env:value"

    UI expects:
    - span kind at: meta.span.kind (same, but we ensure it's there)
    - ml_app at: top-level span.ml_app
    - service at: top-level span.service
    - env at: top-level span.env
    """
    tags = span.get("tags", [])

    # Extract key fields from tags array
    extracted = extract_fields_from_tags(tags)

    # Set ml_app: prefer from tags, then from event level, then default
    ml_app = extracted.get("ml_app") or event_ml_app or span.get("ml_app", "unknown")
    span["ml_app"] = ml_app

    # Set service and env from tags
    if "service" not in span or not span["service"]:
        span["service"] = extracted.get("service", "")
    if "env" not in span or not span["env"]:
        span["env"] = extracted.get("env", "")

    # Ensure meta.span.kind exists and is accessible
    # SDK sends: meta.span.kind
    meta = span.get("meta", {})
    span_meta = meta.get("span", {})
    span_kind = span_meta.get("kind", "llm")

    # Log the span kind for debugging
    log.info(f"Remapped span: name={span.get('name')}, kind={span_kind}, ml_app={ml_app}")

    # Ensure the span kind is in the expected location
    if "meta" not in span:
        span["meta"] = {}
    if "span" not in span["meta"]:
        span["meta"]["span"] = {}
    span["meta"]["span"]["kind"] = span_kind

    # Also store at _ui_kind for easy access
    span["_ui_kind"] = span_kind
    span["_ui_ml_app"] = ml_app

    return span


def extract_fields_from_tags(tags: List[str]) -> Dict[str, str]:
    """Extract key fields from the tags array.

    Tags are in format "key:value". Extract commonly needed fields.
    """
    result = {}
    fields_to_extract = ["ml_app", "service", "env", "version", "source", "language"]

    for tag in tags:
        if not isinstance(tag, str) or ":" not in tag:
            continue
        key, value = tag.split(":", 1)
        if key in fields_to_extract:
            result[key] = value

    return result


def parse_filter_query(query: str) -> List[Dict[str, str]]:
    """Parse a filter query string into a list of filter conditions.

    Query format: @field:value @field2:value2
    Example: @ml_app:test-app @event_type:span @parent_id:undefined

    Returns a list of dicts with 'field' and 'value' keys.
    """
    import re

    filters = []
    if not query:
        return filters

    # Match @field:value patterns (value can contain hyphens, underscores, etc.)
    pattern = r'@([\w.]+):([^\s]+)'
    matches = re.findall(pattern, query)

    for field, value in matches:
        filters.append({"field": field, "value": value})

    log.info(f"Parsed filter query: {query} -> {filters}")
    return filters


def apply_filters(spans: List[Dict[str, Any]], filters: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Apply filter conditions to a list of spans.

    Supports filtering by:
    - ml_app: matches span.ml_app
    - event_type: matches span event type (always 'span' for LLMObs)
    - parent_id: matches span.parent_id ('undefined' for root spans, '*' for any)
    - meta.span.kind: matches span kind
    - status: matches span status
    - name: matches span name
    - trace_id: matches span trace_id
    - span_id: matches span span_id

    Special values:
    - '*' matches any value (wildcard)
    - 'undefined' for parent_id matches root spans (no parent)
    """
    if not filters:
        return spans

    filtered = []
    for span in spans:
        matches_all = True

        for f in filters:
            field = f["field"]
            value = f["value"]

            # Wildcard '*' matches anything
            if value == "*":
                continue

            # Get the span value for this field
            span_value = get_span_field_value(span, field)

            # Check if it matches
            if span_value is None:
                matches_all = False
                break

            # String comparison (case-insensitive for some fields)
            if str(span_value).lower() != str(value).lower():
                matches_all = False
                break

        if matches_all:
            filtered.append(span)

    log.info(f"Filtered {len(spans)} spans to {len(filtered)} spans")
    return filtered


def compute_children_ids(spans: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Compute children_ids for each span from parent_id relationships.

    The SDK sends parent_id but not children_ids. The backend computes
    children_ids by inverting the parent-child relationships.

    Returns a dict mapping span_id -> list of child span_ids.
    """
    children_map: Dict[str, List[str]] = {}

    # Initialize empty lists for all spans
    for span in spans:
        span_id = span.get("span_id", "")
        if span_id:
            children_map[span_id] = []

    # Build children lists from parent_id
    for span in spans:
        span_id = span.get("span_id", "")
        parent_id = span.get("parent_id", "")

        # Skip if no parent or parent is "undefined" (root span)
        if not parent_id or parent_id == "undefined":
            continue

        # Add this span to its parent's children list
        if parent_id in children_map:
            children_map[parent_id].append(span_id)
        else:
            # Parent might not be in our span list (cross-trace)
            children_map[parent_id] = [span_id]

    return children_map


def get_span_field_value(span: Dict[str, Any], field: str) -> Optional[str]:
    """Get the value of a field from a span for filtering.

    Handles nested fields like meta.span.kind.
    """
    # Direct top-level fields
    if field == "ml_app":
        return span.get("ml_app", span.get("_ui_ml_app"))
    elif field == "event_type":
        return "span"  # Always 'span' for LLMObs spans
    elif field == "parent_id":
        parent = span.get("parent_id")
        # Normalize empty/null parent_id to "undefined"
        if not parent or parent == "0" or parent == "":
            return "undefined"
        return str(parent)
    elif field == "status":
        return span.get("status", "ok")
    elif field == "name":
        return span.get("name")
    elif field == "trace_id":
        return span.get("trace_id")
    elif field == "span_id":
        return span.get("span_id")
    elif field == "service":
        return span.get("service")
    elif field == "env":
        return span.get("env")

    # Nested fields with dot notation
    if field.startswith("meta."):
        parts = field.split(".")
        value = span.get("meta", {})
        for part in parts[1:]:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    # Check in tags
    tags = span.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith(f"{field}:"):
            return tag.split(":", 1)[1]

    return None


def convert_span_to_event_platform_format(span: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an LLMObs span to Event Platform event format.

    Maps the span fields to the facet paths expected by the Datadog UI.
    Based on BaseLLMSpan type from web-ui/packages/apps/llm/private/lib/tracing/types.ts
    """
    meta = span.get("meta", {})
    metrics = span.get("metrics", {})

    # Get input/output values
    input_data = meta.get("input", {})
    output_data = meta.get("output", {})

    input_value = input_data.get("value", "")
    if not input_value and "messages" in input_data:
        # Extract from messages array
        messages = input_data.get("messages", [])
        if messages:
            last_msg = messages[-1] if isinstance(messages, list) else messages
            if isinstance(last_msg, dict):
                input_value = last_msg.get("content", "")

    output_value = output_data.get("value", "")
    if not output_value and "messages" in output_data:
        messages = output_data.get("messages", [])
        if messages:
            last_msg = messages[-1] if isinstance(messages, list) else messages
            if isinstance(last_msg, dict):
                output_value = last_msg.get("content", "")

    # Determine status - must be 'error' or 'ok'
    status = span.get("status", "ok")
    if status not in ("error", "ok"):
        status = "ok"

    error_info = meta.get("error", {})
    has_error = 1 if status == "error" or error_info else 0

    # Get span kind from meta.span.kind (SDK format)
    span_meta = meta.get("span", {})
    span_kind = span_meta.get("kind", "llm")

    # Get ml_app from remapped field
    ml_app = span.get("ml_app", span.get("_ui_ml_app", "unknown"))

    # Get timestamps
    start_ns = span.get("start_ns", 0)
    duration_ns = span.get("duration", 0)

    # Build the event object matching BaseLLMSpan type from web-ui
    event = {
        # Core identifiers (required by Span type)
        "span_id": span.get("span_id"),
        "trace_id": span.get("trace_id"),
        "parent_id": span.get("parent_id"),

        # Event type
        "event_type": "span",

        # Basic span info
        "name": span.get("name", ""),
        "resource": span.get("name", ""),  # Usually same as name
        "ml_app": ml_app,
        "status": status,
        "error": has_error,
        "duration": duration_ns,
        "session_id": span.get("session_id"),

        # Timestamps
        "start": start_ns // 1_000_000,  # Milliseconds
        "end": (start_ns + duration_ns) // 1_000_000,  # Milliseconds
        "timestamp": start_ns // 1_000_000,  # Milliseconds for display

        # Tags as array of "key:value" strings
        "tags": span.get("tags", []),

        # Service/env (extract from tags)
        "service": "",
        "env": "",

        # Children and links (empty for now)
        "children_ids": [],
        "span_links": [],

        # Datadog internal fields - THIS IS WHERE ootb_status LIVES
        "_dd": {
            "ootb_status": "success" if status == "ok" else "error",
            "apm_trace_id": span.get("trace_id"),
        },

        # Meta structure matching BaseLLMSpan
        "meta": {
            "span": {
                "kind": span_kind,
            },
            "input": {
                "value": input_value,
                "messages": input_data.get("messages", []),
            },
            "output": {
                "value": output_value,
                "messages": output_data.get("messages", []),
            },
            "model_name": meta.get("metadata", {}).get("model_name", ""),
            "model_provider": meta.get("metadata", {}).get("model_provider", ""),
            "error": error_info if error_info else None,
        },

        # Metrics
        "metrics": {
            "input_tokens": metrics.get("input_tokens", 0),
            "output_tokens": metrics.get("output_tokens", 0),
            "total_tokens": metrics.get("total_tokens", 0),
            "estimated_input_cost": 0,
            "estimated_output_cost": 0,
            "estimated_total_cost": 0,
        },

        # Evaluations (empty for now, can be populated later)
        "evaluations": {},
        "evaluation_assessments": {},
        "evaluation_metadata": {},
        "evaluation_skip_reasons": {},
        "evaluation_reasoning": {},
        "evaluation_tags": {},

        # Trace-level data (for aggregated cost display)
        "trace": {
            "estimated_total_cost": 0,
        },
    }

    # Use remapped service/env if available
    event["service"] = span.get("service", "")
    event["env"] = span.get("env", "")

    return event


def build_event_platform_list_response(
    spans: List[Dict[str, Any]],
    request_id: str,
    limit: int = 100,
) -> Dict[str, Any]:
    """Build an Event Platform list response from spans.

    Returns a response in the exact format returned by the Datadog backend.
    The span data goes under event.custom, with _dd containing ootb_status.
    """
    from datetime import datetime

    # Compute children_ids for all spans upfront
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

        # Get span kind from meta.span.kind (SDK format)
        # After remapping, this should be properly set
        span_meta = meta.get("span", {})
        span_kind = span_meta.get("kind", "llm")

        # Get ml_app from remapped top-level field
        # After remapping, ml_app is extracted from tags and set at top level
        ml_app = span.get("ml_app", span.get("_ui_ml_app", "unknown"))

        # Get service and env (remapped from tags)
        service = span.get("service", "")
        env = span.get("env", "")

        # Get children_ids from computed map
        children_ids = children_map.get(span_id, [])

        # Get span_links from SDK (for cross-span relationships in agentic graphs)
        span_links = span.get("span_links", [])

        # Debug log
        log.info(f"Building event: name={name}, kind={span_kind}, ml_app={ml_app}")

        # Build tag object from tags array
        tag_obj = {}
        for tag in tags:
            if isinstance(tag, str) and ":" in tag:
                k, v = tag.split(":", 1)
                if k in tag_obj:
                    # Convert to list if multiple values
                    if isinstance(tag_obj[k], list):
                        tag_obj[k].append(v)
                    else:
                        tag_obj[k] = [tag_obj[k], v]
                else:
                    tag_obj[k] = v

        # Generate event ID
        event_id = f"AZ{uuid.uuid4().hex[:20]}"

        # Timestamp as ISO string
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

        events.append({
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
        })

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

    def get_llmobs_spans(self, token: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all LLMObs spans from stored requests."""
        all_spans = []

        # Get requests - either for a specific session or all
        if token:
            requests = self.agent._requests_by_session(token)
        else:
            requests = self.agent._requests

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

    async def handle_logs_analytics_list(self, request: Request) -> web.Response:
        """Handle POST /api/v1/logs-analytics/list endpoint.

        This is the main entry point for Event Platform list queries.
        """
        # Add CORS headers for cross-origin requests from Datadog
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

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
                filters = parse_filter_query(query_str)
                spans = apply_filters(spans, filters)

            # Generate request ID for multi-step queries
            request_id = str(uuid.uuid4())

            # Build and return response
            response = build_event_platform_list_response(spans, request_id, limit)

            # Store for potential subsequent GET requests
            self._query_results[request_id] = response

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling logs-analytics list: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_logs_analytics_get(self, request: Request) -> web.Response:
        """Handle GET /api/v1/logs-analytics/list/{requestId} endpoint.

        This is for multi-step query polling.
        """
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

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
            log.error(f"Error handling logs-analytics get: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_aggregate(self, request: Request) -> web.Response:
        """Handle POST /api/v1/logs-analytics/aggregate endpoint.

        Returns aggregated metrics for LLM Observability data.
        """
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

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
                    "buckets": [
                        {
                            "computes": {
                                "c0": len(spans)  # Total count
                            }
                        }
                    ],
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
        """Handle facet_info and facet_range_info endpoints."""
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

        if request.method == "OPTIONS":
            return web.Response(status=200, headers=headers)

        try:
            # Return empty facet info - the UI will still work
            response = {
                "elapsed": 10,
                "requestId": str(uuid.uuid4()),
                "result": {
                    "facets": [],
                    "status": "done",
                },
                "status": "done",
            }

            return web.json_response(response, headers=headers)

        except Exception as e:
            log.error(f"Error handling facet info: {e}")
            return web.json_response(
                {"error": str(e)},
                status=500,
                headers=headers,
            )

    async def handle_fetch_one(self, request: Request) -> web.Response:
        """Handle POST /api/v1/logs-analytics/fetch_one endpoint.

        Fetches a single event/span by ID for the detail view.
        """
        from datetime import datetime

        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

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
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer",
        }

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
                log.info(f"Trace span: span_id={span_id}, name={span.get('name')}, kind={span_kind}, ml_app={ml_app}, children={children_ids}")

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
            # New LLM Obs query rewriter endpoints (used by Datadog UI)
            web.post("/api/unstable/llm-obs-query-rewriter/list", self.handle_logs_analytics_list),
            web.get("/api/unstable/llm-obs-query-rewriter/list/{request_id}", self.handle_logs_analytics_get),
            web.options("/api/unstable/llm-obs-query-rewriter/list", self.handle_logs_analytics_list),
            web.options("/api/unstable/llm-obs-query-rewriter/list/{request_id}", self.handle_logs_analytics_get),
            web.post("/api/unstable/llm-obs-query-rewriter/aggregate", self.handle_aggregate),
            web.options("/api/unstable/llm-obs-query-rewriter/aggregate", self.handle_aggregate),
            web.post("/api/unstable/llm-obs-query-rewriter/facet_info", self.handle_facet_info),
            web.options("/api/unstable/llm-obs-query-rewriter/facet_info", self.handle_facet_info),
            web.post("/api/unstable/llm-obs-query-rewriter/facet_range_info", self.handle_facet_info),
            web.options("/api/unstable/llm-obs-query-rewriter/facet_range_info", self.handle_facet_info),
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
