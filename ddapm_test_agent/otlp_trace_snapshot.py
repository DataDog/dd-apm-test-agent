"""Snapshot testing for OTLP traces.

Snapshots are OTLP/JSON documents, which is what an OTLP collector receives over http/json. Like the native
trace snapshots, ids are renumbered so they are stable across runs.
"""

import base64
import copy
import difflib
import json
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Pattern

from google.protobuf.json_format import MessageToDict
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from .checks import CheckTrace
from .trace_snapshot import _walk_span_attributes_with_regex_replaces


OtlpDocument = Dict[str, Any]

# Values that change between runs: timestamps, the SDK version and the W3C tracestate, which carries the
# random parent id.
DEFAULT_OTLP_IGNORES = [
    "startTimeUnixNano",
    "endTimeUnixNano",
    "timeUnixNano",
    "traceState",
    "meta.telemetry.sdk.version",
]

_ID_KEYS = {"traceId", "trace_id", "spanId", "span_id", "parentSpanId", "parent_span_id"}


def _convert_ids(obj: Any, convert: Callable[[str], str]) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in _ID_KEYS and isinstance(val, str):
                obj[key] = convert(val)
            else:
                _convert_ids(val, convert)
    elif isinstance(obj, list):
        for item in obj:
            _convert_ids(item, convert)


def _hex_to_base64(value: str) -> str:
    # OTLP/JSON uses hex ids (16 or 32 characters) while the protobuf JSON mapping uses base64 (12 or 24).
    try:
        return base64.b64encode(bytes.fromhex(value)).decode() if len(value) in (16, 32) else value
    except ValueError:
        return value


def _to_otlp_json(payload: Dict[str, Any]) -> OtlpDocument:
    """Convert a payload decoded from protobuf or OTLP/JSON to the OTLP/JSON representation."""
    base64_payload = copy.deepcopy(payload)
    _convert_ids(base64_payload, _hex_to_base64)
    doc = MessageToDict(
        ParseDict(base64_payload, ExportTraceServiceRequest(), ignore_unknown_fields=True), use_integers_for_enums=True
    )
    _convert_ids(doc, lambda value: base64.b64decode(value).hex())
    return doc


def _sort_attributes(obj: Any) -> None:
    if isinstance(obj, dict):
        if isinstance(obj.get("attributes"), list):
            obj["attributes"].sort(key=lambda kv: kv["key"])
        for val in obj.values():
            _sort_attributes(val)
    elif isinstance(obj, list):
        for item in obj:
            _sort_attributes(item)


def _iter_spans(doc: OtlpDocument) -> Iterable[Dict[str, Any]]:
    for resource_spans in doc.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            yield from scope_spans.get("spans", [])


def span_count(doc: OtlpDocument) -> int:
    return sum(1 for _ in _iter_spans(doc))


def _merge(docs: List[OtlpDocument]) -> OtlpDocument:
    """Merge export requests, grouping spans that share the same resource and scope."""
    resources: Dict[str, Dict[str, Any]] = {}
    scopes: Dict[str, Dict[str, Any]] = {}
    for doc in docs:
        for resource_spans in doc.get("resourceSpans", []):
            resource = {k: v for k, v in resource_spans.items() if k != "scopeSpans"}
            resource_key = json.dumps(resource, sort_keys=True)
            merged_resource = resources.setdefault(resource_key, {**resource, "scopeSpans": []})
            for scope_spans in resource_spans.get("scopeSpans", []):
                scope = {k: v for k, v in scope_spans.items() if k != "spans"}
                scope_key = resource_key + json.dumps(scope, sort_keys=True)
                if scope_key not in scopes:
                    scopes[scope_key] = {**scope, "spans": []}
                    merged_resource["scopeSpans"].append(scopes[scope_key])
                scopes[scope_key]["spans"].extend(scope_spans.get("spans", []))
    return {"resourceSpans": list(resources.values())}


def _renumber_ids(doc: OtlpDocument) -> None:
    """Renumber trace ids by the start time of their root spans and span ids in BFS order.

    Siblings are ordered by start time and then name. Ids that refer to spans outside the payload are kept.
    """

    def order(span: Dict[str, Any]) -> Any:
        return int(span.get("startTimeUnixNano", 0)), span.get("name", "")

    traces: Dict[str, List[Dict[str, Any]]] = {}
    for span in _iter_spans(doc):
        traces.setdefault(span.get("traceId", ""), []).append(span)

    ordered_traces = []
    for trace_id, spans in traces.items():
        span_ids = {s.get("spanId") for s in spans}
        roots = sorted((s for s in spans if s.get("parentSpanId") not in span_ids), key=order)
        bfs = list(roots)
        for s in bfs:
            bfs.extend(sorted((c for c in spans if c.get("parentSpanId") == s.get("spanId")), key=order))
        ordered_traces.append(([order(r) for r in roots], trace_id, bfs))
    ordered_traces.sort(key=lambda t: t[0])

    trace_id_map: Dict[str, str] = {}
    span_id_map: Dict[str, str] = {}
    for _, trace_id, bfs in ordered_traces:
        trace_id_map[trace_id] = f"{len(trace_id_map) + 1:032x}"
        for s in bfs:
            span_id_map[s.get("spanId", "")] = f"{len(span_id_map) + 1:016x}"

    for span in _iter_spans(doc):
        for obj in [span, *span.get("links", [])]:
            obj["traceId"] = trace_id_map.get(obj.get("traceId", ""), obj.get("traceId", ""))
            for key in ("spanId", "parentSpanId"):
                if key in obj:
                    obj[key] = span_id_map.get(obj[key], obj[key])

    # The new ids are zero-padded, so sorting by them puts the document in trace order.
    for resource_spans in doc["resourceSpans"]:
        for scope_spans in resource_spans["scopeSpans"]:
            scope_spans["spans"].sort(key=lambda s: s["spanId"])
        resource_spans["scopeSpans"].sort(key=lambda ss: min((s["spanId"] for s in ss["spans"]), default=""))
    doc["resourceSpans"].sort(
        key=lambda rs: min((s["spanId"] for s in _iter_spans({"resourceSpans": [rs]})), default="")
    )


def canonicalize(payloads: List[Dict[str, Any]]) -> OtlpDocument:
    """Combine the OTLP trace payloads received in a session into a single OTLP/JSON document."""
    doc = _merge([_to_otlp_json(p) for p in payloads])
    _sort_attributes(doc)
    _renumber_ids(doc)
    return doc


def _drop_keys(doc: OtlpDocument, keys: Iterable[str]) -> None:
    """Drop keys given in the native snapshot syntax.

    meta.X and metrics.X refer to the attribute X of resources, spans, events and links, and keys without a
    dot to span and event fields. Other native keys, such as span_id, have no OTLP equivalent and are no-ops.
    """
    attributes = {k.split(".", 1)[1] for k in keys if k.startswith(("meta.", "metrics."))}
    fields = {k for k in keys if "." not in k}
    for resource_spans in doc.get("resourceSpans", []):
        resource = resource_spans.get("resource", {})
        objects = [resource]
        for span in _iter_spans({"resourceSpans": [resource_spans]}):
            objects.extend([span, *span.get("events", []), *span.get("links", [])])
        for obj in objects:
            for field in fields:
                obj.pop(field, None)
            if "attributes" in obj:
                obj["attributes"] = [kv for kv in obj["attributes"] if kv["key"] not in attributes]


def generate(
    received: OtlpDocument,
    removed: Optional[List[str]] = None,
    attribute_regex_replaces: Optional[Dict[str, Pattern[str]]] = None,
) -> str:
    doc = copy.deepcopy(received)
    _drop_keys(doc, removed or [])
    _walk_span_attributes_with_regex_replaces(doc, attribute_regex_replaces or {})
    return json.dumps(doc, indent=2) + "\n"


def snapshot(
    expected: OtlpDocument,
    received: OtlpDocument,
    ignored: List[str],
    attribute_regex_replaces: Dict[str, Pattern[str]],
) -> None:
    normed_expected = copy.deepcopy(expected)
    normed_received = copy.deepcopy(received)
    _walk_span_attributes_with_regex_replaces(normed_received, attribute_regex_replaces)
    for doc in (normed_expected, normed_received):
        _drop_keys(doc, list(ignored) + DEFAULT_OTLP_IGNORES)
    with CheckTrace.add_frame(
        f"compare of {span_count(normed_expected)} expected to {span_count(normed_received)} received OTLP span(s)"
    ):
        if normed_expected != normed_received:
            diff = difflib.unified_diff(
                json.dumps(normed_expected, indent=2, sort_keys=True).splitlines(),
                json.dumps(normed_received, indent=2, sort_keys=True).splitlines(),
                fromfile="expected",
                tofile="received",
                lineterm="",
            )
            raise AssertionError("Received OTLP traces do not match the snapshot:\n" + "\n".join(diff))
