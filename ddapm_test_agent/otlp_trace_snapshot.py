"""Snapshot testing for OTLP traces.

Snapshots are stored as a single OTLP/JSON ExportTraceServiceRequest document (camelCase keys, hex ids,
integer enums and 64-bit integers as strings), which is what an OTLP collector receives over http/json.
Like the native trace snapshots, ids are renumbered so they are stable across runs while raw timestamps
are kept in the file and ignored when comparing.
"""

import base64
import copy
import difflib
import json
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Pattern
from typing import Set
from typing import Tuple

from google.protobuf.json_format import MessageToDict
from google.protobuf.json_format import ParseDict
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from .checks import CheckTrace
from .trace_snapshot import _walk_span_attributes_with_regex_replaces


OtlpDocument = Dict[str, Any]

# The SDK version changes with every tracer release and the W3C tracestate carries the random parent id.
DEFAULT_OTLP_IGNORES = ["resource.telemetry.sdk.version", "traceState"]

_TRACE_ID_KEYS = ("traceId", "trace_id")
_SPAN_ID_KEYS = ("spanId", "span_id", "parentSpanId", "parent_span_id")
# Byte length of an id and the length of its hex encoding, used to tell hex ids (OTLP/JSON spec)
# apart from base64 ids (protobuf JSON mapping, used by decode_traces_request).
_ID_BYTES = {key: 16 for key in _TRACE_ID_KEYS}
_ID_BYTES.update({key: 8 for key in _SPAN_ID_KEYS})


def _hex_ids_to_base64(obj: Any) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in _ID_BYTES and isinstance(val, str) and len(val) == 2 * _ID_BYTES[key]:
                try:
                    obj[key] = base64.b64encode(bytes.fromhex(val)).decode()
                except ValueError:
                    pass
            else:
                _hex_ids_to_base64(val)
    elif isinstance(obj, list):
        for item in obj:
            _hex_ids_to_base64(item)


def _base64_ids_to_hex(obj: Any) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in _ID_BYTES and isinstance(val, str):
                obj[key] = base64.b64decode(val).hex()
            else:
                _base64_ids_to_hex(val)
    elif isinstance(obj, list):
        for item in obj:
            _base64_ids_to_hex(item)


def _to_otlp_json(payload: Dict[str, Any]) -> OtlpDocument:
    """Convert a decoded OTLP payload to the OTLP/JSON spec representation.

    Accepts payloads decoded from protobuf (snake_case keys, base64 ids) as well as OTLP/JSON
    payloads (camelCase keys, hex ids).
    """
    payload = copy.deepcopy(payload)
    _hex_ids_to_base64(payload)
    request = ParseDict(payload, ExportTraceServiceRequest(), ignore_unknown_fields=True)
    doc = MessageToDict(request, use_integers_for_enums=True)
    _base64_ids_to_hex(doc)
    return doc


def _canonical_key(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)


def _sort_attributes(obj: Dict[str, Any]) -> None:
    if "attributes" in obj:
        obj["attributes"] = sorted(obj["attributes"], key=lambda kv: kv["key"])


def _iter_spans(doc: OtlpDocument) -> Iterable[Dict[str, Any]]:
    for resource_spans in doc.get("resourceSpans", []):
        for scope_spans in resource_spans.get("scopeSpans", []):
            yield from scope_spans.get("spans", [])


def span_count(doc: OtlpDocument) -> int:
    return sum(1 for _ in _iter_spans(doc))


def _merge(docs: List[OtlpDocument]) -> OtlpDocument:
    """Merge export requests, grouping spans that share the same resource and scope."""
    resources: Dict[str, Dict[str, Any]] = {}
    scopes: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for doc in docs:
        for resource_spans in doc.get("resourceSpans", []):
            resource_key = _canonical_key({k: v for k, v in resource_spans.items() if k != "scopeSpans"})
            if resource_key not in resources:
                merged_resource = {k: v for k, v in resource_spans.items() if k != "scopeSpans"}
                merged_resource["scopeSpans"] = []
                resources[resource_key] = merged_resource
            for scope_spans in resource_spans.get("scopeSpans", []):
                scope_key = (resource_key, _canonical_key({k: v for k, v in scope_spans.items() if k != "spans"}))
                if scope_key not in scopes:
                    merged_scope = {k: v for k, v in scope_spans.items() if k != "spans"}
                    merged_scope["spans"] = []
                    scopes[scope_key] = merged_scope
                    resources[resource_key]["scopeSpans"].append(merged_scope)
                scopes[scope_key]["spans"].extend(scope_spans.get("spans", []))
    return {"resourceSpans": list(resources.values())}


def _span_order_key(span: Dict[str, Any]) -> Tuple[int, str]:
    return int(span.get("startTimeUnixNano", 0)), span.get("name", "")


def _renumber_ids(doc: OtlpDocument) -> None:
    """Renumber trace and span ids by trace order and parent-first span order.

    Traces are ordered by the start time of their root spans and spans within a trace are ordered
    parent first, with siblings ordered by start time and then name. Ids that refer to spans outside
    of the payload are left unchanged.
    """
    traces: Dict[str, List[Dict[str, Any]]] = {}
    for span in _iter_spans(doc):
        traces.setdefault(span.get("traceId", ""), []).append(span)

    ordered_traces = []
    for trace_id, spans in traces.items():
        span_ids = {s.get("spanId") for s in spans}
        roots = []
        children: Dict[str, List[Dict[str, Any]]] = {}
        for s in spans:
            if s.get("parentSpanId") in span_ids:
                children.setdefault(s["parentSpanId"], []).append(s)
            else:
                roots.append(s)
        roots.sort(key=_span_order_key)
        ordered: List[Dict[str, Any]] = []
        queue = list(roots)
        while queue:
            s = queue.pop(0)
            ordered.append(s)
            queue.extend(sorted(children.get(s.get("spanId", ""), []), key=_span_order_key))
        ordered_traces.append(([_span_order_key(r) for r in roots], trace_id, ordered))
    ordered_traces.sort(key=lambda t: t[0])

    trace_id_map: Dict[str, str] = {}
    span_id_map: Dict[str, str] = {}
    span_order: Dict[int, int] = {}
    for _, trace_id, ordered in ordered_traces:
        trace_id_map[trace_id] = f"{len(trace_id_map) + 1:032x}"
        for s in ordered:
            span_id_map[s.get("spanId", "")] = f"{len(span_id_map) + 1:016x}"
            span_order[id(s)] = len(span_order)

    for span in _iter_spans(doc):
        span["traceId"] = trace_id_map[span.get("traceId", "")]
        span["spanId"] = span_id_map[span.get("spanId", "")]
        if span.get("parentSpanId") in span_id_map:
            span["parentSpanId"] = span_id_map[span["parentSpanId"]]
        for link in span.get("links", []):
            link["traceId"] = trace_id_map.get(link.get("traceId", ""), link.get("traceId", ""))
            link["spanId"] = span_id_map.get(link.get("spanId", ""), link.get("spanId", ""))

    # Order spans, scopes and resources by the span order so the document reads in trace order.
    for resource_spans in doc["resourceSpans"]:
        for scope_spans in resource_spans["scopeSpans"]:
            scope_spans["spans"].sort(key=lambda s: span_order[id(s)])
        resource_spans["scopeSpans"].sort(key=lambda ss: span_order[id(ss["spans"][0])] if ss["spans"] else -1)
    doc["resourceSpans"].sort(
        key=lambda rs: min((span_order[id(s)] for ss in rs["scopeSpans"] for s in ss["spans"]), default=-1)
    )


def canonicalize(payloads: List[Dict[str, Any]]) -> OtlpDocument:
    """Combine the OTLP trace payloads received in a session into a single OTLP/JSON document."""
    doc = _merge([_to_otlp_json(p) for p in payloads])
    for resource_spans in doc["resourceSpans"]:
        _sort_attributes(resource_spans.get("resource", {}))
        for scope_spans in resource_spans["scopeSpans"]:
            _sort_attributes(scope_spans.get("scope", {}))
            for span in scope_spans["spans"]:
                _sort_attributes(span)
                for event in span.get("events", []):
                    _sort_attributes(event)
                for link in span.get("links", []):
                    _sort_attributes(link)
    _renumber_ids(doc)
    return doc


def _drop_attribute(obj: Dict[str, Any], key: str) -> None:
    if "attributes" in obj:
        obj["attributes"] = [kv for kv in obj["attributes"] if kv["key"] != key]


def _drop_keys(doc: OtlpDocument, keys: Iterable[str]) -> None:
    """Drop the given keys from the document.

    Keys use the native snapshot syntax so the same ignore lists apply to native and OTLP snapshots:
    meta.X and metrics.X refer to span and resource attribute X, span_events.attributes.X and
    span_links.attributes.X to event and link attributes, start and duration to the span timestamps and
    span_events.time_unix_nano to the event timestamps. resource.X refers to resource attribute X only.
    Any other key refers to a span field. The native id keys are not mapped since the renumbered ids
    carry the trace structure.
    """
    span_attrs: Set[str] = set()
    resource_attrs: Set[str] = set()
    event_attrs: Set[str] = set()
    link_attrs: Set[str] = set()
    event_fields: Set[str] = set()
    span_fields: Set[str] = set()
    for key in keys:
        if key.startswith("meta.") or key.startswith("metrics."):
            attr = key.split(".", 1)[1]
            span_attrs.add(attr)
            resource_attrs.add(attr)
        elif key.startswith("resource."):
            resource_attrs.add(key[len("resource.") :])
        elif key.startswith("span_events.attributes."):
            event_attrs.add(key[len("span_events.attributes.") :])
        elif key.startswith("span_links.attributes."):
            link_attrs.add(key[len("span_links.attributes.") :])
        elif key == "span_events.time_unix_nano":
            event_fields.add("timeUnixNano")
        elif key == "start":
            span_fields.add("startTimeUnixNano")
        elif key == "duration":
            span_fields.add("endTimeUnixNano")
        elif key not in ("span_id", "trace_id", "parent_id") and "." not in key:
            span_fields.add(key)

    for resource_spans in doc.get("resourceSpans", []):
        for attr in resource_attrs:
            _drop_attribute(resource_spans.get("resource", {}), attr)
        for span in _iter_spans({"resourceSpans": [resource_spans]}):
            for field in span_fields:
                span.pop(field, None)
            for attr in span_attrs:
                _drop_attribute(span, attr)
            for event in span.get("events", []):
                for field in event_fields:
                    event.pop(field, None)
                for attr in event_attrs:
                    _drop_attribute(event, attr)
            for link in span.get("links", []):
                for attr in link_attrs:
                    _drop_attribute(link, attr)


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
    expected = copy.deepcopy(expected)
    received = copy.deepcopy(received)
    _walk_span_attributes_with_regex_replaces(received, attribute_regex_replaces)
    ignored = list(ignored) + DEFAULT_OTLP_IGNORES
    _drop_keys(expected, ignored)
    _drop_keys(received, ignored)
    with CheckTrace.add_frame(
        f"compare of {span_count(expected)} expected OTLP span(s) to {span_count(received)} received OTLP span(s)"
    ):
        if expected != received:
            diff = "\n".join(
                difflib.unified_diff(
                    json.dumps(expected, indent=2, sort_keys=True).splitlines(),
                    json.dumps(received, indent=2, sort_keys=True).splitlines(),
                    fromfile="expected",
                    tofile="received",
                    lineterm="",
                )
            )
            raise AssertionError(f"Received OTLP traces do not match the snapshot:\n{diff}")
