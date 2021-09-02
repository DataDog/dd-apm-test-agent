"""Tracing specific functions and types"""
import json
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import TypedDict
from typing import cast

import msgpack


SpanId = int
TraceId = int


SPAN_TYPES = [
    "cache",
    "cassandra",
    "elasticsearch",
    "grpc",
    "http",
    "mongodb",
    "redis",
    "sql",
    "template",
    "test",
    "web",
    "worker",
]


class Span(TypedDict, total=False):
    name: str
    span_id: SpanId
    trace_id: TraceId
    parent_id: Optional[int]  # TODO: is this actually optional...it could be?
    service: Optional[str]
    resource: Optional[str]
    type: Optional[str]  # noqa
    error: Optional[int]
    start: int
    duration: int
    meta: Dict[str, str]
    metrics: Dict[str, float]


Trace = List[Span]
v04TraceChunk = List[List[Span]]
TraceMap = Dict[int, Trace]


def v04_verify_span(d: Dict[str, Any]) -> Span:
    # TODO: check these
    try:
        required_attrs = ["span_id", "trace_id", "name"]
        for attr in required_attrs:
            assert attr in d, f"'{attr}' required in span"
        NoneType = type(None)
        assert isinstance(d["span_id"], int)
        assert isinstance(d["trace_id"], int)
        assert isinstance(d["name"], str)
        if "resource" in d:
            assert isinstance(d["resource"], (str, NoneType))
        if "service" in d:
            assert isinstance(d["service"], (str, NoneType))
        if "type" in d:
            assert isinstance(d["type"], (str, NoneType))
        if "parent_id" in d:
            assert isinstance(d["parent_id"], (int, NoneType))
        if "error" in d:
            assert isinstance(d["error"], int)
        if "meta" in d:
            assert isinstance(d["meta"], dict)
            for k, v in d["meta"].items():
                assert isinstance(k, str)
                assert isinstance(v, str)
        if "metrics" in d:
            assert isinstance(d["metrics"], dict)
            for k, v in d["metrics"].items():
                assert isinstance(k, str)
                assert isinstance(v, (float, int))
        return cast(Span, d)
    except AssertionError as e:
        raise TypeError(*e.args) from e


def v04_verify_trace(maybe_trace: Any) -> Trace:
    if not isinstance(maybe_trace, list):
        raise TypeError("Trace must be a list.")
    for maybe_span in maybe_trace:
        v04_verify_span(maybe_span)
    return cast(Trace, maybe_trace)


def _verify_v04_payload(data: Any) -> v04TraceChunk:
    if not isinstance(data, list):
        raise TypeError("Trace chunk must be a list.")
    for maybe_trace in data:
        v04_verify_trace(maybe_trace)
    return cast(v04TraceChunk, data)


def _child_map(trace: Trace) -> Dict[int, List[Span]]:
    child_map: Dict[SpanId, List[Span]] = {}
    # Initialize the map with all possible ids
    for s in trace:
        child_map[s["span_id"]] = []
        child_map[s["parent_id"]] = []

    for s in trace:
        child_map[s["parent_id"]].append(s)

    # Sort the children by their start time
    for span_id in child_map:
        child_map[span_id] = sorted(child_map[span_id], key=lambda s: s["start"])
    return child_map


def bfs_order(trace: Trace) -> Generator[Span, None, None]:
    child_map = _child_map(trace)
    root = root_span(trace)
    children = [[root]]
    while children:
        cs = children.pop(0)
        for c in cs:
            yield c
            children.append(child_map[c["span_id"]])


def dfs_order(trace: Trace) -> Generator[Span, None, None]:
    child_map = _child_map(trace)
    root = root_span(trace)
    children = [root]
    while children:
        c = children.pop(0)
        yield c
        children = child_map[c["span_id"]] + children


def root_span(t: Trace) -> Span:
    """Return the root span of the trace."""
    for s in t:
        if "parent_id" not in s or s["parent_id"] is None or s["parent_id"] == 0:
            return s

    raise ValueError("root span not found in trace")


def trace_id(t: Trace) -> TraceId:
    return t[0]["trace_id"]


def decode_v04(content_type: str, data: bytes) -> v04TraceChunk:
    if content_type == "application/msgpack":
        chunk = msgpack.unpackb(data)
    elif content_type == "application/json":
        chunk = json.loads(data)
    else:
        raise TypeError("Content type %r not supported" % content_type)
    return _verify_v04_payload(chunk)
