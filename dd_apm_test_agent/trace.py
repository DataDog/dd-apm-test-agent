"""Tracing specific functions and types"""
import json
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import TypedDict
from typing import cast

import msgpack
import typeguard


SpanId = int
TraceId = int


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


def _verify_v04_payload(data: bytes) -> v04TraceChunk:
    typeguard.check_type("data", data, v04TraceChunk)
    return cast(v04TraceChunk, data)


def _child_map(trace: Trace) -> Dict[int, List[Span]]:
    child_map: Dict[int, List[Span]] = {}
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


def decode_v04(content_type: str, data: bytes) -> v04TraceChunk:
    if content_type == "application/msgpack":
        chunk = msgpack.unpackb(data)
    elif content_type == "application/json":
        chunk = json.loads(data)
    else:
        raise TypeError("Content type %r not supported" % content_type)
    return _verify_v04_payload(chunk)
