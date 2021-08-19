"""Tracing specific functions and types"""
import json
from typing import Dict
from typing import List
from typing import Optional
from typing import TypedDict
from typing import cast

import msgpack
import typeguard


class Span(TypedDict, total=False):
    name: str
    span_id: int
    trace_id: int
    parent_id: Optional[int]
    service: Optional[str]
    resource: Optional[str]
    type: Optional[str]  # noqa
    error: Optional[int]
    meta: Dict[str, str]
    metrics: Dict[str, float]


Trace = List[Span]
v04TraceChunk = List[List[Span]]
TraceMap = Dict[int, Trace]


def _verify_v04_payload(data: bytes) -> v04TraceChunk:
    typeguard.check_type("data", data, v04TraceChunk)
    return cast(v04TraceChunk, data)


def decode_v04(content_type: str, data: bytes) -> v04TraceChunk:
    if content_type == "application/msgpack":
        chunk = msgpack.unpackb(data)
    elif content_type == "application/json":
        chunk = json.loads(data)
    else:
        raise TypeError("Content type %r not supported" % content_type)
    return _verify_v04_payload(chunk)
