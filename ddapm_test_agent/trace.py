"""Tracing specific functions and types"""
import json
from typing import Any
from typing import Callable
from typing import Dict
from typing import Generator
from typing import List
from typing import Literal
from typing import Optional
from typing import OrderedDict
from typing import Tuple
from typing import Union
from typing import cast

import msgpack
from typing_extensions import NotRequired
from typing_extensions import TypedDict


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
SPAN_REQUIRED_ATTRS = [
    "name",
    "span_id",
    "trace_id",
    "duration",
    "start",
    "parent_id",
]

MetricType = Union[int, float]


class SpanLink(TypedDict):
    trace_id: int
    trace_id_high: int
    span_id: SpanId
    attributes: NotRequired[Dict[str, str]]
    tracestate: NotRequired[Optional[str]]
    flags: NotRequired[Optional[int]]


class Span(TypedDict):
    name: str
    span_id: SpanId
    trace_id: TraceId
    start: int
    duration: int
    parent_id: NotRequired[Optional[int]]
    service: NotRequired[Optional[str]]
    resource: NotRequired[Optional[str]]
    type: NotRequired[Optional[str]]  # noqa
    error: NotRequired[Optional[int]]
    meta: NotRequired[Dict[str, str]]
    metrics: NotRequired[Dict[str, MetricType]]
    span_links: NotRequired[List[SpanLink]]


SpanAttr = Literal[
    "name",
    "span_id",
    "trace_id",
    "start",
    "duration",
    "parent_id",
    "service",
    "resource",
    "type",
    "error",
    "meta",
    "metrics",
    "span_links",
]
TopLevelSpanValue = Union[None, SpanId, TraceId, int, str, Dict[str, str], Dict[str, MetricType], List[SpanLink]]
Trace = List[Span]
v04TracePayload = List[List[Span]]
TraceMap = OrderedDict[int, Trace]


def verify_span(d: Any) -> Span:
    try:
        assert isinstance(d, dict), f"Expected 'span' to be of type: '{dict}', got: '{type(d)}'"
        # TODO: check these
        required_attrs = ["span_id", "trace_id", "name"]
        for attr in required_attrs:
            assert attr in d, f"'{attr}' required in span"
        NoneType = type(None)
        assert isinstance(d["span_id"], int), "Expected 'span_id' to be of type: 'int', got: " + str(type(d["span_id"]))
        assert isinstance(d["trace_id"], int), "Expected 'trace_id' to be of type: 'int', got: " + str(
            type(d["trace_id"])
        )
        assert isinstance(d["name"], str), "Expected 'name' to be of type: 'str', got: " + str(type(d["name"]))
        if "resource" in d:
            assert isinstance(d["resource"], (str, NoneType)), "Expected 'resource' to be of type: 'str', got: " + str(type(d["resource"]))  # type: ignore
        if "service" in d:
            assert isinstance(d["service"], (str, NoneType)), "Expected 'service' to be of type: 'str', got: " + str(type(d["service"]))  # type: ignore
        if "type" in d:
            assert isinstance(d["type"], (str, NoneType)), "Expected 'type' to be of type: 'str', got: " + str(type(d["type"]))  # type: ignore
        if "parent_id" in d:
            assert isinstance(d["parent_id"], (int, NoneType)), "Expected 'parent_id' to be of type: 'int', got: " + str(type(d["parent_id"]))  # type: ignore
        if "error" in d:
            assert isinstance(d["error"], int), "Expected error to be of type: 'int', got: " + str(type(d["error"]))
        if "meta" in d:
            assert isinstance(d["meta"], dict)
            for k, v in d["meta"].items():
                assert isinstance(k, str), f"Expected key 'meta.{k}' to be of type: 'str', got: {type(k)}"
                assert isinstance(v, str), f"Expected value of key 'meta.{k}' to be of type: 'str', got: {type(v)}"
        if "metrics" in d:
            assert isinstance(d["metrics"], dict)
            for k, v in d["metrics"].items():
                assert isinstance(k, str), f"Expected key 'metrics.{k}' to be of type: 'str', got: {type(k)}"
                assert isinstance(
                    v, (int, float)
                ), f"Expected value of key 'metrics.{k}' to be of type: 'float/int', got: {type(v)}"
        if "span_links" in d:
            assert isinstance(d["span_links"], list)
            for link in d["span_links"]:
                assert isinstance(link, dict), f"Expected all span_links to be of type: 'dict', got: {type(link)}"
                required_attrs = ["span_id", "trace_id"]
                for attr in required_attrs:
                    assert attr in link, f"'{attr}' required in span link"
                assert isinstance(link["span_id"], int), "Expected 'span_id' to be of type: 'int', got: " + str(
                    type(link["span_id"])
                )
                assert isinstance(link["trace_id"], int), "Expected 'trace_id' to be of type: 'int', got: " + str(
                    type(link["trace_id"])
                )
                if "trace_id_high" in link:
                    assert isinstance(
                        link["trace_id_high"], (int, NoneType)  # type: ignore
                    ), "Expected 'trace_id_high' to be of type: 'int', got: " + str(type(link["trace_id_high"]))
                if "attributes" in link:
                    assert isinstance(link["attributes"], dict)
                    for k, v in link["attributes"].items():
                        assert isinstance(k, str), f"Expected key 'attributes.{k}' to be of type: 'str', got: {type(k)}"
                        assert isinstance(
                            v, str
                        ), f"Expected value of key 'attributes.{k}' to be of type: 'str', got: {type(v)}"
                if "tracestate" in link:
                    assert isinstance(
                        link["tracestate"], (str, NoneType)  # type: ignore
                    ), "Expected 'tracestate' to be of type: 'str', got: " + str(type(link["tracestate"]))
                if "flags" in link:
                    assert isinstance(link["flags"], int), "Expected flags to be of type: 'int', got: " + str(
                        type(link["flags"])
                    )
        return cast(Span, d)
    except AssertionError as e:
        raise TypeError(*e.args) from e


def v04_verify_trace(maybe_trace: Any) -> Trace:
    if not isinstance(maybe_trace, list):
        raise TypeError("Trace must be a list.")
    for maybe_span in maybe_trace:
        verify_span(maybe_span)
    return cast(Trace, maybe_trace)


def _verify_v04_payload(data: Any) -> v04TracePayload:
    if not isinstance(data, list):
        raise TypeError("Trace payload must be a list.")
    for maybe_trace in data:
        v04_verify_trace(maybe_trace)
    return cast(v04TracePayload, data)


def child_map(trace: Trace) -> Dict[int, List[Span]]:
    cmap: Dict[SpanId, List[Span]] = {}
    # Initialize the map with all possible ids
    for s in trace:
        cmap[s["span_id"]] = []
        parent_id = s.get("parent_id") or 0
        cmap[parent_id] = []

    for s in trace:
        parent_id = s.get("parent_id") or 0
        cmap[parent_id].append(s)

    # Sort the children ascending by their start time, else by their span_id
    for span_id in cmap:
        cmap[span_id] = sorted(cmap[span_id], key=lambda _: (_["start"] if "start" in _ else _["span_id"]))
    return cmap


def bfs_order(trace: Trace) -> Generator[Span, None, None]:
    """Return trace in BFS order.

    Note: does not return copies of the spans.
    """
    cmap = child_map(trace)
    root = root_span(trace)
    children = [[root]]
    while children:
        cs = children.pop(0)
        for c in cs:
            yield c
            children.append(cmap[c["span_id"]])


def dfs_order(trace: Trace) -> Generator[Span, None, None]:
    """Return the trace in DFS order.

    Note: does not return copies of the spans.
    """
    cmap = child_map(trace)
    root = root_span(trace)
    children = [root]
    while children:
        c = children.pop(0)
        yield c
        children = cmap[c["span_id"]] + children


def dfs_order_with_depth(trace: Trace) -> Generator[Tuple[Span, int], None, None]:
    cmap = child_map(trace)
    root = root_span(trace)
    children = [(root, 0)]
    while children:
        c, depth = children.pop(0)
        yield c, depth
        children = [(_, depth) for _ in cmap[c["span_id"]]] + children


def pprint_trace(
    trace: Trace,
    fmt: Union[str, Callable[[Span], str]],
) -> str:
    cmap = child_map(trace)
    stack: List[Tuple[str, str, Span]] = [("", "", root_span(trace))]
    s = ""
    while stack:
        prefix, childprefix, span = stack.pop(0)
        for i, child in enumerate(reversed(cmap[span["span_id"]])):
            if i == 0:
                stack.insert(0, (childprefix + "└─ ", childprefix + "   ", child))
            else:
                stack.insert(0, (childprefix + "├─ ", childprefix + "│  ", child))

        spanf = fmt(span) if callable(fmt) else fmt.format(**span)
        s += f"{prefix}{spanf}"
        if stack:
            s += "\n"
    return s


def copy_span_links(s: SpanLink) -> SpanLink:
    attributes = s["attributes"].copy() if "attributes" in s else None
    copy = s.copy()
    if attributes is not None:
        copy["attributes"] = attributes
    return copy


def copy_span(s: Span) -> Span:
    meta = s["meta"].copy() if "meta" in s else None
    metrics = s["metrics"].copy() if "metrics" in s else None
    links = s["span_links"].copy() if "span_links" in s else None
    copy = s.copy()
    if meta is not None:
        copy["meta"] = meta
    if metrics is not None:
        copy["metrics"] = metrics
    if links is not None:
        copy["span_links"] = [copy_span_links(link) for link in links]
    return copy


def copy_trace(t: Trace) -> Trace:
    return [copy_span(s) for s in t]


def root_span(t: Trace) -> Span:
    """Return the root span of the trace."""
    # Follow approach used in Datadog Agent: https://github.com/DataDog/datadog-agent/blob/927f9ca9acf7983b72a4bfbdd7a69132e1da8501/pkg/trace/traceutil/trace.go#L53

    if len(t) == 0:
        raise ValueError("empty trace: %s" % t)

    # common case optimization to check for span where parent_id is either not
    # set or set to 0
    for s in t:
        if "parent_id" not in s or s["parent_id"] is None or s["parent_id"] == 0:
            return s

    # collect root spans as those with parents that are not themselves spans in trace
    span_ids = set(s["span_id"] for s in t)
    roots = {s["parent_id"]: s for s in t if "parent_id" in s and s["parent_id"] not in span_ids}

    if len(roots) != 1:
        raise ValueError("single root span not found in trace (n=%d): %s" % (len(t), t))

    # return any root candidate
    return roots.popitem()[1]


def trace_id(t: Trace) -> TraceId:
    return t[0]["trace_id"]


def set_attr(s: Span, k: SpanAttr, v: TopLevelSpanValue) -> Span:
    s[k] = v
    return s


def set_meta_tag(s: Span, k: str, v: str) -> Span:
    s["meta"][k] = v
    return s


def set_metric_tag(s: Span, k: str, v: MetricType) -> Span:
    s["metrics"][k] = v
    return s


def add_span_link(
    s: Span, link: Span, attributes: Optional[Dict[str, str]] = None, flags: Optional[int] = None
) -> Span:
    if "span_links" not in s:
        s["span_links"] = []
    new_link = SpanLink(trace_id=link["trace_id"], span_id=link["span_id"], trace_id_high=0)
    if attributes is not None:
        new_link["attributes"] = attributes
    if flags is not None:
        new_link["flags"] = flags
    s["span_links"].append(new_link)
    return s


def _trace_decoder_flexible(json_string: bytes) -> Dict[str, Any]:
    """Parse Trace JSON and accounts for meta that may contain numbers such as ports. Converts these meta correctly to strings.
    Also ensures that any valid integers/floats are correctly parsed, to prevent ids from being decoded as strings incorrectly.
    """

    def is_number_as_str(num, number_type=int):
        try:
            number_type(num)
            return isinstance(num, str)
        except ValueError:
            return False

    # Define a custom JSON decoder for decoding spans
    def json_decoder(maybe_span):
        # loop through the span object
        if isinstance(maybe_span, dict):
            for key, value in maybe_span.items():
                if key == "meta":
                    # Check if the value is an int or float and convert back to string if true
                    for k, v in value.items():
                        if isinstance(v, int) or isinstance(v, float):
                            value[k] = str(v)
                elif key == "metrics":
                    for k, v in value.items():
                        # Check if value is a a float or int
                        if is_number_as_str(v, int):
                            value[k] = int(v)
                        elif is_number_as_str(v, float):
                            value[k] = float(v)
                # For other attributes, check if the value is a string that can be converted to an int
                elif is_number_as_str(value, int):
                    maybe_span[key] = int(value)
        return maybe_span

    parsed_data: Dict[str, Any] = json.loads(json_string, object_hook=json_decoder)
    return parsed_data


def decode_v04(content_type: str, data: bytes, suppress_errors: bool) -> v04TracePayload:
    if content_type == "application/msgpack":
        payload = msgpack.unpackb(data)
    elif content_type == "application/json":
        payload = _trace_decoder_flexible(data) if suppress_errors else json.loads(data)
    else:
        raise TypeError("Content type %r not supported" % content_type)
    return _verify_v04_payload(payload)


def decode_v05(data: bytes) -> v04TracePayload:
    payload = msgpack.unpackb(data, strict_map_key=False)
    if not isinstance(payload, list):
        raise TypeError("Trace payload must be an array containing two elements, got type %r." % type(payload))
    if len(payload) != 2:
        raise TypeError("Trace payload must contain two elements, got an array with %r elements." % len(payload))

    maybe_string_table = payload[0]
    for s in maybe_string_table:
        if not isinstance(s, str):
            raise TypeError("String table contains non-string value %r." % s)
    string_table = cast(List[str], maybe_string_table)

    v05_traces = payload[1]
    traces: List[List[Span]] = []
    for v05_trace in v05_traces:
        trace: List[Span] = []
        for v05_span in v05_trace:
            if not isinstance(v05_span, list):
                raise TypeError("Span data was not an array, got type %r." % type(v05_span))
            if len(v05_span) != 12:
                raise TypeError("Span data was not an array of size 12, got array of size %r" % len(v05_span))

            v05_meta = v05_span[9]
            meta: Dict[str, str] = {}
            for idx1, idx2 in v05_meta.items():
                meta[string_table[idx1]] = string_table[idx2]

            v05_metrics = v05_span[10]
            metrics: Dict[str, MetricType] = {}
            for idx, val in v05_metrics.items():
                if not isinstance(val, (float, int)):
                    raise TypeError("Unexpected metric type %s" % type(val))
                metrics[string_table[idx]] = val

            # Recreate the span using the string values from the table
            span = verify_span(
                {
                    "service": string_table[v05_span[0]],
                    "name": string_table[v05_span[1]],
                    "resource": string_table[v05_span[2]],
                    "trace_id": v05_span[3],
                    "span_id": v05_span[4],
                    "parent_id": v05_span[5],
                    "start": v05_span[6],
                    "duration": v05_span[7],
                    "error": v05_span[8],
                    "meta": meta,
                    "metrics": metrics,
                    "type": string_table[v05_span[11]],
                }
            )
            trace.append(span)
        traces.append(trace)
    return traces
