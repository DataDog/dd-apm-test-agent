"""Tracing specific functions and types"""

from enum import IntEnum
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


class SpanEvent(TypedDict):
    time_unix_nano: int
    name: str
    attributes: NotRequired[Dict[str, Dict[str, Any]]]


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
    span_events: NotRequired[List[SpanEvent]]
    meta_struct: NotRequired[Dict[str, Dict[str, Any]]]


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
    "span_events",
    "meta_struct",
]
TopLevelSpanValue = Union[
    None,
    SpanId,
    TraceId,
    int,
    str,
    Dict[str, str],
    Dict[str, MetricType],
    List[SpanLink],
    List[SpanEvent],
]
Trace = List[Span]
v04TracePayload = List[List[Span]]
TraceMap = OrderedDict[int, Trace]


class V1ChunkKeys(IntEnum):
    PRIORITY = 1
    ORIGIN = 2
    ATTRIBUTES = 3
    SPANS = 4
    DROPPED_TRACE = 5
    TRACE_ID = 6
    SAMPLING_MECHANISM = 7


class V1SpanKeys(IntEnum):
    SERVICE = 1
    NAME = 2
    RESOURCE = 3
    SPAN_ID = 4
    PARENT_ID = 5
    START = 6
    DURATION = 7
    ERROR = 8
    ATTRIBUTES = 9
    TYPE = 10
    SPAN_LINKS = 11
    SPAN_EVENTS = 12
    ENV = 13
    VERSION = 14
    COMPONENT = 15
    SPAN_KIND = 16


class V1SpanLinkKeys(IntEnum):
    TRACE_ID = 1
    SPAN_ID = 2
    ATTRIBUTES = 3
    TRACE_STATE = 4
    FLAGS = 5


class V1SpanEventKeys(IntEnum):
    TIME = 1
    NAME = 2
    ATTRIBUTES = 3


class V1AnyValueKeys(IntEnum):
    STRING = 1
    BOOL = 2
    DOUBLE = 3
    INT = 4
    BYTES = 5
    ARRAY = 6
    KEY_VALUE_LIST = 7


# TODO:ban add extra tags to add to the span
# TODO:ban warn about dropping metastruct
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
            for k, attr in d["meta"].items():
                assert isinstance(k, str), f"Expected key 'meta.{k}' to be of type: 'str', got: {type(k)}"
                assert isinstance(
                    attr, str
                ), f"Expected value of key 'meta.{k}' to be of type: 'str', got: {type(attr)}"
        if "meta_struct" in d:
            assert isinstance(d["meta_struct"], dict)
            for k, val in d["meta_struct"].items():
                assert isinstance(k, str), f"Expected key 'meta_struct.{k}' to be of type: 'str', got: {type(k)}"
                assert isinstance(
                    val, dict
                ), f"Expected msgpack decoded value of key 'meta_struct.{k}' to be of type: 'dict', got: {type(val)}"
                for inner_k in val:
                    assert isinstance(
                        inner_k, str
                    ), f"Expected key 'meta_struct.{k}.{inner_k}' to be of type: 'str', got: {type(inner_k)}"
        if "metrics" in d:
            assert isinstance(d["metrics"], dict)
            for k, attr in d["metrics"].items():
                assert isinstance(k, str), f"Expected key 'metrics.{k}' to be of type: 'str', got: {type(k)}"
                assert isinstance(
                    attr, (int, float)
                ), f"Expected value of key 'metrics.{k}' to be of type: 'float/int', got: {type(attr)}"
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
                    for k, attr in link["attributes"].items():
                        assert isinstance(k, str), f"Expected key 'attributes.{k}' to be of type: 'str', got: {type(k)}"
                        assert isinstance(
                            attr, str
                        ), f"Expected value of key 'attributes.{k}' to be of type: 'str', got: {type(attr)}"
                if "tracestate" in link:
                    assert isinstance(
                        link["tracestate"], (str, NoneType)  # type: ignore
                    ), "Expected 'tracestate' to be of type: 'str', got: " + str(type(link["tracestate"]))
                if "flags" in link:
                    assert isinstance(link["flags"], int), "Expected flags to be of type: 'int', got: " + str(
                        type(link["flags"])
                    )
        if "span_events" in d:
            assert isinstance(d["span_events"], list)
            for event in d["span_events"]:
                assert isinstance(event, dict), f"Expected all span_events to be of type: 'dict', got: {type(event)}"
                required_attrs = ["time_unix_nano", "name"]
                for attr in required_attrs:
                    assert attr in event, f"'{attr}' required in span event"
                assert isinstance(
                    event["time_unix_nano"], int
                ), "Expected 'time_unix_nano' to be of type: 'int', got: " + str(type(event["time_unix_nano"]))
                assert isinstance(event["name"], str), "Expected 'name' to be of type: 'str', got: " + str(
                    type(event["name"])
                )
                if "attributes" in event:
                    assert isinstance(event["attributes"], dict)
                    for k, attr in event["attributes"].items():
                        assert isinstance(k, str), f"Expected key 'attributes.{k}' to be of type: 'str', got: {type(k)}"
                        assert isinstance(
                            attr, dict
                        ), f"Expected value 'attributes.{k}={attr}' to be of type: 'dict', got: {type(attr)}"

                        # for this data struture for attr:
                        # // AttributeAnyValue is an Object with String keys, defined below.
                        # // We have to implement a union type manually here because Go's MessagePack generator does not support
                        # // unions: https://github.com/tinylib/msgp/issues/184
                        # {
                        #   // Represents the type of the value represented in this attribute entry.
                        #   // For String values: "type": 0
                        #   // For Boolean values: "type": 1
                        #   // For Integer values: "type": 2
                        #   // For Double values: "type": 3
                        #   // For Array values: "type": 4
                        #   "type": Integer,
                        #
                        #   // Populate with a String value if `type` is 0, otherwise do not include this field.
                        #   "string_value": String,
                        #   // Populate with a Boolean value if `type` is 1, otherwise do not include this field.
                        #   "bool_value": Boolean,
                        #   // Populate with a Integer value if `type` is 2, otherwise do not include this field.
                        #   "int_value": Integer,
                        #   // Populate with a Double value if `type` is 3, otherwise do not include this field.
                        #   "double_value": Double,
                        #   // Populate with a Array value if `type` is 4, otherwise do not include this field.
                        #   "array_value": Array<AttributeArrayValue>,
                        # }
                        # assert its values

                        if attr["type"] == 0:
                            assert isinstance(
                                attr["string_value"], str
                            ), f"Expected 'string_value' to be of type: 'str', got: {type(attr['string_value'])}"
                        elif attr["type"] == 1:
                            assert isinstance(
                                attr["bool_value"], bool
                            ), f"Expected 'bool_value' to be of type: 'bool', got: {type(attr['bool_value'])}"
                        elif attr["type"] == 2:
                            assert isinstance(
                                attr["int_value"], int
                            ), f"Expected 'int_value' to be of type: 'int', got: {type(attr['int_value'])}"
                        elif attr["type"] == 3:
                            assert isinstance(
                                attr["double_value"], float
                            ), f"Expected 'double_value' to be of type: 'float', got: {type(attr['double_value'])}"
                        elif attr["type"] == 4:
                            assert isinstance(
                                attr["array_value"], dict
                            ), f"Expected 'array_value' to be of type: 'dict', got: {type(attr['array_value'])}"
                            assert (
                                len(attr["array_value"]) == 1 and attr["array_value"].get("values") is not None
                            ), f"Expected 'array_value' to contain exactly one key values, got keys: {' ,'.join(attr['array_value'].keys())}"
                            array = attr["array_value"]["values"]
                            if array:
                                first_type = array[0]["type"]
                                i = None
                                assert all(
                                    i["type"] == first_type for i in array
                                ), f"Expected all elements in list to be of the same type: '{first_type}', got: {i['type']}"

                            for e in array:
                                assert isinstance(
                                    e, dict
                                ), f"Expected all elements in 'array_value' to be of type: 'dict', got: {type(e)}"
                                if e["type"] == 0:
                                    assert isinstance(
                                        e["string_value"], str
                                    ), f"Expected 'string_value' to be of type: 'str', got: {type(e['string_value'])}"
                                elif e["type"] == 1:
                                    assert isinstance(
                                        e["bool_value"], bool
                                    ), f"Expected 'bool_value' to be of type: 'bool', got: {type(e['bool_value'])}"
                                elif e["type"] == 2:
                                    assert isinstance(
                                        e["int_value"], int
                                    ), f"Expected 'int_value' to be of type: 'int', got: {type(e['int_value'])}"
                                elif e["type"] == 3:
                                    assert isinstance(
                                        e["double_value"], float
                                    ), f"Expected 'double_value' to be of type: 'float', got: {type(e['double_value'])}"
                                else:
                                    raise ValueError(
                                        f"Unsupported span event attribute type {attr['type']} for: {k}={attr}"
                                    )
                        else:
                            raise ValueError(f"Unsupported span event attribute type {attr['type']} for: {k}={attr}")

        return cast(Span, d)
    except AssertionError as e:
        raise TypeError(*e.args) from e


def _parse_meta_struct(value: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(value, dict):
        raise TypeError("Expected meta_struct to be of type: 'dict', got: %s" % type(value))

    return {key: msgpack.unpackb(val_bytes) for key, val_bytes in value.items()}


def _flexible_decode_meta_struct(value: Any) -> None:
    if not isinstance(value, list):
        return
    for maybe_trace in value:
        if not isinstance(maybe_trace, list):
            continue
        for maybe_span in maybe_trace:
            if not isinstance(maybe_span, dict):
                continue
            if "meta_struct" in maybe_span:
                maybe_span["meta_struct"] = _parse_meta_struct(maybe_span["meta_struct"])


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


def copy_span_events(s: SpanEvent) -> SpanEvent:
    attributes = s["attributes"].copy() if "attributes" in s else None
    copy = s.copy()
    if attributes is not None:
        # Copy arrays inside attributes
        for k, v in attributes.items():
            if isinstance(v, dict) and v["type"] == "array_value":
                array = v["array_value"]["values"]

                value = v.copy()
                value["array_value"] = {"values": array.copy()}

                attributes[k] = value
        copy["attributes"] = attributes
    return copy


def copy_span(s: Span) -> Span:
    meta = s["meta"].copy() if "meta" in s else None
    metrics = s["metrics"].copy() if "metrics" in s else None
    links = s["span_links"].copy() if "span_links" in s else None
    events = s["span_events"].copy() if "span_events" in s else None
    copy = s.copy()
    if meta is not None:
        copy["meta"] = meta
    if metrics is not None:
        copy["metrics"] = metrics
    if links is not None:
        copy["span_links"] = [copy_span_links(link) for link in links]
    if events is not None:
        copy["span_events"] = [copy_span_events(event) for event in events]
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


def add_span_event(
    s: Span,
    time_unix_nano: int = 1730405656000000000,
    name: str = "event",
    attributes: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Span:
    if "span_events" not in s:
        s["span_events"] = []
    new_event = SpanEvent(time_unix_nano=time_unix_nano, name=name)
    if attributes is not None:
        # Add protobuf-like structure for attributes
        new_attributes: Dict[str, Dict[str, Any]] = {}
        for k, v in attributes.items():
            if isinstance(v, str):
                new_attributes[k] = {"type": 0, "string_value": v}
            elif isinstance(v, bool):
                new_attributes[k] = {"type": 1, "bool_value": v}
            elif isinstance(v, int):
                new_attributes[k] = {"type": 2, "int_value": v}
            elif isinstance(v, float):
                new_attributes[k] = {"type": 3, "double_value": v}
            elif isinstance(v, list):
                array_value: Dict[str, List[Dict[str, Any]]] = {"values": []}
                new_attributes[k] = {"type": 4, "array_value": array_value}
                for i in v:
                    if isinstance(i, str):
                        array_value["values"].append({"type": 0, "string_value": i})
                    elif isinstance(i, bool):
                        array_value["values"].append({"type": 1, "bool_value": i})
                    elif isinstance(i, int):
                        array_value["values"].append({"type": 2, "int_value": i})
                    elif isinstance(i, float):
                        array_value["values"].append({"type": 3, "double_value": i})
                    else:
                        raise ValueError(f"Unsupported span event attribute type {type(i)} for: {k}={v}")
            else:
                raise ValueError(f"Unsupported span event attribute type {type(v)} for: {k}={v}")
        new_event["attributes"] = new_attributes
    s["span_events"].append(new_event)
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
    _flexible_decode_meta_struct(payload)
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


def decode_v07(data: bytes) -> v04TracePayload:
    """Decode a v07 trace payload.
    The v07 format is almost the same as the v04 format, but the there is some
    extra structure to the payload.

    These are the types of the payload:

    class TracerPayloadV07(TypedDict):
        container_id: NotRequired[str]
        language_name: NotRequired[str]
        language_version: NotRequired[str]
        tracer_version: NotRequired[str]
        runtime_id: NotRequired[str]
        chunks: List[TraceChunkV07]
        tags: NotRequired[Dict[str, str]]
        env: NotRequired[str]
        hostname: NotRequired[str]
        app_version: NotRequired[str]

    class TraceChunkV07(TypedDict):
        priority: int
        origin: str
        spans: List[Span]
        tags: NotRequired[Dict[str, str]]
        droppedTrace: NotRequired[bool]
    """
    payload = msgpack.unpackb(data)
    return _verify_v07_payload(payload)


def decode_v1(data: bytes) -> v04TracePayload:
    """Decode a v1 trace payload.
    The v1 format is similar to the v07 format but in an optimized format and with a few changes:
    - Strings are deduplicated and sent in a "Streaming" format where strings are referred to by their index in a string table
    - Trace IDs are sent as 128 bit integers in a bytes array
    - 'meta' and 'metrics' are now sent as typed 'attributes', more similar to how OTLP traces are sent
    """
    payload = msgpack.unpackb(data, strict_map_key=False)
    return _convert_v1_payload(payload)


def _get_and_add_string(string_table: List[str], value: Union[int, str]) -> str:
    if isinstance(value, str):
        string_table.append(value)
        return value
    elif isinstance(value, int):
        if value >= len(string_table) or value < 0:
            raise ValueError(f"Value {value} is out of range for string table of length {len(string_table)}")
        return string_table[value]


def _convert_v1_payload(data: Any) -> v04TracePayload:
    if not isinstance(data, dict):
        raise TypeError("Trace payload must be a map, got type %r." % type(data))

    string_table: List[str] = [""]  # 0 is reserved for empty string

    v04Payload: List[List[Span]] = []

    for k, v in data.items():
        if k == 1:
            raise TypeError("Message pack representation of v1 trace payload must stream strings")
        elif k > 1 and k < 10:  # All keys from 2-9 are strings, for now we can just build the string table
            # TODO: In the future we can assert on these keys
            if isinstance(v, str):
                string_table.append(v)
        elif k == 11:
            if not isinstance(v, list):
                raise TypeError("Trace payload 'chunks' (11) must be a list.")
            for chunk in v:
                v04Payload.append(_convert_v1_chunk(chunk, string_table))
        else:
            raise TypeError("Unknown key %r in v1 trace payload" % k)
    return cast(v04TracePayload, v04Payload)


def _convert_v1_chunk(chunk: Any, string_table: List[str]) -> List[Span]:
    if not isinstance(chunk, dict):
        raise TypeError("Chunk must be a map.")

    priority, origin, sampling_mechanism = "", "", None
    trace_id, trace_id_high = 0, 0
    meta: Dict[str, str] = {}
    metrics: Dict[str, MetricType] = {}
    spans: List[Span] = []
    for k, v in chunk.items():
        if k == V1ChunkKeys.PRIORITY:
            priority = v
        elif k == V1ChunkKeys.ORIGIN:
            origin = _get_and_add_string(string_table, v)
        elif k == V1ChunkKeys.ATTRIBUTES:
            if not isinstance(v, list):
                raise TypeError("Chunk Attributes must be a list, got type %r." % type(v))
            _convert_v1_attributes(v, meta, metrics, string_table)
        elif k == V1ChunkKeys.SPANS:
            if not isinstance(v, list):
                raise TypeError("Chunk 'spans'(4) must be a list.")
            for span in v:
                converted_span = _convert_v1_span(span, string_table)
                spans.append(converted_span)
        elif k == V1ChunkKeys.DROPPED_TRACE:
            raise TypeError("Tracers must not set the droppedTrace(5) flag.")
        elif k == V1ChunkKeys.TRACE_ID:
            if len(v) != 16:
                raise TypeError("Trace ID must be 16 bytes, got %r." % len(v))
            # trace_id is a 128 bit integer in a bytes array, so we need to get the last 64 bits
            trace_id = int.from_bytes(v[8:], "big")
            trace_id_high = int.from_bytes(v[:8], "big")
        elif k == V1ChunkKeys.SAMPLING_MECHANISM:
            sampling_mechanism = v
        else:
            raise TypeError("Unknown key %r in v1 trace chunk" % k)

    for span in spans:
        if "metrics" not in span:
            span["metrics"] = {}
        if "meta" not in span:
            span["meta"] = {}
        span["trace_id"] = trace_id
        span["meta"]["_dd.p.tid"] = hex(trace_id_high)
        if sampling_mechanism is not None:
            span["meta"]["_dd.p.dm"] = "-" + str(sampling_mechanism)
        if origin != "":
            span["meta"]["_dd.origin"] = origin
        if priority != "":
            span["metrics"]["_sampling_priority_v1"] = priority
        for k, v in meta.items():
            span["meta"][k] = v
        for k, v in metrics.items():
            span["metrics"][k] = v
    return spans


def _convert_v1_span(span: Any, string_table: List[str]) -> Span:
    if not isinstance(span, dict):
        raise TypeError("Span must be a map.")

    # Create a regular dict first, then cast to TypedDict
    v4Span: Dict[str, Any] = {}
    env, version, component, spanKind = "", "", "", ""

    for k, v in span.items():
        if k == V1SpanKeys.SERVICE:
            v4Span["service"] = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.NAME:
            v4Span["name"] = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.RESOURCE:
            v4Span["resource"] = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.SPAN_ID:
            v4Span["span_id"] = v
        elif k == V1SpanKeys.PARENT_ID:
            v4Span["parent_id"] = v
        elif k == V1SpanKeys.START:
            v4Span["start"] = v
        elif k == V1SpanKeys.DURATION:
            v4Span["duration"] = v
        elif k == V1SpanKeys.ERROR:
            if not isinstance(v, bool):
                raise TypeError("Error must be a boolean, got type %r." % type(v))
            v4Span["error"] = 1 if v else 0
        elif k == V1SpanKeys.ATTRIBUTES:
            if not isinstance(v, list):
                raise TypeError("Attributes must be a list, got type %r." % type(v))
            meta: Dict[str, str] = {}
            metrics: Dict[str, MetricType] = {}
            _convert_v1_attributes(v, meta, metrics, string_table)
            v4Span["meta"] = meta
            v4Span["metrics"] = metrics
        elif k == V1SpanKeys.TYPE:
            v4Span["type"] = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.SPAN_LINKS:
            if not isinstance(v, list):
                raise TypeError("Span links must be a list, got type %r." % type(v))
            links: List[SpanLink] = []
            for raw_link in v:
                link = _convert_v1_span_link(raw_link, string_table)
                links.append(link)
            v4Span["span_links"] = links
        elif k == V1SpanKeys.SPAN_EVENTS:
            if not isinstance(v, list):
                raise TypeError("Span events must be a list, got type %r." % type(v))
            events: List[SpanEvent] = []
            for raw_event in v:
                event = _convert_v1_span_event(raw_event, string_table)
                events.append(event)
            v4Span["span_events"] = events
        elif k == V1SpanKeys.ENV:
            env = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.VERSION:
            version = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.COMPONENT:
            component = _get_and_add_string(string_table, v)
        elif k == V1SpanKeys.SPAN_KIND:
            if not isinstance(v, int):
                raise TypeError("Span kind must be an integer, got type %r." % type(v))
            if v == 1:
                spanKind = "internal"
            elif v == 2:
                spanKind = "server"
            elif v == 3:
                spanKind = "client"
            elif v == 4:
                spanKind = "producer"
            elif v == 5:
                spanKind = "consumer"
            else:
                raise TypeError("Unknown span kind %r." % v)

    if "meta" not in v4Span or v4Span["meta"] is None:
        v4Span["meta"] = {}
    if env != "":
        v4Span["meta"]["env"] = env
    if version != "":
        v4Span["meta"]["version"] = version
    if component != "":
        v4Span["meta"]["component"] = component
    if spanKind != "":
        v4Span["meta"]["span.kind"] = spanKind

    # Cast to TypedDict
    return v4Span  # type: ignore


def _convert_v1_span_event(event: Any, string_table: List[str]) -> SpanEvent:
    if not isinstance(event, dict):
        raise TypeError("Span event must be a map, got type %r." % type(event))

    # Create a regular dict first, then cast to TypedDict
    v4Event: Dict[str, Any] = {}

    for k, v in event.items():
        if k == V1SpanEventKeys.TIME:
            v4Event["time_unix_nano"] = v
        elif k == V1SpanEventKeys.NAME:
            v4Event["name"] = _get_and_add_string(string_table, v)
        elif k == V1SpanEventKeys.ATTRIBUTES:
            v4Event["attributes"] = _convert_v1_span_event_attributes(v, string_table)
        else:
            raise TypeError("Unknown key %r in v1 span event" % k)

    # Cast to TypedDict
    return v4Event  # type: ignore


def _convert_v1_span_link(link: Any, string_table: List[str]) -> SpanLink:
    if not isinstance(link, dict):
        raise TypeError("Span link must be a map, got type %r." % type(link))

    # Create a regular dict first, then cast to TypedDict
    v4Link: Dict[str, Any] = {}

    for k, v in link.items():
        if k == V1SpanLinkKeys.TRACE_ID:
            if len(v) != 16:
                raise TypeError("Trace ID must be 16 bytes, got %r." % len(v))
            # trace_id is a 128 bit integer in a bytes array, so we need to get the last 64 bits
            v4Link["trace_id"] = int.from_bytes(v[8:], "big")
            v4Link["trace_id_high"] = int.from_bytes(v[:8], "big")
        elif k == V1SpanLinkKeys.SPAN_ID:
            v4Link["span_id"] = v
        elif k == V1SpanLinkKeys.ATTRIBUTES:
            v4Link["attributes"] = _convert_v1_span_link_attributes(v, string_table)
        elif k == V1SpanLinkKeys.TRACE_STATE:
            v4Link["tracestate"] = _get_and_add_string(string_table, v)
        elif k == V1SpanLinkKeys.FLAGS:
            v4Link["flags"] = v
        else:
            raise TypeError("Unknown key %r in v1 span link" % k)

    # Cast to TypedDict
    return v4Link  # type: ignore


def _convert_v1_span_link_attributes(attr: Any, string_table: List[str]) -> Dict[str, str]:
    """
    Convert a v1 span link attributes to a v4 span link attributes. Unfortunately we need multiple implementations that
    convert "attributes" as the v0.4 representation of attributes is different between span links and span events.
    """
    if not isinstance(attr, list):
        raise TypeError("Attribute must be a list, got type %r." % type(attr))
    if len(attr) % 3 != 0:
        raise TypeError("Attribute list must have a multiple of 3 elements, got %r." % len(attr))
    v4_attributes: Dict[str, str] = {}
    for i in range(0, len(attr), 3):
        key = _get_and_add_string(string_table, attr[i])
        value_type = attr[i + 1]
        value = attr[i + 2]
        if value_type == V1AnyValueKeys.STRING:
            v4_attributes[key] = _get_and_add_string(string_table, value)
        elif value_type == V1AnyValueKeys.BOOL:
            v4_attributes[key] = "true" if value else "false"
        elif value_type == V1AnyValueKeys.DOUBLE:
            v4_attributes[key] = str(value)
        elif value_type == V1AnyValueKeys.INT:
            v4_attributes[key] = str(value)
        elif value_type == V1AnyValueKeys.BYTES:
            raise NotImplementedError("Bytes values are not supported yet.")
        elif value_type == V1AnyValueKeys.ARRAY:
            raise NotImplementedError("Array of values are not supported yet.")
        elif value_type == V1AnyValueKeys.KEY_VALUE_LIST:
            raise NotImplementedError("Key value list values are not supported yet.")
        else:
            raise TypeError("Unknown attribute value type %r." % value_type)
    return v4_attributes


def _convert_v1_span_event_attributes(attr: Any, string_table: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Convert a v1 span event attributes to a v4 span event attributes. Unfortunately we need multiple implementations that
    convert "attributes" as the v0.4 representation of attributes is different between span links and span events.
    """
    if not isinstance(attr, list):
        raise TypeError("Attribute must be a list, got type %r." % type(attr))
    if len(attr) % 3 != 0:
        raise TypeError("Attribute list must have a multiple of 3 elements, got %r." % len(attr))
    attributes: Dict[str, Dict[str, Any]] = {}
    for i in range(0, len(attr), 3):
        v4_attr_value: Dict[str, Any] = {}
        key = _get_and_add_string(string_table, attr[i])
        value_type = attr[i + 1]
        value = attr[i + 2]
        if value_type == V1AnyValueKeys.STRING:
            v4_attr_value["type"] = 0
            v4_attr_value["string_value"] = _get_and_add_string(string_table, value)
        elif value_type == V1AnyValueKeys.BOOL:
            v4_attr_value["type"] = 1
            v4_attr_value["bool_value"] = value
        elif value_type == V1AnyValueKeys.DOUBLE:
            v4_attr_value["type"] = 3
            v4_attr_value["double_value"] = value
        elif value_type == V1AnyValueKeys.INT:
            v4_attr_value["type"] = 2  # Yes the constants are different here
            v4_attr_value["int_value"] = value
        elif value_type == V1AnyValueKeys.BYTES:
            raise NotImplementedError("Bytes values are not supported yet.")
        elif value_type == V1AnyValueKeys.ARRAY:
            raise NotImplementedError("Array of strings values are not supported yet.")
        elif value_type == V1AnyValueKeys.KEY_VALUE_LIST:
            raise NotImplementedError("Key value list values are not supported yet.")
        else:
            raise TypeError("Unknown attribute value type %r." % value_type)
        attributes[key] = v4_attr_value
    return attributes


def _convert_v1_attributes(
    attr: Any, meta: Dict[str, str], metrics: Dict[str, MetricType], string_table: List[str]
) -> None:
    if not isinstance(attr, list):
        raise TypeError("Attribute must be a list, got type %r." % type(attr))
    if len(attr) % 3 != 0:
        raise TypeError("Attribute list must have a multiple of 3 elements, got %r." % len(attr))
    for i in range(0, len(attr), 3):
        key = _get_and_add_string(string_table, attr[i])
        value_type = attr[i + 1]
        value = attr[i + 2]
        if value_type == V1AnyValueKeys.STRING:
            meta[key] = _get_and_add_string(string_table, value)
        elif value_type == V1AnyValueKeys.BOOL:
            # Treat v1 boolean attributes as metrics with a value of 1 or 0
            metrics[key] = 1 if value else 0
        elif value_type == V1AnyValueKeys.DOUBLE:
            metrics[key] = value
        elif value_type == V1AnyValueKeys.INT:
            metrics[key] = value
        elif value_type == V1AnyValueKeys.BYTES:
            raise NotImplementedError("Bytes values are not supported yet.")
        elif value_type == V1AnyValueKeys.ARRAY:
            raise NotImplementedError("Array of strings values are not supported yet.")
        elif value_type == V1AnyValueKeys.KEY_VALUE_LIST:
            raise NotImplementedError("Key value list values are not supported yet.")
        else:
            raise TypeError("Unknown attribute value type %r." % value_type)


def _verify_v07_payload(data: Any) -> v04TracePayload:
    if not isinstance(data, dict):
        raise TypeError("Trace payload must be a map, got type %r." % type(data))
    if "chunks" not in data:
        raise TypeError("Trace payload must contain a 'chunks' key.")
    if not isinstance(data["chunks"], list):
        raise TypeError("Trace payload 'chunks' must be a list.")
    # TODO:ban pull out the tags and other things that should be applied to all spans
    traces: List[List[Span]] = []
    for chunk in data["chunks"]:
        traces.append(_verify_v07_chunk(chunk))
    return cast(v04TracePayload, traces)


def _verify_v07_chunk(chunk: Any) -> List[Span]:
    if not isinstance(chunk, dict):
        raise TypeError("Chunk must be a map.")
    if "spans" not in chunk:
        raise TypeError("Chunk must contain a 'spans' key.")
    if not isinstance(chunk["spans"], list):
        raise TypeError("Chunk 'spans' must be a list.")
    # TODO:ban pull out the tags and other things that should be applied to all spans
    return v04_verify_trace(chunk["spans"])
