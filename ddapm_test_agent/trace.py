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
