import msgpack
import pytest

from ddapm_test_agent.trace import V1AnyValueKeys
from ddapm_test_agent.trace import V1ChunkKeys
from ddapm_test_agent.trace import V1SpanEventKeys
from ddapm_test_agent.trace import V1SpanKeys
from ddapm_test_agent.trace import _convert_v1_array_value
from ddapm_test_agent.trace import decode_v1


def _decode_single_event_attributes(attributes):
    """Decode a minimal v1 payload carrying one span event with the given (wire-encoded)
    attribute triplet list, and return the decoded v0.4 attributes of that event.

    A v1 span event attribute is a flat ``(key, type, value)`` triplet stream; an ARRAY value is a
    flat ``[item_type, item_value, ...]`` list.
    """
    event = {
        V1SpanEventKeys.TIME: 1,
        V1SpanEventKeys.NAME: "event",
        V1SpanEventKeys.ATTRIBUTES: attributes,
    }
    span = {V1SpanKeys.SPAN_ID: 1234, V1SpanKeys.SPAN_EVENTS: [event]}
    chunk = {V1ChunkKeys.SPANS: [span]}
    # Top-level v1 trace payload key `11` contains the list of chunks.
    result = decode_v1(msgpack.packb({11: [chunk]}))
    return result[0][0]["span_events"][0]["attributes"]


def test_v1_span_event_string_array_attribute():
    attrs = ["tags", V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, "checkout", V1AnyValueKeys.STRING, "payment"]]
    assert _decode_single_event_attributes(attrs) == {
        "tags": {
            "type": 4,
            "array_value": {
                "values": [
                    {"type": 0, "string_value": "checkout"},
                    {"type": 0, "string_value": "payment"},
                ]
            },
        }
    }


def test_v1_span_event_empty_array_attribute():
    attrs = ["tags", V1AnyValueKeys.ARRAY, []]
    assert _decode_single_event_attributes(attrs) == {"tags": {"type": 4, "array_value": {"values": []}}}


def test_v1_span_event_mixed_scalar_and_array_attributes():
    attrs = [
        "message",
        V1AnyValueKeys.STRING,
        "hello",
        "http.status_code",
        V1AnyValueKeys.INT,
        200,
        "retry_delays_ms",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.INT, 100, V1AnyValueKeys.INT, 200],
    ]
    decoded = _decode_single_event_attributes(attrs)
    assert decoded["message"] == {"type": 0, "string_value": "hello"}
    assert decoded["http.status_code"] == {"type": 2, "int_value": 200}
    assert decoded["retry_delays_ms"] == {
        "type": 4,
        "array_value": {"values": [{"type": 2, "int_value": 100}, {"type": 2, "int_value": 200}]},
    }


@pytest.mark.parametrize(
    "item_type, item_value, expected",
    [
        (V1AnyValueKeys.STRING, "ok", {"type": 0, "string_value": "ok"}),
        (V1AnyValueKeys.BOOL, True, {"type": 1, "bool_value": True}),
        (V1AnyValueKeys.BOOL, False, {"type": 1, "bool_value": False}),
        (V1AnyValueKeys.INT, 5, {"type": 2, "int_value": 5}),
        (V1AnyValueKeys.DOUBLE, 1.5, {"type": 3, "double_value": 1.5}),
    ],
)
def test_v1_span_event_array_item_types(item_type, item_value, expected):
    attrs = ["items", V1AnyValueKeys.ARRAY, [item_type, item_value]]
    assert _decode_single_event_attributes(attrs)["items"]["array_value"]["values"] == [expected]


def test_v1_span_event_heterogeneous_array_attribute():
    # v1 array attributes derive from OTLP ArrayValue and may mix element types,
    # for example: ["ok", 7, 2.5, false].
    # The decoder accepts them on purpose; it does not enforce the single-type rule
    # that v0.4 verify_span applies.
    attrs = [
        "mixed_values",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.STRING, "ok", V1AnyValueKeys.INT, 7, V1AnyValueKeys.DOUBLE, 2.5, V1AnyValueKeys.BOOL, False],
    ]
    assert _decode_single_event_attributes(attrs)["mixed_values"]["array_value"]["values"] == [
        {"type": 0, "string_value": "ok"},
        {"type": 2, "int_value": 7},
        {"type": 3, "double_value": 2.5},
        {"type": 1, "bool_value": False},
    ]


def test_v1_span_event_array_attribute_resolves_string_table_indexes():
    # End-to-end streaming-string check: the attribute key and a string array item arrive as
    # indexes into the string table rather than inline strings. Payload keys 2-9 seed the table
    # (index 1 -> "tags", index 2 -> "checkout") before the chunks (key 11) are decoded.
    event = {
        V1SpanEventKeys.TIME: 1,
        V1SpanEventKeys.ATTRIBUTES: [1, V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, 2]],
    }
    span = {V1SpanKeys.SPAN_ID: 1234, V1SpanKeys.SPAN_EVENTS: [event]}
    # Top-level v1 trace payload key `11` contains the list of chunks.
    payload = msgpack.packb({2: "tags", 3: "checkout", 11: [{V1ChunkKeys.SPANS: [span]}]})

    result = decode_v1(payload)

    assert result[0][0]["span_events"][0]["attributes"] == {
        "tags": {"type": 4, "array_value": {"values": [{"type": 0, "string_value": "checkout"}]}}
    }


def test_convert_v1_array_value_resolves_string_table_index():
    # String items may arrive as an index into the streaming string table rather than inline.
    string_table = ["", "indexed"]
    assert _convert_v1_array_value([V1AnyValueKeys.STRING, 1], string_table) == {
        "values": [{"type": 0, "string_value": "indexed"}]
    }


def test_convert_v1_array_value_rejects_non_list():
    with pytest.raises(TypeError):
        _convert_v1_array_value("not a list", [""])


def test_convert_v1_array_value_rejects_odd_length():
    with pytest.raises(TypeError):
        _convert_v1_array_value([V1AnyValueKeys.INT], [""])


def test_convert_v1_array_value_rejects_unknown_item_type():
    with pytest.raises(TypeError):
        _convert_v1_array_value([V1AnyValueKeys.KEY_VALUE_LIST, 0], [""])
