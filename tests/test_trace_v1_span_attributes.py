import msgpack
import pytest

from ddapm_test_agent.trace import V1AnyValueKeys
from ddapm_test_agent.trace import _convert_v1_attributes
from ddapm_test_agent.trace import _convert_v1_span_link_attributes
from ddapm_test_agent.trace import decode_v1


def _decode(attrs, string_table=None):
    meta, metrics, meta_struct = {}, {}, {}
    _convert_v1_attributes(attrs, meta, metrics, string_table if string_table is not None else [], meta_struct)
    return meta, metrics, meta_struct


def test_span_attribute_list_of_strings_is_flattened_into_meta():
    attrs = ["array_val_str", V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, "val1", V1AnyValueKeys.STRING, "val2"]]
    meta, metrics, _ = _decode(attrs)
    assert meta == {"array_val_str.0": "val1", "array_val_str.1": "val2"}
    assert metrics == {}


def test_span_attribute_list_of_numbers_is_flattened_into_metrics():
    attrs = [
        "ints",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.INT, 10, V1AnyValueKeys.INT, 20],
        "doubles",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.DOUBLE, 10.1, V1AnyValueKeys.DOUBLE, 20.2],
    ]
    meta, metrics, _ = _decode(attrs)
    assert meta == {}
    assert metrics == {"ints.0": 10, "ints.1": 20, "doubles.0": 10.1, "doubles.1": 20.2}


def test_span_attribute_list_of_bools_is_flattened_into_metrics():
    attrs = ["bools", V1AnyValueKeys.ARRAY, [V1AnyValueKeys.BOOL, True, V1AnyValueKeys.BOOL, False]]
    meta, metrics, _ = _decode(attrs)
    assert meta == {}
    assert metrics == {"bools.0": 1, "bools.1": 0}


def test_span_attribute_list_mixed_types():
    attrs = [
        "mixed",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.STRING, "x", V1AnyValueKeys.INT, 3, V1AnyValueKeys.DOUBLE, 1.5],
    ]
    meta, metrics, _ = _decode(attrs)
    assert meta == {"mixed.0": "x"}
    assert metrics == {"mixed.1": 3, "mixed.2": 1.5}


def test_span_attribute_key_value_nested():
    attrs = [
        "kv",
        V1AnyValueKeys.KEY_VALUE_LIST,
        [
            "name",
            V1AnyValueKeys.STRING,
            "n",
            "inner",
            V1AnyValueKeys.KEY_VALUE_LIST,
            ["count", V1AnyValueKeys.INT, 2],
            "items",
            V1AnyValueKeys.ARRAY,
            [V1AnyValueKeys.INT, 1, V1AnyValueKeys.STRING, "b"],
        ],
    ]
    meta, metrics, _ = _decode(attrs)
    assert meta == {"kv.name": "n", "kv.items.1": "b"}
    assert metrics == {"kv.inner.count": 2, "kv.items.0": 1}


def test_span_attribute_string_table_indices():
    string_table = ["", "key", "elem"]
    attrs = [1, V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, 2]]
    meta, _, _ = _decode(attrs, string_table)
    assert meta == {"key.0": "elem"}


def test_span_attribute_empty_containers_emit_nothing():
    meta, metrics, _ = _decode(["a", V1AnyValueKeys.ARRAY, [], "b", V1AnyValueKeys.KEY_VALUE_LIST, []])
    assert meta == {} and metrics == {}


def test_streaming_string_table_follows_libdatadog_write_order():
    # libdatadog interns keys and string values in write order: first occurrence is the string,
    # later occurrences are the table index (key, then type, then value, depth first).
    attrs = [
        "outer",  # idx 0
        V1AnyValueKeys.KEY_VALUE_LIST,
        [
            "inner",  # idx 1
            V1AnyValueKeys.ARRAY,
            [V1AnyValueKeys.STRING, "v", V1AnyValueKeys.STRING, 2],  # "v" idx 2, then reference to it
            0,  # reference to "outer"
            V1AnyValueKeys.STRING,
            1,  # reference to "inner"
        ],
    ]
    meta, _, _ = _decode(attrs)
    assert meta == {"outer.inner.0": "v", "outer.inner.1": "v", "outer.outer": "inner"}


@pytest.mark.parametrize(
    "value_type,value",
    [
        (V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING]),
        (V1AnyValueKeys.ARRAY, "nope"),
        (V1AnyValueKeys.KEY_VALUE_LIST, ["k", V1AnyValueKeys.STRING]),
        (V1AnyValueKeys.KEY_VALUE_LIST, "nope"),
    ],
)
def test_span_attribute_malformed_containers(value_type, value):
    with pytest.raises(TypeError):
        _decode(["k", value_type, value])


def test_span_attribute_bytes_ascii_goes_to_meta():
    meta, _, meta_struct = _decode(["b", V1AnyValueKeys.BYTES, b"HELLO"])
    assert meta == {"b": "HELLO"}
    assert meta_struct == {}


def test_span_attribute_bytes_msgpack_goes_to_meta_struct():
    meta, _, meta_struct = _decode(["b", V1AnyValueKeys.BYTES, msgpack.packb({"a": 1, "b": [1, 2]})])
    assert meta == {}
    assert meta_struct == {"b": {"a": 1, "b": [1, 2]}}


def test_span_attribute_bytes_not_ascii_nor_msgpack_is_rejected():
    with pytest.raises(ValueError):
        _decode(["b", V1AnyValueKeys.BYTES, b"\xff\xfe\xfd\xfc"])


def test_span_attribute_bytes_rejects_non_bytes():
    with pytest.raises(TypeError):
        _decode(["b", V1AnyValueKeys.BYTES, "str"])


def test_span_attribute_bytes_nested_in_list_is_flattened():
    attrs = ["l", V1AnyValueKeys.ARRAY, [V1AnyValueKeys.BYTES, b"HELLO"]]
    meta, _, _ = _decode(attrs)
    assert meta == {"l.0": "HELLO"}


def test_span_link_attributes_flattened_with_string_leaves():
    attrs = [
        "l",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.STRING, "a", V1AnyValueKeys.INT, 2, V1AnyValueKeys.BOOL, True],
        "m",
        V1AnyValueKeys.KEY_VALUE_LIST,
        ["k", V1AnyValueKeys.DOUBLE, 1.5, "n", V1AnyValueKeys.KEY_VALUE_LIST, ["b", V1AnyValueKeys.BOOL, False]],
    ]
    assert _convert_v1_span_link_attributes(attrs, []) == {
        "l.0": "a",
        "l.1": "2",
        "l.2": "true",
        "m.k": "1.5",
        "m.n.b": "false",
    }


def test_span_link_attributes_bytes_ascii():
    assert _convert_v1_span_link_attributes(["b", V1AnyValueKeys.BYTES, b"hi"], []) == {"b": "hi"}


def _payload(span_attributes=None, chunk_attributes=None, payload_attributes=None):
    span = {1: "svc", 2: "name", 3: "res", 4: 1, 5: 0, 6: 1, 7: 2, 8: False}
    if span_attributes is not None:
        span[9] = span_attributes
    chunk = {1: 0, 3: [], 4: [span], 6: bytes(16)}
    if chunk_attributes is not None:
        chunk[3] = chunk_attributes
    payload = {11: [chunk]}
    if payload_attributes is not None:
        payload[10] = payload_attributes
    return msgpack.packb(payload)


def test_decode_v1_places_bytes_and_flattened_attributes_on_the_span():
    data = _payload(
        span_attributes=[
            "ms",
            V1AnyValueKeys.BYTES,
            msgpack.packb({"x": 1}),
            "tags",
            V1AnyValueKeys.ARRAY,
            [V1AnyValueKeys.STRING, "a"],
        ]
    )
    span = decode_v1(data)[0][0]
    assert span["meta_struct"] == {"ms": {"x": 1}}
    assert span["meta"]["tags.0"] == "a"


def test_decode_v1_chunk_and_payload_level_bytes_reach_spans():
    data = _payload(
        chunk_attributes=["c", V1AnyValueKeys.BYTES, msgpack.packb({"c": 1})],
        payload_attributes=["p", V1AnyValueKeys.BYTES, msgpack.packb({"p": 1})],
    )
    span = decode_v1(data)[0][0]
    assert span["meta_struct"] == {"c": {"c": 1}, "p": {"p": 1}}


def test_span_attribute_bytes_single_ascii_byte_is_not_read_as_msgpack_int():
    meta, _, meta_struct = _decode(["b", V1AnyValueKeys.BYTES, b"A"])
    assert meta == {"b": "A"} and meta_struct == {}
