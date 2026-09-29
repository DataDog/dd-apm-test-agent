import json

import pytest

from ddapm_test_agent.trace import V1AnyValueKeys
from ddapm_test_agent.trace import _convert_v1_attributes
from ddapm_test_agent.trace import _convert_v1_span_link_attributes


def _decode_meta(attrs, string_table=None):
    meta, metrics = {}, {}
    _convert_v1_attributes(attrs, meta, metrics, string_table if string_table is not None else [])
    return meta, metrics


def test_span_attribute_list_of_strings():
    attrs = ["tags", V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, "a", V1AnyValueKeys.STRING, "b"]]
    meta, metrics = _decode_meta(attrs)
    assert json.loads(meta["tags"]) == ["a", "b"]
    assert metrics == {}


def test_span_attribute_list_mixed_types():
    attrs = [
        "mixed",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.STRING, "x", V1AnyValueKeys.INT, 3, V1AnyValueKeys.DOUBLE, 1.5, V1AnyValueKeys.BOOL, True],
    ]
    meta, _ = _decode_meta(attrs)
    assert json.loads(meta["mixed"]) == ["x", 3, 1.5, True]


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
            [V1AnyValueKeys.INT, 1, V1AnyValueKeys.INT, 2],
        ],
    ]
    meta, _ = _decode_meta(attrs)
    assert json.loads(meta["kv"]) == {"name": "n", "inner": {"count": 2}, "items": [1, 2]}


def test_span_attribute_string_table_indices():
    string_table = ["", "key", "elem"]
    attrs = [1, V1AnyValueKeys.ARRAY, [V1AnyValueKeys.STRING, 2]]
    meta, _ = _decode_meta(attrs, string_table)
    assert json.loads(meta["key"]) == ["elem"]


def test_span_attribute_empty_containers():
    meta, _ = _decode_meta(["a", V1AnyValueKeys.ARRAY, [], "b", V1AnyValueKeys.KEY_VALUE_LIST, []])
    assert meta == {"a": "[]", "b": "{}"}


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
        _decode_meta(["k", value_type, value])


def test_span_link_attributes_containers_are_json():
    attrs = [
        "l",
        V1AnyValueKeys.ARRAY,
        [V1AnyValueKeys.STRING, "a"],
        "m",
        V1AnyValueKeys.KEY_VALUE_LIST,
        ["k", V1AnyValueKeys.BOOL, True],
    ]
    decoded = _convert_v1_span_link_attributes(attrs, [])
    assert json.loads(decoded["l"]) == ["a"]
    assert json.loads(decoded["m"]) == {"k": True}
