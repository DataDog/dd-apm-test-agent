import msgpack

from ddapm_test_agent.trace import V1AnyValueKeys
from ddapm_test_agent.trace import V1ChunkKeys
from ddapm_test_agent.trace import V1SpanKeys
from ddapm_test_agent.trace import decode_v1


def test_v1_boolean_span_attributes_are_projected_as_meta_strings():
    span = {
        V1SpanKeys.SPAN_ID: 1234,
        V1SpanKeys.ATTRIBUTES: [
            "true_attr",
            V1AnyValueKeys.BOOL,
            True,
            "false_attr",
            V1AnyValueKeys.BOOL,
            False,
            "int_attr",
            V1AnyValueKeys.INT,
            7,
            "double_attr",
            V1AnyValueKeys.DOUBLE,
            1.5,
        ],
    }
    chunk = {V1ChunkKeys.SPANS: [span]}

    result = decode_v1(msgpack.packb({11: [chunk]}))
    decoded_span = result[0][0]

    assert decoded_span["meta"] == {"true_attr": "true", "false_attr": "false"}
    assert decoded_span["metrics"] == {"int_attr": 7, "double_attr": 1.5}
