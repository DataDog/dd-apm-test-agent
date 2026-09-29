import json

import msgpack
import pytest

from ddapm_test_agent.trace import V1AnyValueKeys
from ddapm_test_agent.trace import V1ChunkKeys
from ddapm_test_agent.trace import V1SpanEventKeys
from ddapm_test_agent.trace import V1SpanKeys
from ddapm_test_agent.trace import V1SpanLinkKeys
from ddapm_test_agent.trace import decode_v1


TRACE_ID = bytes([0x00] * 15 + [0x01])
S, B, D, I, BY, A, KV = (
    V1AnyValueKeys.STRING,
    V1AnyValueKeys.BOOL,
    V1AnyValueKeys.DOUBLE,
    V1AnyValueKeys.INT,
    V1AnyValueKeys.BYTES,
    V1AnyValueKeys.ARRAY,
    V1AnyValueKeys.KEY_VALUE_LIST,
)


def _span(span_id=1, parent_id=0, attributes=None, extra=None):
    span = {
        V1SpanKeys.SERVICE: "svc",
        V1SpanKeys.NAME: "op",
        V1SpanKeys.SPAN_ID: span_id,
        V1SpanKeys.PARENT_ID: parent_id,
    }
    if attributes is not None:
        span[V1SpanKeys.ATTRIBUTES] = attributes
    span.update(extra or {})
    return span


def _decode(spans, chunk_fields=None, payload_attributes=None):
    chunk = {V1ChunkKeys.TRACE_ID: TRACE_ID, V1ChunkKeys.SPANS: spans}
    chunk.update(chunk_fields or {})
    payload = {11: [chunk]}
    if payload_attributes is not None:
        payload[10] = payload_attributes
    return decode_v1(msgpack.packb(payload))


def _decode_span(attributes):
    return _decode([_span(attributes=attributes)])[0][0]


def test_v1_span_array_attributes_are_flattened_by_element_type():
    span = _decode_span(
        [
            "array_val_str", A, [S, "val1", S, "val2"],
            "array_val_int", A, [I, 10, I, 20],
            "array_val_bool", A, [B, True, B, False],
            "array_val_double", A, [D, 10.1, D, 20.2],
        ]
    )  # fmt: skip
    assert span["meta"]["array_val_str.0"] == "val1"
    assert span["meta"]["array_val_str.1"] == "val2"
    assert span["metrics"]["array_val_int.0"] == 10
    assert span["metrics"]["array_val_int.1"] == 20
    assert span["metrics"]["array_val_bool.0"] == 1
    assert span["metrics"]["array_val_bool.1"] == 0
    assert span["metrics"]["array_val_double.0"] == 10.1
    assert span["metrics"]["array_val_double.1"] == 20.2
    for key in ("array_val_str", "array_val_int", "array_val_bool", "array_val_double"):
        assert key not in span["meta"] and key not in span["metrics"]


def test_v1_span_nested_array_attribute():
    span = _decode_span(["nested_str_array", A, [A, [S, "a", S, "b"], A, [S, "c", S, "d"]]])
    assert span["meta"] == {
        "nested_str_array.0.0": "a",
        "nested_str_array.0.1": "b",
        "nested_str_array.1.0": "c",
        "nested_str_array.1.1": "d",
    }


def test_v1_span_heterogeneous_and_empty_arrays():
    span = _decode_span(["mixed", A, [S, "ok", I, 7, D, 2.5, B, True], "empty", A, []])
    assert span["meta"] == {"mixed.0": "ok"}
    assert span["metrics"] == {"mixed.1": 7, "mixed.2": 2.5, "mixed.3": 1}


def test_v1_span_key_value_list_attribute():
    span = _decode_span(
        ["http", KV, ["method", S, "GET", "status", I, 200, "headers", KV, ["accept", A, [S, "a/b", S, "c/d"]]]]
    )
    assert span["meta"] == {"http.method": "GET", "http.headers.accept.0": "a/b", "http.headers.accept.1": "c/d"}
    assert span["metrics"] == {"http.status": 200}


def test_v1_span_array_attribute_resolves_string_table_indexes():
    # Strings inside arrays and key-value lists are streamed through the string table in wire order:
    # "svc"(1) "op"(2) "tags"(3) "x"(4) "kv"(5) "k"(6) "y"(7); the second span only uses indexes.
    first = _span(span_id=1, attributes=["tags", A, [S, "x"], "kv", KV, ["k", S, "y"]])
    second = {
        V1SpanKeys.SERVICE: 1,
        V1SpanKeys.NAME: 2,
        V1SpanKeys.SPAN_ID: 2,
        V1SpanKeys.PARENT_ID: 1,
        V1SpanKeys.ATTRIBUTES: [3, A, [S, 4], 5, KV, [6, S, 7]],
    }
    trace = _decode([first, second])[0]
    for span in trace:
        assert span["service"] == "svc"
        assert span["meta"] == {"tags.0": "x", "kv.k": "y"}


def test_v1_span_bytes_attribute_goes_to_meta_struct():
    span = _decode_span(
        ["_dd.stack", BY, msgpack.packb({"exploit": [{"frames": []}]}), "raw", BY, b"not msgpack \xff\xfe"]
    )
    assert span["meta_struct"]["_dd.stack"] == {"exploit": [{"frames": []}]}
    assert span["meta_struct"]["raw"] == "not msgpack ��"
    assert "_dd.stack" not in span["meta"]


def test_v1_span_without_bytes_attribute_has_no_meta_struct():
    assert "meta_struct" not in _decode_span(["k", S, "v"])


def test_v1_chunk_array_attribute_applies_to_every_span():
    trace = _decode(
        [_span(span_id=1), _span(span_id=2, parent_id=1)],
        chunk_fields={V1ChunkKeys.ATTRIBUTES: ["chunk_list", A, [S, "a", I, 1], "blob", BY, msgpack.packb({"k": 1})]},
    )[0]
    for span in trace:
        assert span["meta"]["chunk_list.0"] == "a"
        assert span["metrics"]["chunk_list.1"] == 1
        assert span["meta_struct"]["blob"] == {"k": 1}


def test_v1_payload_array_attribute_applies_to_every_span():
    trace = _decode(
        [_span(span_id=1), _span(span_id=2, parent_id=1)], payload_attributes=["payload_list", A, [S, "a", S, "b"]]
    )[0]
    for span in trace:
        assert span["meta"]["payload_list.0"] == "a"
        assert span["meta"]["payload_list.1"] == "b"


def test_v1_payload_git_metadata_only_on_local_root():
    # The child is serialized first, so the local root is not the first span of the chunk.
    trace = _decode(
        [_span(span_id=2, parent_id=1), _span(span_id=1, parent_id=0)],
        payload_attributes=[
            "_dd.git.commit.sha", S, "abc123",
            "_dd.git.repository_url", S, "https://github.com/DataDog/repo",
            "_dd.tags.process", S, "entrypoint.name:php",
            "_dd.apm_mode", S, "on",
        ],
    )[0]  # fmt: skip
    child, root = trace
    assert root["meta"]["_dd.git.commit.sha"] == "abc123"
    assert root["meta"]["_dd.git.repository_url"] == "https://github.com/DataDog/repo"
    assert "_dd.git.commit.sha" not in child["meta"]
    assert "_dd.git.repository_url" not in child["meta"]
    # Process tags go on the first span of the chunk, other payload attributes on every span.
    assert child["meta"]["_dd.tags.process"] == "entrypoint.name:php"
    assert "_dd.tags.process" not in root["meta"]
    assert child["meta"]["_dd.apm_mode"] == root["meta"]["_dd.apm_mode"] == "on"


def test_v1_payload_git_metadata_with_remote_parent():
    # A chunk whose root has a remote parent: the local root is the span whose parent is not in the chunk.
    trace = _decode(
        [_span(span_id=10, parent_id=99), _span(span_id=11, parent_id=10)],
        payload_attributes=["_dd.git.commit.sha", S, "abc123"],
    )[0]
    assert trace[0]["meta"]["_dd.git.commit.sha"] == "abc123"
    assert "_dd.git.commit.sha" not in trace[1]["meta"]


def test_v1_span_link_array_attributes_are_flattened():
    link = {
        V1SpanLinkKeys.TRACE_ID: TRACE_ID,
        V1SpanLinkKeys.SPAN_ID: 5,
        V1SpanLinkKeys.ATTRIBUTES: [
            "foo", S, "bar",
            "array", A, [S, "a", S, "b", S, "c"],
            "bools", A, [B, True, B, False],
            "nested", A, [I, 1, I, 2],
            "kv", KV, ["x", D, 1.5],
            "raw", BY, b"text",
        ],
    }  # fmt: skip
    span = _decode([_span(extra={V1SpanKeys.SPAN_LINKS: [link]})])[0][0]
    assert span["span_links"][0]["attributes"] == {
        "foo": "bar",
        "array.0": "a",
        "array.1": "b",
        "array.2": "c",
        "bools.0": "true",
        "bools.1": "false",
        "nested.0": "1",
        "nested.1": "2",
        "kv.x": "1.5",
        "raw": "text",
    }


def test_v1_span_event_key_value_list_and_bytes_attributes():
    event = {
        V1SpanEventKeys.TIME: 1,
        V1SpanEventKeys.NAME: "event",
        V1SpanEventKeys.ATTRIBUTES: ["exception", KV, ["type", S, "E", "lines", A, [I, 1, I, 2]], "raw", BY, b"x"],
    }
    span = _decode([_span(extra={V1SpanKeys.SPAN_EVENTS: [event]})])[0][0]
    assert span["span_events"][0]["attributes"] == {
        "exception.type": {"type": 0, "string_value": "E"},
        "exception.lines": {
            "type": 4,
            "array_value": {"values": [{"type": 2, "int_value": 1}, {"type": 2, "int_value": 2}]},
        },
        "raw": {"type": 0, "string_value": "x"},
    }


@pytest.mark.parametrize(
    "attributes, message",
    [
        (["k", A, [S]], "multiple of 2"),
        (["k", A, "nope"], "must be a list"),
        (["k", KV, ["a", S]], "multiple of 3"),
        (["k", A, [99, 1]], "Unknown attribute value type"),
    ],
)
def test_v1_malformed_nested_attribute_values(attributes, message):
    with pytest.raises(TypeError, match=message):
        _decode_span(attributes)


async def test_v1_session_traces_with_array_attributes(agent, v04_reference_http_trace_payload_headers):
    # Regression: a span ARRAY attribute used to raise NotImplementedError, so every
    # /test/session/traces call for the session failed with HTTP 400.
    payload = {
        11: [
            {
                V1ChunkKeys.TRACE_ID: TRACE_ID,
                V1ChunkKeys.SPANS: [_span(attributes=["process.command_args", A, [S, "server.php", S, "x"]])],
            }
        ]
    }
    resp = await agent.put(
        "/v1.0/traces", headers=v04_reference_http_trace_payload_headers, data=msgpack.packb(payload)
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/traces")
    assert resp.status == 200, await resp.text()
    traces = json.loads(await resp.text())
    span = traces[0][0]
    assert span["meta"]["process.command_args.0"] == "server.php"
    assert span["meta"]["process.command_args.1"] == "x"
