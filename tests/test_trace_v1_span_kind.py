import msgpack

from ddapm_test_agent.trace import V1ChunkKeys
from ddapm_test_agent.trace import V1SpanKeys
from ddapm_test_agent.trace import decode_v1


def test_v1_span_kind_unspecified():
    span = {
        V1SpanKeys.SPAN_ID: 1234,
        V1SpanKeys.SPAN_KIND: 0,  # OTEL "unspecified"; should not emit `span.kind`.
    }

    chunk = {
        V1ChunkKeys.SPANS: [span],
    }

    # Top-level `v1` trace payload key `11` contains the list of chunks.
    data = msgpack.packb({11: [chunk]})

    result = decode_v1(data)

    assert result[0][0]["span_id"] == 1234
    assert "span.kind" not in result[0][0]["meta"]
