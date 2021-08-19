import json

import msgpack
import pytest

from dd_apm_test_agent import trace


@pytest.mark.parametrize(
    "content_type, payload",
    [
        ("application/msgpack", msgpack.packb([])),
        (
            "application/msgpack",
            msgpack.packb(
                [
                    [
                        {
                            "name": "span",
                            "span_id": 1234,
                            "trace_id": 321,
                        }
                    ]
                ]
            ),
        ),
    ],
)
def test_decode_v04(content_type, payload):
    assert trace.decode_v04(content_type, payload) is not None


@pytest.mark.parametrize(
    "content_type, payload",
    [
        ("application/msgpack", msgpack.packb([{"name": "test"}])),
        ("application/json", json.dumps([{"name": "test"}])),
    ],
)
def test_decode_v04_bad(content_type, payload):
    with pytest.raises(TypeError):
        trace.decode_v04(content_type, payload)
