import json

import msgpack
import pytest

from ddapm_test_agent.trace import bfs_order
from ddapm_test_agent.trace import decode_v04
from ddapm_test_agent.trace import dfs_order
from ddapm_test_agent.trace import root_span

from .trace_utils import random_id
from .trace_utils import random_trace


def test_random_trace():
    for i in range(1, 100):
        t = random_trace(i)
        assert root_span(t)
        assert len(t) == i
        assert dfs_order(t)
        assert bfs_order(t)


def test_trace_chunk():
    trace_id = random_id()
    parent_id = random_id()
    t = random_trace(10, trace_id=trace_id, parent_id=parent_id)
    root = root_span(t)
    assert root
    assert root.get("trace_id") == trace_id
    assert root.get("parent_id") == parent_id


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
    assert decode_v04(content_type, payload) is not None


@pytest.mark.parametrize(
    "content_type, payload",
    [
        ("application/msgpack", msgpack.packb([{"name": "test"}])),
        ("application/json", json.dumps([{"name": "test"}])),
    ],
)
def test_decode_v04_bad(content_type, payload):
    with pytest.raises(TypeError):
        decode_v04(content_type, payload)


@pytest.mark.parametrize(
    "trace",
    [
        [{"name": "root"}],
        [{"name": "root", "parent_id": 0}],
        [{"name": "root", "parent_id": None}],
        [{"name": "root"}],
        [{"name": "child", "parent_id": 1234}, {"name": "root", "parent_id": None}],
    ],
)
def test_root_span(trace):
    root = root_span(trace)
    assert root["name"] == "root"
    if "parent_id" in root:
        assert root["parent_id"] in [None, 0]
    else:
        assert "parent_id" not in root


@pytest.mark.parametrize(
    "trace, expected",
    [
        (
            [{"span_id": 1, "parent_id": 0, "start": 0}],
            [{"span_id": 1, "parent_id": 0, "start": 0}],
        ),
        (
            [{"span_id": 1, "start": 0}],
            [{"span_id": 1, "start": 0}],
        ),
        (
            [
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 1, "parent_id": None, "start": 0},
            ],
            [
                {"span_id": 1, "parent_id": None, "start": 0},
                {"span_id": 2, "parent_id": 1, "start": 1},
            ],
        ),
        (
            [
                {"span_id": 4, "parent_id": 2, "start": 2},
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 5, "parent_id": 3, "start": 4},
                {"span_id": 3, "parent_id": 1, "start": 3},
                {"span_id": 1, "parent_id": 0, "start": 0},
            ],
            [
                {"span_id": 1, "parent_id": 0, "start": 0},
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 3, "parent_id": 1, "start": 3},
                {"span_id": 4, "parent_id": 2, "start": 2},
                {"span_id": 5, "parent_id": 3, "start": 4},
            ],
        ),
        (
            [
                {"span_id": 4, "parent_id": 1, "start": 1},
                {"span_id": 5, "parent_id": 1, "start": 2},
                {"span_id": 1, "parent_id": 0, "start": 0},
                {"span_id": 3, "parent_id": 1, "start": 3},
            ],
            [
                {"span_id": 1, "parent_id": 0, "start": 0},
                {"span_id": 4, "parent_id": 1, "start": 1},
                {"span_id": 5, "parent_id": 1, "start": 2},
                {"span_id": 3, "parent_id": 1, "start": 3},
            ],
        ),
    ],
)
def test_bfs_order(trace, expected):
    assert list(bfs_order(trace)) == expected


@pytest.mark.parametrize(
    "trace, expected",
    [
        (
            [{"span_id": 1, "parent_id": 0, "start": 0}],
            [{"span_id": 1, "parent_id": 0, "start": 0}],
        ),
        (
            [
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 1, "parent_id": None, "start": 0},
            ],
            [
                {"span_id": 1, "parent_id": None, "start": 0},
                {"span_id": 2, "parent_id": 1, "start": 1},
            ],
        ),
        (
            [
                {"span_id": 4, "parent_id": 2, "start": 2},
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 5, "parent_id": 3, "start": 4},
                {"span_id": 3, "parent_id": 1, "start": 3},
                {"span_id": 1, "parent_id": None, "start": 0},
            ],
            [
                {"span_id": 1, "parent_id": None, "start": 0},
                {"span_id": 2, "parent_id": 1, "start": 1},
                {"span_id": 4, "parent_id": 2, "start": 2},
                {"span_id": 3, "parent_id": 1, "start": 3},
                {"span_id": 5, "parent_id": 3, "start": 4},
            ],
        ),
    ],
)
def test_dfs_order(trace, expected):
    assert list(dfs_order(trace)) == expected
