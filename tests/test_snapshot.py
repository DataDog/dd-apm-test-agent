import os

import pytest

from ddapm_test_agent.snapshot import generate_snapshot
from ddapm_test_agent.trace import copy_span
from ddapm_test_agent.trace import set_attr
from ddapm_test_agent.trace import set_meta_tag
from ddapm_test_agent.trace import set_metric_tag

from .conftest import v04_trace
from .trace_utils import random_trace


@pytest.mark.parametrize("snapshot_ci_mode", [False, True])
async def test_snapshot_single_trace(
    agent,
    snapshot_dir,
    snapshot_ci_mode,
    do_reference_v04_http_trace,
):
    """
    When a trace is sent and a snapshot taken
        When not in CI mode
            The test should fail
        When in CI mode
            The snapshot file should be created
            When the same trace is sent again
                The snapshot should pass
    """  # noqa: RST301
    # Send a trace
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    # Do the snapshot
    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test_case"}
    )
    snap_path = snapshot_dir / "test_case.json"
    if snapshot_ci_mode:
        # No previous snapshot file exists so this should fail
        assert resp.status == 400, await resp.text()
        assert f"Snapshot file '{snap_path}' not found" in await resp.text()
    else:
        # Since this is the first invocation the snapshot file should be created
        assert resp.status == 200, await resp.text()
        assert os.path.exists(snap_path)
        with open(snap_path, mode="r") as f:
            assert "".join(f.readlines()) != ""

        # Do the snapshot again to actually perform a comparison
        resp = await do_reference_v04_http_trace(token="test_case")
        assert resp.status == 200, await resp.text()

        resp = await agent.get(
            "/test/session/snapshot", params={"test_session_token": "test_case"}
        )
        assert resp.status == 200, await resp.text()


ONE_SPAN_TRACE = random_trace(1)
TWO_SPAN_TRACE = random_trace(2)
FIVE_SPAN_TRACE = random_trace(5)


@pytest.mark.parametrize(
    "expected_traces,actual_traces,error",
    [
        ([ONE_SPAN_TRACE], [ONE_SPAN_TRACE], ""),
        ([FIVE_SPAN_TRACE], [FIVE_SPAN_TRACE], ""),
        # Mismatching trace sizes
        (
            [TWO_SPAN_TRACE],
            [TWO_SPAN_TRACE[:-1]],
            "Number of traces received (1) doesn't match expected (2).",
        ),
        (
            [TWO_SPAN_TRACE[:-1]],
            [TWO_SPAN_TRACE],
            "Number of traces received (2) doesn't match expected (1).",
        ),
        (
            [[set_attr(copy_span(ONE_SPAN_TRACE[0]), "name", "name_expected")]],
            [[set_attr(copy_span(ONE_SPAN_TRACE[0]), "name", "name_received")]],
            "span mismatch on 'name': got 'name_received' which does not match expected 'name_expected'",
        ),
        (
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_attr(copy_span(TWO_SPAN_TRACE[1]), "name", "name_expected"),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_attr(copy_span(TWO_SPAN_TRACE[1]), "name", "name_received"),
                ]
            ],
            "span mismatch on 'name': got 'name_received' which does not match expected 'name_expected'",
        ),
        (
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_meta_tag(copy_span(TWO_SPAN_TRACE[1]), "expected", "value"),
                ]
            ],
            [[TWO_SPAN_TRACE[0], TWO_SPAN_TRACE[1]]],
            "Span meta value 'expected' in expected span but is not in the received span.",
        ),
        (
            [[TWO_SPAN_TRACE[0], TWO_SPAN_TRACE[1]]],
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE[1]), "received", 123.32),
                ]
            ],
            "Span metrics value 'received' in received span but is not in the expected span.",
        ),
        # Mismatching metrics tag
        (
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE[1]), "received", 123.32),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE[1]), "received", 123.32),
                ]
            ],
            "",
        ),
        # Default ignored fields
        (
            [
                [
                    {
                        "name": "s",
                        "span_id": 1234,
                        "trace_id": 1,
                        "parent_id": 0,
                        "resource": "/",
                        "start": 0,
                        "duration": 1,
                        "type": "web",
                        "error": 0,
                        "meta": {},
                        "metrics": {},
                    }
                ]
            ],
            [
                [
                    {
                        "name": "s",
                        "span_id": 4321,
                        "trace_id": 2,
                        "parent_id": 0,
                        "resource": "/",
                        "start": 0,
                        "duration": 1,
                        "type": "web",
                        "error": 0,
                        "meta": {},
                        "metrics": {},
                    }
                ]
            ],
            "",
        ),
    ],
)
async def test_snapshot_trace_differences(agent, expected_traces, actual_traces, error):
    resp = await v04_trace(agent, expected_traces, token="test")
    assert resp.status == 200, await resp.text()

    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test"}
    )
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/clear", params={"test_session_token": "test"})
    assert resp.status == 200, await resp.text()

    resp = await v04_trace(agent, actual_traces, token="test")
    assert resp.status == 200, await resp.text()
    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test"}
    )
    resp_text = await resp.text()
    if error:
        assert resp.status == 400, resp_text
        assert error in resp_text, resp_text
    else:
        assert resp.status == 200, resp_text


@pytest.mark.parametrize(
    "trace,expected",
    [
        (
            [
                [
                    {"parent_id": 0, "span_id": 1, "start": 0},
                    {"parent_id": 1, "span_id": 2, "start": 1},
                    {"parent_id": 1, "span_id": 3, "start": 2},
                    {"parent_id": 2, "span_id": 4, "start": 4},
                ]
            ],
            """[[
  {
    "meta": {},
    "metrics": {},
    "parent_id": 0,
    "span_id": 1,
    "start": 0,
    "trace_id": 0
  },
     {
       "meta": {},
       "metrics": {},
       "parent_id": 1,
       "span_id": 2,
       "start": 1,
       "trace_id": 0
     },
        {
          "meta": {},
          "metrics": {},
          "parent_id": 2,
          "span_id": 4,
          "start": 4,
          "trace_id": 0
        },
     {
       "meta": {},
       "metrics": {},
       "parent_id": 1,
       "span_id": 3,
       "start": 2,
       "trace_id": 0
     }]]\n""",
        )
    ],
)
def test_generate_snapshot(trace, expected):
    assert generate_snapshot(trace) == expected


async def test_snapshot_custom_dir(agent, tmp_path, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()

    resp = await agent.get(
        "/test/session/snapshot",
        params={"test_session_token": "test_case", "dir": str(custom_dir)},
    )
    snap_path = custom_dir / "test_case.json"
    assert resp.status == 200, await resp.text()
    assert os.path.exists(snap_path)
    with open(snap_path, mode="r") as f:
        assert "".join(f.readlines()) != ""


async def test_snapshot_custom_file(agent, tmp_path, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    custom_file = custom_dir / "custom_snapshot.json"

    resp = await agent.get(
        "/test/session/snapshot",
        params={"test_session_token": "test_case", "file": str(custom_file)},
    )
    assert resp.status == 200, await resp.text()
    assert os.path.exists(custom_file), custom_file
    with open(custom_file, mode="r") as f:
        assert "".join(f.readlines()) != ""
