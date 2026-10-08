import base64
import json
import os
import re

import pytest

from ddapm_test_agent import fmt
from ddapm_test_agent import otlp_trace_snapshot
from ddapm_test_agent import trace_snapshot
from ddapm_test_agent import tracestats_snapshot
from ddapm_test_agent.checks import start_trace
from ddapm_test_agent.trace import add_span_event
from ddapm_test_agent.trace import add_span_link
from ddapm_test_agent.trace import copy_span
from ddapm_test_agent.trace import set_attr
from ddapm_test_agent.trace import set_meta_tag
from ddapm_test_agent.trace import set_metric_tag
from ddapm_test_agent.tracestats import StatsAggr
from ddapm_test_agent.tracestats import StatsBucket

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
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_case"})
    snap_path = snapshot_dir / "test_case.json"
    if snapshot_ci_mode:
        # No previous snapshot file exists so this should fail
        assert resp.status == 400, await resp.text()
        assert f"Trace snapshot file '{snap_path}' not found" in await resp.text()
    else:
        # Since this is the first invocation the snapshot file should be created
        assert resp.status == 200, await resp.text()
        assert os.path.exists(snap_path)
        with open(snap_path, mode="r") as f:
            assert "".join(f.readlines()) != ""

        # Do the snapshot again to actually perform a comparison
        resp = await do_reference_v04_http_trace(token="test_case")
        assert resp.status == 200, await resp.text()

        resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_case"})
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
            "Received fewer spans (1) than expected (2). Expected unmatched spans: 'postgres.query'",
        ),
        (
            [TWO_SPAN_TRACE[:-1]],
            [TWO_SPAN_TRACE],
            "Received more spans (2) than expected (1). Received unmatched spans: 'postgres.query'",
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

    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test"})
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/clear", params={"test_session_token": "test"})
    assert resp.status == 200, await resp.text()

    resp = await v04_trace(agent, actual_traces, token="test")
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test"})
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
                    {"trace_id": 1, "span_id": 1, "start": 0},
                    {"trace_id": 1, "parent_id": 1, "span_id": 2, "start": 1},
                    {"trace_id": 1, "parent_id": 1, "span_id": 3, "start": 2},
                    {"trace_id": 1, "parent_id": 2, "span_id": 4, "start": 4},
                ]
            ],
            """[[
  {
    "trace_id": 0,
    "span_id": 1,
    "parent_id": 0,
    "start": 0
  },
     {
       "trace_id": 0,
       "span_id": 2,
       "parent_id": 1,
       "start": 1
     },
        {
          "trace_id": 0,
          "span_id": 4,
          "parent_id": 2,
          "start": 4
        },
     {
       "trace_id": 0,
       "span_id": 3,
       "parent_id": 1,
       "start": 2
     }]]\n""",
        ),
        (
            [
                [
                    {"trace_id": 1, "parent_id": None, "span_id": 1, "start": 0},
                    {"trace_id": 1, "parent_id": 1, "span_id": 2, "start": 1},
                    {"trace_id": 1, "parent_id": 1, "span_id": 3, "start": 2},
                    {"trace_id": 1, "parent_id": 2, "span_id": 4, "start": 4},
                ]
            ],
            """[[
  {
    "trace_id": 0,
    "span_id": 1,
    "parent_id": 0,
    "start": 0
  },
     {
       "trace_id": 0,
       "span_id": 2,
       "parent_id": 1,
       "start": 1
     },
        {
          "trace_id": 0,
          "span_id": 4,
          "parent_id": 2,
          "start": 4
        },
     {
       "trace_id": 0,
       "span_id": 3,
       "parent_id": 1,
       "start": 2
     }]]\n""",
        ),
    ],
)
def test_generate_trace_snapshot(trace, expected):
    assert trace_snapshot.generate_snapshot(trace) == expected


@pytest.mark.parametrize(
    "buckets,expected",
    [
        (
            [
                StatsBucket(  # noqa
                    Start=1000,
                    Duration=10,
                    Stats=[
                        # Not using all the fields of StatsAggr, hence the ignores
                        StatsAggr(  # type: ignore
                            Name="http.request",
                            Type="http",
                            Resource="/users/list",
                            Hits=10,
                            TopLevelHits=10,
                            Duration=100,
                        ),  # noqa
                        StatsAggr(  # type: ignore
                            Name="http.request",
                            Type="http",
                            Resource="/users/create",
                            Hits=5,
                            TopLevelHits=5,
                            Duration=10,
                        ),  # noqa
                    ],
                ),
                StatsBucket(
                    Start=1010,
                    Duration=10,
                    Stats=[
                        StatsAggr(  # type: ignore
                            Name="http.request",
                            Type="http",
                            Resource="/users/list",
                            Hits=20,
                            TopLevelHits=20,
                            Duration=200,
                        ),
                    ],
                ),
            ],
            """[
  {
    "Start": 0,
    "Duration": 10,
    "Stats": [
      {
        "Name": "http.request",
        "Type": "http",
        "Resource": "/users/create",
        "Hits": 5,
        "TopLevelHits": 5,
        "Duration": 10
      },
      {
        "Name": "http.request",
        "Type": "http",
        "Resource": "/users/list",
        "Hits": 10,
        "TopLevelHits": 10,
        "Duration": 100
      }
    ]
  },
  {
    "Start": 10,
    "Duration": 10,
    "Stats": [
      {
        "Name": "http.request",
        "Type": "http",
        "Resource": "/users/list",
        "Hits": 20,
        "TopLevelHits": 20,
        "Duration": 200
      }
    ]
  }
]\n""",
        ),
    ],
)
def test_generate_tracestats_snapshot(buckets, expected):
    assert tracestats_snapshot.generate(buckets) == expected


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
    custom_file_name = custom_dir / "custom_snapshot"
    custom_file = custom_dir / "custom_snapshot.json"

    resp = await agent.get(
        "/test/session/snapshot",
        params={"test_session_token": "test_case", "file": str(custom_file_name)},
    )
    assert resp.status == 200, await resp.text()
    assert os.path.exists(custom_file), custom_file
    with open(custom_file, mode="r") as f:
        assert "".join(f.readlines()) != ""


@pytest.mark.parametrize("snapshot_ci_mode", [False, True])
async def test_snapshot_tracestats(agent, tmp_path, snapshot_ci_mode, do_reference_v06_http_stats, snapshot_dir):
    resp = await do_reference_v06_http_stats(token="test_case")
    assert resp.status == 200

    snap_path = snapshot_dir / "test_case_tracestats.json"
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_case"})
    resp_clear = await agent.get("/test/session/clear", params={"test_session_token": "test_case"})
    assert resp_clear.status == 200, await resp_clear.text()

    if snapshot_ci_mode:
        # No previous snapshot file exists so this should fail
        assert resp.status == 400
        assert f"Trace stats snapshot file '{snap_path}' not found" in await resp.text()
    else:
        # First invocation the snapshot, file should be created
        assert resp.status == 200
        assert os.path.exists(snap_path)
        with open(snap_path, mode="r") as f:
            assert "".join(f.readlines()) != ""

        # Do the snapshot again to actually perform a comparison
        resp = await do_reference_v06_http_stats(token="test_case")
        assert resp.status == 200, await resp.text()

        resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_case"})
        assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("snapshot_removed_attrs", [{"start", "duration", "span_events.name"}])
async def test_removed_attributes(agent, tmp_path, snapshot_removed_attrs, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    custom_file_name = custom_dir / "custom_snapshot"
    custom_file = custom_dir / "custom_snapshot.json"

    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test_case", "file": str(custom_file_name)}
    )
    assert resp.status == 200, await resp.text()

    assert os.path.exists(custom_file), custom_file
    with open(custom_file, mode="r") as f:  # Check that the removed attributes are not present in the span
        file_content = "".join(f.readlines())
        assert file_content != ""
        span = json.loads(file_content)
        for removed_attr in snapshot_removed_attrs:
            assert removed_attr not in span[0]


@pytest.mark.parametrize("snapshot_removed_attrs", [{"metrics.process_id"}])
async def test_removed_attributes_metrics(agent, tmp_path, snapshot_removed_attrs, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    custom_file_name = custom_dir / "custom_snapshot"
    custom_file = custom_dir / "custom_snapshot.json"

    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test_case", "file": str(custom_file_name)}
    )
    assert resp.status == 200, await resp.text()

    assert os.path.exists(custom_file), custom_file
    with open(custom_file, mode="r") as f:
        file_content = "".join(f.readlines())
        assert file_content != ""
        span = json.loads(file_content)
        assert "process_id" not in span[0]


@pytest.mark.parametrize("snapshot_regex_placeholders", [{"addr": "localhost:8080", "path": "^/.*"}])
async def test_with_regex_placeholders(agent, tmp_path, snapshot_removed_attrs, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200

    custom_dir = tmp_path / "custom"
    custom_dir.mkdir()
    custom_file_name = custom_dir / "custom_snapshot"
    custom_file = custom_dir / "custom_snapshot.json"

    resp = await agent.get(
        "/test/session/snapshot", params={"test_session_token": "test_case", "file": str(custom_file_name)}
    )
    assert resp.status == 200, await resp.text()

    assert os.path.exists(custom_file), custom_file
    with open(custom_file, mode="r") as f:  # Check that the removed attributes are not present in the span
        file_content = "".join(f.readlines())
        assert file_content != ""
        span = json.loads(file_content)
        assert "http.request" == span[0][0]["name"]
        assert "{path}" == span[0][0]["resource"]
        assert "http://{addr}/users" == span[0][0]["meta"]["http.url"]


ONE_SPAN_TRACE_NO_START = random_trace(1, remove_keys=["start"])
TWO_SPAN_TRACE_NO_START = random_trace(2, remove_keys=["start"])
FIVE_SPAN_TRACE_NO_START = random_trace(5, remove_keys=["start"])


@pytest.mark.parametrize(
    "expected_traces,actual_traces,error,snapshot_removed_attrs",
    [
        ([ONE_SPAN_TRACE_NO_START], [ONE_SPAN_TRACE_NO_START], "", {"start"}),
        ([FIVE_SPAN_TRACE_NO_START], [FIVE_SPAN_TRACE_NO_START], "", {"start"}),
        # Mismatching trace sizes
        (
            [TWO_SPAN_TRACE_NO_START],
            [TWO_SPAN_TRACE_NO_START[:-1]],
            "Received fewer spans (1) than expected (2). Expected unmatched spans: 'flask.request'",
            {"start"},
        ),
        (
            [TWO_SPAN_TRACE_NO_START[:-1]],
            [TWO_SPAN_TRACE_NO_START],
            "Received more spans (2) than expected (1). Received unmatched spans: 'flask.request'",
            {"start"},
        ),
        (
            [[set_attr(copy_span(ONE_SPAN_TRACE_NO_START[0]), "name", "name_expected")]],
            [[set_attr(copy_span(ONE_SPAN_TRACE_NO_START[0]), "name", "name_received")]],
            "span mismatch on 'name': got 'name_received' which does not match expected 'name_expected'",
            {"start"},
        ),
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_attr(copy_span(TWO_SPAN_TRACE_NO_START[1]), "name", "name_expected"),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_attr(copy_span(TWO_SPAN_TRACE_NO_START[1]), "name", "name_received"),
                ]
            ],
            "span mismatch on 'name': got 'name_received' which does not match expected 'name_expected'",
            {"start"},
        ),
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_meta_tag(copy_span(TWO_SPAN_TRACE_NO_START[1]), "expected", "value"),
                ]
            ],
            [[TWO_SPAN_TRACE_NO_START[0], TWO_SPAN_TRACE_NO_START[1]]],
            "Span meta value 'expected' in expected span but is not in the received span.",
            {"start"},
        ),
        (
            [[TWO_SPAN_TRACE_NO_START[0], TWO_SPAN_TRACE_NO_START[1]]],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE_NO_START[1]), "received", 123.32),
                ]
            ],
            "Span metrics value 'received' in received span but is not in the expected span.",
            {"start"},
        ),
        # Mismatching metrics tag
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE_NO_START[1]), "received", 123.32),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    set_metric_tag(copy_span(TWO_SPAN_TRACE_NO_START[1]), "received", 123.32),
                ]
            ],
            "",
            {"start"},
        ),
        # Mismatching span links count
        (
            [
                TWO_SPAN_TRACE_NO_START,
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0]),
                ]
            ],
            "Span value 'span_links' in received span but is not in the expected span.",
            {"start"},
        ),
        # Mismatching span link reference
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[1]),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0]),
                ]
            ],
            "Span link 0 mismatch on 'span_id': got '1' which does not match expected '2'.",
            {"start"},
        ),
        # Mismatching span link value
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], flags=1),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], flags=0),
                ]
            ],
            "Span link 0 mismatch on 'flags': got '0' which does not match expected '1'.",
            {"start"},
        ),
        # Mismatching span link fields
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0]),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], flags=1),
                ]
            ],
            "Span link 0 value 'flags' in received span link but is not in the expected span link.",
            {"start"},
        ),
        # Mismatching span link attribute
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(
                        copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], {"a": "2", "b": "3"}
                    ),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(
                        copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], {"a": "2", "b": "0"}
                    ),
                ]
            ],
            "Span link 0 attributes mismatch on 'b': got '0' which does not match expected '3'.",
            {"start"},
        ),
        # Matching span link
        (
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(
                        copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], {"a": "2", "b": "0"}, 1
                    ),
                ]
            ],
            [
                [
                    TWO_SPAN_TRACE_NO_START[0],
                    add_span_link(
                        copy_span(TWO_SPAN_TRACE_NO_START[1]), TWO_SPAN_TRACE_NO_START[0], {"a": "2", "b": "0"}, 1
                    ),
                ]
            ],
            "",
            {"start"},
        ),
        # Mismatching span events count
        (
            [TWO_SPAN_TRACE_NO_START],
            [[TWO_SPAN_TRACE_NO_START[0], add_span_event(copy_span(TWO_SPAN_TRACE_NO_START[1]))]],
            "Span value 'span_events' in received span but is not in the expected span.",
            {"start"},
        ),
        # Mismatching span event name
        (
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), name="expected_name")]],
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), name="got_name")]],
            "Span event 0 mismatch on 'name': got 'got_name' which does not match expected 'expected_name'.",
            {"start"},
        ),
        # Mismatching span event attributes
        (
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), attributes={"a": "1", "b": "2"})]],
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), attributes={"a": "1", "b": "0"})]],
            "Span event 0 attributes mismatch on 'b': got '{'type': 0, 'string_value': '0'}' which does not match expected '{'type': 0, 'string_value': '2'}'.",
            {"start"},
        ),
        # Matching span event
        (
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), attributes={"a": "1", "b": 2, "c": [3]})]],
            [[add_span_event(copy_span(ONE_SPAN_TRACE_NO_START[0]), attributes={"a": "1", "b": 2, "c": [3]})]],
            "",
            {"start"},
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
                        "duration": 1,
                        "type": "web",
                        "error": 0,
                        "meta": {},
                        "metrics": {},
                        "span_events": [
                            {
                                "time_unix_nano": 123,
                                "name": "event_name",
                            },
                        ],
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
                        "duration": 1,
                        "type": "web",
                        "error": 0,
                        "meta": {},
                        "metrics": {},
                        "span_events": [
                            {
                                "time_unix_nano": 456,
                                "name": "event_name",
                            },
                        ],
                    }
                ]
            ],
            "",
            {"start"},
        ),
    ],
)
async def test_snapshot_trace_differences_removed_start(agent, expected_traces, actual_traces, error):
    resp = await v04_trace(agent, expected_traces, token="test")
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test"})
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/clear", params={"test_session_token": "test"})
    assert resp.status == 200, await resp.text()

    resp = await v04_trace(agent, actual_traces, token="test")
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test"})
    resp_text = await resp.text()
    if error:
        assert resp.status == 400, resp_text
        assert error in resp_text, resp_text
    else:
        assert resp.status == 200, resp_text


def test_normalize_meta_events_sorts_attribute_keys():
    """_normalize_meta_events sorts attribute keys within each event."""
    events = [{"name": "evt", "time_unix_nano": 1, "attributes": {"z": "last", "a": "first", "m": "mid"}}]
    result = trace_snapshot._normalize_meta_events(json.dumps(events))
    parsed = json.loads(result)
    assert list(parsed[0]["attributes"].keys()) == ["a", "m", "z"]


def test_normalize_meta_events_no_attributes():
    """_normalize_meta_events leaves events without attributes unchanged."""
    events = [{"name": "evt", "time_unix_nano": 1}]
    result = trace_snapshot._normalize_meta_events(json.dumps(events))
    parsed = json.loads(result)
    assert parsed == events


def test_normalize_meta_events_multiple_events():
    """_normalize_meta_events handles multiple events correctly."""
    events = [
        {"name": "e1", "time_unix_nano": 1, "attributes": {"b": 2, "a": 1}},
        {"name": "e2", "time_unix_nano": 2, "attributes": {"y": "y", "x": "x"}},
    ]
    result = trace_snapshot._normalize_meta_events(json.dumps(events))
    parsed = json.loads(result)
    assert list(parsed[0]["attributes"].keys()) == ["a", "b"]
    assert list(parsed[1]["attributes"].keys()) == ["x", "y"]


def test_normalize_meta_events_already_sorted():
    """_normalize_meta_events is idempotent when keys are already sorted."""
    events = [{"name": "evt", "time_unix_nano": 1, "attributes": {"a": 1, "b": 2, "c": 3}}]
    raw = json.dumps(events)
    result = trace_snapshot._normalize_meta_events(raw)
    assert json.loads(result) == json.loads(raw)


@pytest.mark.parametrize("snapshot_ci_mode", [False])
async def test_snapshot_meta_events_attribute_order_independent(agent, snapshot_ci_mode):
    """Snapshot comparison succeeds when meta.events attribute key order differs."""
    events_v1 = [{"name": "evt", "time_unix_nano": 100, "attributes": {"a": "1", "b": "2"}}]
    events_v2 = [{"name": "evt", "time_unix_nano": 100, "attributes": {"b": "2", "a": "1"}}]

    span_v1 = {
        "name": "s",
        "span_id": 1,
        "trace_id": 1,
        "parent_id": 0,
        "resource": "/",
        "duration": 1,
        "type": "web",
        "error": 0,
        "meta": {"events": json.dumps(events_v1)},
        "metrics": {},
    }

    span_v2 = {
        "name": "s",
        "span_id": 1,
        "trace_id": 1,
        "parent_id": 0,
        "resource": "/",
        "duration": 1,
        "type": "web",
        "error": 0,
        "meta": {"events": json.dumps(events_v2)},
        "metrics": {},
    }

    # Generate snapshot from v1 ordering
    resp = await v04_trace(agent, [[span_v1]], token="test_events_order")
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_events_order"})
    assert resp.status == 200, await resp.text()

    # Clear and send v2 ordering (different attribute key order)
    resp = await agent.get("/test/session/clear", params={"test_session_token": "test_events_order"})
    assert resp.status == 200, await resp.text()
    resp = await v04_trace(agent, [[span_v2]], token="test_events_order")
    assert resp.status == 200, await resp.text()

    # Should pass despite different attribute key ordering
    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_events_order"})
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("snapshot_removed_attrs", [{"span_id"}])
async def test_removed_attributes_fails_span_id(agent, tmp_path, snapshot_removed_attrs, do_reference_v04_http_trace):
    resp = await do_reference_v04_http_trace(token="test_case")
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/session/snapshot", params={"test_session_token": "test_case"})
    assert resp.status == 400
    assert "Cannot remove 'span_id' from spans" in await resp.text()


@pytest.fixture
def check_trace():
    start_trace("test")


TRACE_A = "0123456789abcdef0123456789abcdef"
TRACE_B = "fedcba9876543210fedcba9876543210"
ROOT = "aaaaaaaaaaaaaaaa"
CHILD = "bbbbbbbbbbbbbbbb"
EXTERNAL = "dddddddddddddddd"


def _otlp_attr(key, value):
    return {"key": key, "value": {"stringValue": value}}


def _otlp_span(trace_id, span_id, name, start, parent=None, attributes=None, **extra):
    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": 3,
        "startTimeUnixNano": str(start),
        "endTimeUnixNano": str(start + 10),
        "attributes": attributes or [],
    }
    if parent:
        span["parentSpanId"] = parent
    span.update(extra)
    return span


def _otlp_payload(spans, resource_attrs=None):
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": resource_attrs
                    or [_otlp_attr("service.name", "svc"), _otlp_attr("telemetry.sdk.version", "1.0.0")]
                },
                "scopeSpans": [{"scope": {"name": "datadog"}, "spans": spans}],
            }
        ]
    }


def _otlp_spans(doc):
    return [s for rs in doc["resourceSpans"] for ss in rs["scopeSpans"] for s in ss["spans"]]


def _otlp_to_protobuf_dict(spec_payload):
    """Render an OTLP/JSON spec payload the way decode_traces_request renders protobuf payloads."""
    snake = json.loads(
        json.dumps(spec_payload)
        .replace("resourceSpans", "resource_spans")
        .replace("scopeSpans", "scope_spans")
        .replace("traceId", "trace_id")
        .replace("parentSpanId", "parent_span_id")
        .replace("spanId", "span_id")
        .replace("startTimeUnixNano", "start_time_unix_nano")
        .replace("endTimeUnixNano", "end_time_unix_nano")
        .replace("stringValue", "string_value")
    )
    for rs in snake["resource_spans"]:
        for ss in rs["scope_spans"]:
            for span in ss["spans"]:
                for key in ("trace_id", "span_id", "parent_span_id"):
                    if key in span:
                        span[key] = base64.b64encode(bytes.fromhex(span[key])).decode()
                span["kind"] = "SPAN_KIND_CLIENT"
    return snake


def test_otlp_canonicalize_renumbers_ids_in_trace_and_parent_order():
    payload = _otlp_payload(
        [
            # Span ids are only unique within a trace.
            _otlp_span(TRACE_B, ROOT, "second", 300),
            _otlp_span(TRACE_A, CHILD, "child", 200, parent=ROOT),
            _otlp_span(TRACE_A, ROOT, "root", 100),
        ]
    )
    doc = otlp_trace_snapshot.canonicalize([payload])
    spans = _otlp_spans(doc)
    assert [s["name"] for s in spans] == ["root", "child", "second"]
    assert [s["traceId"] for s in spans] == [f"{1:032x}", f"{1:032x}", f"{2:032x}"]
    assert [s["spanId"] for s in spans] == [f"{1:016x}", f"{2:016x}", f"{3:016x}"]
    assert spans[1]["parentSpanId"] == f"{1:016x}"
    # Timestamps are kept as received.
    assert spans[0]["startTimeUnixNano"] == "100"


def test_otlp_canonicalize_keeps_ids_outside_the_payload(check_trace):
    def doc(trace_id, span_id):
        link = {"traceId": trace_id, "spanId": span_id}
        span = _otlp_span(TRACE_A, ROOT, "root", 100, parent=span_id, links=[link])
        return otlp_trace_snapshot.canonicalize([_otlp_payload([span])])

    (span,) = _otlp_spans(doc(TRACE_B, EXTERNAL))
    assert span["parentSpanId"] == EXTERNAL
    assert span["links"][0] == {"traceId": TRACE_B, "spanId": EXTERNAL}
    # External ids are random, so they are not compared.
    otlp_trace_snapshot.snapshot(doc(TRACE_B, EXTERNAL), doc(TRACE_A[::-1], CHILD), [], {})


def test_otlp_canonicalize_protobuf_and_json_payloads_match():
    payload = _otlp_payload(
        [
            _otlp_span(TRACE_A, ROOT, "root", 100, attributes=[_otlp_attr("b", "2"), _otlp_attr("a", "1")]),
            _otlp_span(TRACE_A, CHILD, "child", 200, parent=ROOT),
        ]
    )
    from_json = otlp_trace_snapshot.canonicalize([payload])
    from_protobuf = otlp_trace_snapshot.canonicalize([_otlp_to_protobuf_dict(payload)])
    assert from_json == from_protobuf
    # Attributes are sorted by key and enums are rendered as integers.
    assert [a["key"] for a in _otlp_spans(from_json)[0]["attributes"]] == ["a", "b"]
    assert _otlp_spans(from_json)[0]["kind"] == 3


def test_otlp_canonicalize_merges_a_trace_split_across_exports():
    first = _otlp_payload([_otlp_span(TRACE_A, CHILD, "child", 200, parent=ROOT)])
    # The same resource attributes in a different order.
    second = _otlp_payload(
        [_otlp_span(TRACE_A, ROOT, "root", 100)],
        resource_attrs=[_otlp_attr("telemetry.sdk.version", "1.0.0"), _otlp_attr("service.name", "svc")],
    )
    doc = otlp_trace_snapshot.canonicalize([first, second])
    assert len(doc["resourceSpans"]) == 1
    assert len(doc["resourceSpans"][0]["scopeSpans"]) == 1
    assert [s["name"] for s in _otlp_spans(doc)] == ["root", "child"]
    assert doc == otlp_trace_snapshot.canonicalize([second, first])


def test_otlp_generate_round_trips_through_snapshot(check_trace):
    doc = otlp_trace_snapshot.canonicalize([_otlp_payload([_otlp_span(TRACE_A, ROOT, "root", 100)])])
    expected = json.loads(otlp_trace_snapshot.generate(doc))
    otlp_trace_snapshot.snapshot(expected, doc, ignored=[], attribute_regex_replaces={})


def test_otlp_snapshot_fails_on_attribute_change(check_trace):
    expected = otlp_trace_snapshot.canonicalize(
        [_otlp_payload([_otlp_span(TRACE_A, ROOT, "root", 100, attributes=[_otlp_attr("a", "1")])])]
    )
    received = otlp_trace_snapshot.canonicalize(
        [_otlp_payload([_otlp_span(TRACE_A, ROOT, "root", 100, attributes=[_otlp_attr("a", "2")])])]
    )
    with pytest.raises(AssertionError, match="do not match the snapshot"):
        otlp_trace_snapshot.snapshot(expected, received, ignored=[], attribute_regex_replaces={})


def test_otlp_snapshot_fails_on_missing_spans(check_trace):
    expected = otlp_trace_snapshot.canonicalize([_otlp_payload([_otlp_span(TRACE_A, ROOT, "root", 100)])])
    with pytest.raises(AssertionError):
        otlp_trace_snapshot.snapshot(expected, {"resourceSpans": []}, ignored=[], attribute_regex_replaces={})


def test_otlp_snapshot_ignores_use_the_native_syntax(check_trace):
    def doc(value, start, sdk_version, span_attributes):
        payload = _otlp_payload(
            [_otlp_span(TRACE_A, ROOT, "root", start, attributes=span_attributes, traceState=f"dd=p:{value}")],
            resource_attrs=[_otlp_attr("runtime-id", value), _otlp_attr("telemetry.sdk.version", sdk_version)],
        )
        return otlp_trace_snapshot.canonicalize([payload])

    expected = doc("one", 100, "1.0.0", [_otlp_attr("runtime-id", "one")])
    # Ignoring the only attribute matches a span without attributes.
    received = doc("two", 500, "2.0.0", [])
    with pytest.raises(AssertionError):
        otlp_trace_snapshot.snapshot(expected, received, ignored=[], attribute_regex_replaces={})
    # telemetry.sdk.version and traceState are always ignored; meta.X matches span and resource attributes.
    otlp_trace_snapshot.snapshot(
        expected, received, ignored=["meta.runtime-id", "start", "duration"], attribute_regex_replaces={}
    )


def test_otlp_generate_applies_removes_and_regex_placeholders():
    doc = otlp_trace_snapshot.canonicalize(
        [
            _otlp_payload(
                [
                    _otlp_span(
                        TRACE_A,
                        ROOT,
                        "root",
                        100,
                        attributes=[_otlp_attr("url", "http://localhost:1234/"), _otlp_attr("x", "1")],
                    )
                ]
            )
        ]
    )
    generated = json.loads(
        otlp_trace_snapshot.generate(
            doc, removed=["meta.x"], attribute_regex_replaces={"{port}": re.compile(r"(?<=:)\d+(?=/)")}
        )
    )
    assert _otlp_spans(generated)[0]["attributes"] == [_otlp_attr("url", "http://localhost:{port}/")]


def test_fmt_formats_otlp_trace_snapshots(tmp_path):
    doc = otlp_trace_snapshot.canonicalize([_otlp_payload([_otlp_span(TRACE_A, ROOT, "root", 100)])])
    snapshot_file = tmp_path / "token_otlp_traces.json"
    snapshot_file.write_text(json.dumps(doc))

    with pytest.raises(SystemExit):
        fmt.main(["--check", str(tmp_path)])
    fmt.main([str(tmp_path)])
    assert snapshot_file.read_text() == otlp_trace_snapshot.generate(doc)
    fmt.main(["--check", str(tmp_path)])
