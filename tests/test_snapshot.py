import os

import pytest


@pytest.mark.parametrize(
    "params,headers,snapshot_ci_mode",
    [
        ({"test_session_token": "test_case"}, {}, False),
        ({"test_session_token": "test_case"}, {}, True),
        ({}, {"X-Datadog-Test-Session-Token": "test_case"}, False),
        ({}, {"X-Datadog-Test-Session-Token": "test_case"}, True),
    ],
)
async def test_snapshot_single_trace_synchronous(
    agent,
    headers,
    params,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    snapshot_dir,
    snapshot_ci_mode,
):
    """
    When doing a synchronous session
        When a trace is sent and a snapshot taken
            When in CI mode
                The snapshot file should be created
            When not in CI mode
                The test should fail
    """
    # Send a trace
    hdrs = v04_reference_http_trace_payload_headers.copy()
    hdrs.update(headers)
    resp = await agent.put(
        "/v0.4/traces",
        params=params,
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200

    # Perform the snapshot
    resp = await agent.get("/test/session-snapshot", params=params, headers=headers)

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
            print(f.readlines())
