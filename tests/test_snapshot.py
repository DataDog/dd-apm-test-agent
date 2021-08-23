import os

import pytest


@pytest.mark.parametrize(
    "snapshot_ci_mode",
    [
        False,
        True,
        False,
        True,
    ],
)
async def test_snapshot_single_trace_synchronous(
    agent,
    snapshot_dir,
    snapshot_ci_mode,
    do_reference_http_trace,
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
    resp = await do_reference_http_trace(token="test_case")
    assert resp.status == 200

    # Do the snapshot
    resp = await agent.get(
        "/test/session-snapshot", params={"test_session_token": "test_case"}
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
            print("".join(f.readlines()))

        # Do the snapshot again to actually perform a comparison
        resp = await do_reference_http_trace(token="test_case")
        assert resp.status == 200, await resp.text()

        resp = await agent.get(
            "/test/session-snapshot", params={"test_session_token": "test_case"}
        )
        assert resp.status == 200, await resp.text()
