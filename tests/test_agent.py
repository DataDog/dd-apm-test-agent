import msgpack


async def test_sync_snapshot_single_trace(agent):
    resp = await agent.get(
        "/test/start",
        headers={
            "X-Datadog-Test-Token": "mytoken",
        },
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.put(
        "/v0.4/traces",
        headers={
            "Content-Type": "application/msgpack",
            "X-Datadog-Trace-Count": "1",
            "Datadog-Meta-Tracer-Version": "v0.1",
        },
        data=msgpack.packb(
            [
                {
                    "name": "http.request",
                    "service": "my-http-server",
                    "resource": "/users/",
                    "meta": {},
                    "metrics": {
                        "sampling_priority_v1": "1",
                    },
                }
            ]
        ),
    )
    assert resp.status == 200, await resp.text()

    resp = await agent.get("/test/snapshot", params={"token": "mytoken"})
    assert resp.status == 200, await resp.text()
