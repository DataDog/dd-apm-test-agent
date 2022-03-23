async def test_stats_basic(agent, do_reference_v06_http_stats):
    resp = await do_reference_v06_http_stats(token="test_stats_decode")
    assert resp.status == 200, await resp.text()

    resp = await agent.get(
        "/test/session/stats",
        headers={"X-Datadog-Test-Session-Token": "test_stats_decode"},
    )
    assert resp.status == 200, await resp.text()
    body = await resp.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["Hostname"] == "Host-1234"
    assert body[0]["Stats"][0]["Stats"][0]["Hits"] == 100
