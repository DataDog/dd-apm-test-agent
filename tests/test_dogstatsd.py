import asyncio
import socket


async def test_session_dogstatsd(agent):
    agent.app["agent"]._store_dogstatsd_datagram(b"page.views:1|c|#env:test\n\nruntime.mem:42|g")
    resp = await agent.get("/test/session/dogstatsd")
    assert resp.status == 200, await resp.text()
    assert await resp.json() == ["page.views:1|c|#env:test", "runtime.mem:42|g"]


async def test_session_dogstatsd_clear(agent):
    agent.app["agent"]._store_dogstatsd_datagram(b"page.views:1|c")
    resp = await agent.get("/test/session/clear")
    assert resp.status == 200, await resp.text()
    resp = await agent.get("/test/session/dogstatsd")
    assert await resp.json() == []


async def test_dogstatsd_over_udp(testagent, testagent_url, dogstatsd_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"page.views:1|c", ("127.0.0.1", int(dogstatsd_port)))

    for _ in range(50):
        resp = await testagent.get(f"{testagent_url}/test/session/dogstatsd")
        lines = await resp.json()
        if lines:
            break
        await asyncio.sleep(0.05)
    assert lines == ["page.views:1|c"]
