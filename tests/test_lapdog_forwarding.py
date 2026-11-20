import asyncio
import gzip
import json
import time

from aiohttp import web
import msgpack
import pytest

from lapdog.cli import forward as forward_cli
from lapdog.forwarding import Forwarding
from lapdog.forwarding import ForwardingConfig
from lapdog.forwarding import load_forwarding_config
from lapdog.forwarding import normalize_server_url
from lapdog.forwarding import payload_span_keys
from lapdog.forwarding import save_forwarding_config


def _span(span_id, **extra):
    span = {
        "span_id": span_id,
        "trace_id": "trace-1",
        "parent_id": "undefined",
        "name": span_id,
        "start_ns": time.time_ns(),
        "duration": 1_000,
        "meta": {"span": {"kind": "llm"}},
        "metrics": {},
        "tags": ["ml_app:app"],
    }
    span.update(extra)
    return span


def _payload(*spans):
    return msgpack.packb({"_dd.stage": "raw", "event_type": "span", "spans": list(spans)})


@pytest.fixture
async def self_hosted_stub(aiohttp_server):
    """Stand in for a self-hosted server and record what lapdog sends it."""
    received = []
    state = {"status": 200}

    async def intake(request):
        body = await request.read()  # aiohttp undoes Content-Encoding: gzip
        received.append({"path": request.path, "headers": dict(request.headers), "body": body})
        return web.json_response({}, status=state["status"])

    async def info(request):
        if state.get("down"):
            return web.json_response({}, status=503)
        return web.json_response({"mode": "server", "retention_days": 7})

    app = web.Application()
    app.router.add_post("/evp_proxy/v2/api/v2/llmobs", intake)
    app.router.add_post("/evp_proxy/v4/api/v2/llmobs", intake)
    app.router.add_get("/info", info)
    server = await aiohttp_server(app)
    server.received = received
    server.state = state
    server.url = str(server.make_url("")).rstrip("/")
    return server


async def _wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting")
        await asyncio.sleep(0.02)


async def _forwarding(lapdog_agent, **change):
    resp = await lapdog_agent.post("/lapdog/forwarding", json=change)
    assert resp.status == 200, await resp.text()
    return await resp.json()


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("http://lapdog.internal:8126/", "http://lapdog.internal:8126"),
        ("https://example.com/lapdog", "https://example.com/lapdog"),
        ("lapdog.internal", None),
        ("http://user:pw@host", None),
        ("http://host/?x=1", None),
    ],
)
def test_normalize_server_url(raw, expected):
    assert normalize_server_url(raw) == expected


def test_config_round_trip(isolated_forwarding_config):
    assert load_forwarding_config() == ForwardingConfig()
    save_forwarding_config(ForwardingConfig("http://host:8126", True))
    assert load_forwarding_config() == ForwardingConfig("http://host:8126", True)
    assert json.loads(isolated_forwarding_config.read_text())["self_hosted"] == "http://host:8126"


def test_payload_span_keys():
    keys = payload_span_keys(_payload(_span("a"), _span("b")), "application/msgpack")
    assert [span_id for _, span_id in keys] == ["a", "b"]
    assert payload_span_keys(b"not a payload", "application/msgpack") == []


async def test_app_spans_are_sent_to_self_hosted(lapdog_agent, self_hosted_stub, isolated_forwarding_config):
    state = await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    assert state["self_hosted"]["enabled"] is True
    assert load_forwarding_config().self_hosted == self_hosted_stub.url

    body = _payload(_span("a"), _span("b"))
    resp = await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=gzip.compress(body),
    )
    assert resp.status == 200
    await _wait_for(lambda: self_hosted_stub.received)

    sent = self_hosted_stub.received[0]
    assert sent["path"] == "/evp_proxy/v2/api/v2/llmobs"
    assert sent["headers"]["Content-Encoding"] == "gzip"
    assert sent["body"] == body

    info = await (await lapdog_agent.get("/info")).json()
    self_hosted = info["forwarding"]["self_hosted"]
    assert self_hosted["spans_last_hour"] == 2
    assert self_hosted["last_error"] is None
    # Spans stay in lapdog's memory too.
    listed = await lapdog_agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs", json={"list": {"limit": 10}}
    )
    assert len((await listed.json())["result"]["events"]) == 2


async def test_self_hosted_errors_are_reported(lapdog_agent, self_hosted_stub):
    self_hosted_stub.state["status"] = 500
    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs", headers={"Content-Type": "application/msgpack"}, data=_payload(_span("a"))
    )
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    await _wait_for(lambda: forwarding.self_hosted_stats.last_error is not None)
    assert forwarding.self_hosted_stats.last_error.startswith("HTTP 500")
    assert forwarding.self_hosted_stats.to_json()["spans_last_hour"] == 0


async def test_nothing_is_sent_when_forwarding_is_off(lapdog_agent, self_hosted_stub):
    await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs", headers={"Content-Type": "application/msgpack"}, data=_payload(_span("a"))
    )
    await asyncio.sleep(0.2)
    assert self_hosted_stub.received == []
    info = await (await lapdog_agent.get("/info")).json()
    assert info["forwarding"]["self_hosted"]["enabled"] is False


async def test_coding_agent_spans_need_opt_in(lapdog_agent, self_hosted_stub):
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    forwarding.forward_coding_agent_spans([_span("agent")])
    await asyncio.sleep(0.2)
    assert self_hosted_stub.received == []

    state = await _forwarding(lapdog_agent, self_hosted_coding_agents=True)
    assert state["self_hosted"]["coding_agents"] is True
    forwarding.forward_coding_agent_spans([_span("agent")])
    await _wait_for(lambda: self_hosted_stub.received)
    spans = msgpack.unpackb(self_hosted_stub.received[0]["body"], raw=False)["spans"]
    assert [s["span_id"] for s in spans] == ["agent"]


async def test_forwarding_api_guards(lapdog_agent):
    bad_origin = await lapdog_agent.post(
        "/lapdog/forwarding", json={"self_hosted": "http://evil:8126"}, headers={"Origin": "https://evil.example"}
    )
    assert bad_origin.status == 403
    not_json = await lapdog_agent.post(
        "/lapdog/forwarding", data='{"self_hosted": "http://evil:8126"}', headers={"Content-Type": "text/plain"}
    )
    assert not_json.status == 415
    assert (await lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": "not a url"})).status == 400
    allowed = await lapdog_agent.post(
        "/lapdog/forwarding", json={"self_hosted": None}, headers={"Origin": "https://lapdog.datadoghq.com"}
    )
    assert allowed.status == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "https://lapdog.datadoghq.com"


async def test_a_url_that_isnt_a_lapdog_server_is_refused(lapdog_agent, self_hosted_stub, aiohttp_server):
    async def not_lapdog(request):
        return web.json_response({"version": "7.50.0"})

    app = web.Application()
    app.router.add_get("/info", not_lapdog)
    other = await aiohttp_server(app)
    other_url = str(other.make_url("")).rstrip("/")
    unused = await aiohttp_server(web.Application())
    down_url = str(unused.make_url("")).rstrip("/")
    await unused.close()

    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    for url, error in [(other_url, f"{other_url} isn't a lapdog server"), (down_url, f"Can't reach {down_url}")]:
        resp = await lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": url})
        assert resp.status == 400
        assert (await resp.json())["error"] == error
    # The working server stays configured.
    state = await (await lapdog_agent.get("/lapdog/forwarding")).json()
    assert state["self_hosted"]["url"] == self_hosted_stub.url


async def test_turning_forwarding_off_wins_over_an_earlier_pending_connect(lapdog_agent, aiohttp_server):
    release = asyncio.Event()

    async def slow_info(request):
        await release.wait()
        return web.json_response({"mode": "server"})

    app = web.Application()
    app.router.add_get("/info", slow_info)
    slow = await aiohttp_server(app)
    slow_url = str(slow.make_url("")).rstrip("/")

    connect = asyncio.ensure_future(lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": slow_url}))
    await asyncio.sleep(0.05)
    off = asyncio.ensure_future(lapdog_agent.post("/lapdog/forwarding", json={"self_hosted": None}))
    await asyncio.sleep(0.05)
    release.set()
    assert (await connect).status == 200
    assert (await off).status == 200
    state = await (await lapdog_agent.get("/lapdog/forwarding")).json()
    assert state["self_hosted"]["enabled"] is False


async def test_self_hosted_health_and_retention_in_info(lapdog_agent, self_hosted_stub):
    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    await _wait_for(lambda: forwarding.self_hosted_reachable is not None)
    self_hosted = (await (await lapdog_agent.get("/info")).json())["forwarding"]["self_hosted"]
    assert self_hosted["reachable"] is True
    assert self_hosted["retention_days"] == 7


async def test_polling_info_notices_a_server_going_down_quickly(lapdog_agent, self_hosted_stub, monkeypatch):
    from lapdog import forwarding as forwarding_module

    monkeypatch.setattr(forwarding_module, "_FRESH_HEALTH", 0.05)
    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    await _wait_for(lambda: forwarding.self_hosted_reachable is True)

    async def reachable_after_polls():
        # The UI polls /info every few seconds; each poll refreshes reachability for the next one.
        for _ in range(20):
            info = await (await lapdog_agent.get("/info")).json()
            if info["forwarding"]["self_hosted"]["reachable"] is (not self_hosted_stub.state.get("down")):
                return True
            await asyncio.sleep(0.05)
        return False

    self_hosted_stub.state["down"] = True
    assert await reachable_after_polls(), "never noticed the server going down"
    self_hosted_stub.state["down"] = False
    assert await reachable_after_polls(), "never noticed the server coming back"


async def test_a_reachable_server_clears_a_failed_send(lapdog_agent, self_hosted_stub):
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    forwarding.configure_self_hosted("http://127.0.0.1:9", False)
    await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs", headers={"Content-Type": "application/msgpack"}, data=_payload(_span("lost"))
    )
    await _wait_for(lambda: forwarding.self_hosted_stats.last_error is not None)

    # The server is back (here: the same lapdog now pointed at a working one), with nothing sent since.
    forwarding.self_hosted = self_hosted_stub.url
    await forwarding._check_self_hosted()
    assert forwarding.self_hosted_reachable is True
    assert forwarding.self_hosted_stats.last_error is None


async def test_a_rejected_send_stays_an_error_while_reachable(lapdog_agent, self_hosted_stub):
    await _forwarding(lapdog_agent, self_hosted=self_hosted_stub.url)
    self_hosted_stub.state["status"] = 400
    await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs", headers={"Content-Type": "application/msgpack"}, data=_payload(_span("bad"))
    )
    forwarding = lapdog_agent.app["lapdog_forwarding"]
    await _wait_for(lambda: forwarding.self_hosted_stats.last_error is not None)
    await forwarding._check_self_hosted()
    assert forwarding.self_hosted_stats.last_error.startswith("HTTP 400")


async def test_spans_reach_a_real_self_hosted_server(lapdog_agent, self_hosted_server):
    url = str(self_hosted_server.make_url("")).rstrip("/")
    await _forwarding(lapdog_agent, self_hosted=url)
    await lapdog_agent.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack"},
        data=_payload(_span("stored", trace_id="trace-real")),
    )

    async def stored():
        resp = await self_hosted_server.post(
            "/api/unstable/llm-obs-query-rewriter/list?type=llmobs", json={"list": {"limit": 10}}
        )
        return [e["event"]["custom"]["span_id"] for e in (await resp.json())["result"]["events"]]

    deadline = time.monotonic() + 10
    while await stored() != ["stored"]:
        assert time.monotonic() < deadline, "span never reached the self-hosted server"
        await asyncio.sleep(0.1)


def test_cli_saves_self_hosted_when_lapdog_is_stopped(monkeypatch, capsys):
    monkeypatch.setattr(forward_cli, "lapdog_alive", lambda: False)
    monkeypatch.setattr(forward_cli, "_check_self_hosted", lambda url: None)
    forward_cli.cmd_forward(["http://self-hosted:8126/", "--include-coding-agents"])
    assert load_forwarding_config() == ForwardingConfig("http://self-hosted:8126", True)
    forward_cli.cmd_forward(["off"])
    assert load_forwarding_config() == ForwardingConfig(None, True)
    assert "Stopped sending" in capsys.readouterr().out


def test_cli_rejects_bad_arguments(monkeypatch):
    monkeypatch.setattr(forward_cli, "lapdog_alive", lambda: False)
    for argv in (["not a url"], ["http://self-hosted:8126", "--bogus"]):
        with pytest.raises(SystemExit) as exc:
            forward_cli.cmd_forward(argv)
        assert exc.value.code == 2


async def test_spans_from_v04_meta_struct_are_forwarded(monkeypatch):
    from unittest import mock

    from ddapm_test_agent import agent as agent_module

    envelope = {"spans": [{"span_id": "1", "trace_id": "2", "start_ns": 1}]}
    monkeypatch.setattr(agent_module, "extract_llmobs_envelopes_from_v04_traces", lambda traces: [envelope])
    agent = agent_module.Agent()
    received = []
    agent.llmobs_payload_listener = lambda path, body, content_type: received.append((path, body, content_type))
    source = mock.Mock()
    source.get.return_value = None
    source.url.origin.return_value = "http://localhost:8126"
    agent._store_synthetic_llmobs_requests(source, [])
    assert received == [("/evp_proxy/v4/api/v2/llmobs", json.dumps([envelope]).encode(), "application/json")]


def test_forwarded_keys_are_kept_while_their_span_is_in_memory():
    forwarding = Forwarding(ForwardingConfig())
    local = {("t", "1"), ("t", "2"), ("t", "3")}
    forwarding.local_keys = lambda: local
    forwarding._prune_at = 2
    forwarding._remember([("t", "1"), ("t", "2"), ("t", "3")])
    # Over the limit, but every span is still in memory: none may be forgotten, or it'd be counted twice.
    assert all(forwarding.is_forwarded({"trace_id": "t", "span_id": i}) for i in "123")

    local.discard(("t", "1"))
    forwarding._prune_at = 2
    forwarding._remember([("t", "4")])
    assert not forwarding.is_forwarded({"trace_id": "t", "span_id": "1"})
    assert all(forwarding.is_forwarded({"trace_id": "t", "span_id": i}) for i in "234")
