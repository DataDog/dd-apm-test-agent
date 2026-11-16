import datetime
import json
import os
import time

import pytest

from lapdog import model_pricing
from lapdog.cli import team_server as server_cli
from lapdog.team_server.app import ENFORCER_KEY
from lapdog.team_server.app import STATE_KEY
from lapdog.team_server.clickhouse import render_config
from lapdog.team_server.config import Settings
from lapdog.team_server.config import parse_max_disk
from lapdog.team_server.config import parse_retention_days
from lapdog.team_server.config import parse_settings_update

DAY_NS = 86_400 * 1_000_000_000


def _payload(*spans, ml_app="test-app"):
    return json.dumps({"ml_app": ml_app, "spans": list(spans)})


def _span(span_id, start_ns=None, **extra):
    span = {
        "span_id": span_id,
        "trace_id": extra.pop("trace_id", "trace-1"),
        "name": extra.pop("name", span_id),
        "start_ns": start_ns if start_ns is not None else time.time_ns(),
        "duration": 1_000,
        "meta": {"span": {"kind": extra.pop("kind", "llm")}},
        "metrics": {},
        "tags": [],
    }
    span.update(extra)
    return span


async def _post_spans(client, *spans, path="/api/v2/llmobs", headers=None):
    return await client.post(
        path, data=_payload(*spans), headers={"Content-Type": "application/json", **(headers or {})}
    )


async def _list(client, query="", headers=None):
    resp = await client.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"limit": 100, "search": {"query": query}}},
        headers=headers or {},
    )
    assert resp.status == 200, await resp.text()
    return [event["event"]["custom"] for event in (await resp.json())["result"]["events"]]


# -- config ------------------------------------------------------------------


@pytest.mark.parametrize("value,days", [("30d", 30), ("2w", 14), ("14", 14), ("1 day", 1), ("3650d", 3650)])
def test_parse_retention_days(value, days):
    assert parse_retention_days(value) == days


@pytest.mark.parametrize("value", ["0d", "3651d", "12h", "soon", ""])
def test_parse_retention_days_rejects(value):
    with pytest.raises(ValueError):
        parse_retention_days(value)


@pytest.mark.parametrize("value,size", [("20GB", 20 * 1024**3), ("1TiB", 1024**4), ("1.5g", int(1.5 * 1024**3))])
def test_parse_max_disk(value, size):
    assert parse_max_disk(value) == size


@pytest.mark.parametrize("value", ["500MB", "lots", "-1GB"])
def test_parse_max_disk_rejects(value):
    with pytest.raises(ValueError):
        parse_max_disk(value)


def test_parse_settings_update():
    current = Settings(30, 20 * 1024**3)
    assert parse_settings_update({"retention": "7d"}, current) == Settings(7, 20 * 1024**3)
    assert parse_settings_update({"max_disk": "50GB"}, current) == Settings(30, 50 * 1024**3)
    with pytest.raises(ValueError):
        parse_settings_update({"retention": "7d", "color": "blue"}, current)
    with pytest.raises(ValueError):
        parse_settings_update(["7d"], current)


# -- intake ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/v2/llmobs", "/evp_proxy/v2/api/v2/llmobs", "/evp_proxy/v4/api/v2/llmobs"])
async def test_intake_paths(team_server, path):
    resp = await _post_spans(team_server, _span("a"), path=path)
    assert resp.status == 200, await resp.text()
    assert [s["span_id"] for s in await _list(team_server)] == ["a"]


async def test_resent_span_replaces_previous_copy(team_server):
    start = time.time_ns()
    await _post_spans(team_server, _span("a", start, name="first"))
    await _post_spans(team_server, _span("a", start, name="second"))
    spans = await _list(team_server)
    assert [s["name"] for s in spans] == ["second"]


async def test_span_without_start_ns_gets_ingest_time(team_server):
    span = _span("a")
    del span["start_ns"]
    before = time.time_ns()
    await _post_spans(team_server, span)
    (stored,) = await _list(team_server)
    assert stored["start_ns"] >= before


async def test_eval_metrics_are_accepted(team_server):
    resp = await team_server.post("/api/intake/llm-obs/v2/eval-metric", json={"data": {}})
    assert resp.status == 200


async def test_update_merges_partial_fields(team_server):
    await _post_spans(
        team_server,
        _span("a", session_id="sess-1", tags=["user:alice"], kind="agent", metrics={"output_tokens": 1}),
    )
    resp = await team_server.post(
        "/api/v2/llmobs/update",
        data=json.dumps({"spans": [{"span_id": "a", "metrics": {"output_tokens": 99}}]}),
        headers={"Content-Type": "application/json"},
    )
    assert (await resp.json()) == {"updated": 1}
    (stored,) = await _list(team_server)
    assert stored["metrics"]["output_tokens"] == 99
    assert stored["ml_app"] == "test-app"
    assert stored["session_id"] == "sess-1"
    assert "user:alice" in stored["tags"]
    assert stored["kind"] == "agent"


async def test_update_unknown_span_is_dropped(team_server):
    resp = await team_server.post(
        "/evp_proxy/v2/api/v2/llmobs/update",
        data=json.dumps({"spans": [{"span_id": "nope", "metrics": {"output_tokens": 1}}]}),
        headers={"Content-Type": "application/json"},
    )
    assert (await resp.json()) == {"updated": 0}


async def test_spans_priced_at_ingest_and_repriced_on_update(team_server, monkeypatch, tmp_path):
    prices = [
        {
            "id": "openai",
            "models": [{"id": "gpt-4", "match": {"equals": "gpt-4"}, "prices": {"input_mtok": 2, "output_mtok": 8}}],
        }
    ]
    price_file = tmp_path / "prices.json"
    price_file.write_bytes(json.dumps(prices).encode())
    monkeypatch.setattr(model_pricing, "PRICE_PATH", price_file)
    monkeypatch.setattr(model_pricing, "_catalog", None)
    monkeypatch.setattr(model_pricing, "_catalog_stamp", None)

    span = _span("llm", metrics={"input_tokens": 5, "output_tokens": 10})
    span["meta"].update({"model_name": "gpt-4", "model_provider": "openai"})
    await _post_spans(team_server, span)
    (stored,) = await _list(team_server)
    assert stored["metrics"]["estimated_total_cost"] == 5 * 2000 + 10 * 8000

    async def update(metrics):
        await team_server.post(
            "/api/v2/llmobs/update",
            data=json.dumps({"spans": [{"span_id": "llm", "metrics": metrics}]}),
            headers={"Content-Type": "application/json"},
        )
        (stored,) = await _list(team_server)
        return stored["metrics"]["estimated_total_cost"]

    assert await update({"output_tokens": 20}) == 5 * 2000 + 20 * 8000
    assert await update({"estimated_total_cost": 123}) == 123


def test_clickhouse_config_measures_its_own_memory():
    # Reading memory from the cgroup counts the whole container (or CI runner) against ClickHouse's cap.
    config = render_config("/data", 9000, "0" * 64, 1024**3)
    assert "<memory_worker_use_cgroup>0</memory_worker_use_cgroup>" in config
    assert f"<max_server_memory_usage>{1024**3}</max_server_memory_usage>" in config


# -- routes ------------------------------------------------------------------


async def test_info(team_server):
    assert (await team_server.get("/ping")).status == 200
    info = await team_server.get("/info")
    assert info.status == 200
    body = await info.json()
    assert body["mode"] == "server"
    assert "/evp_proxy/v2/" in body["endpoints"]
    assert body["retention_days"] == 3650


async def test_routes_need_no_credentials(team_server):
    # ddtrace's agentless mode always sends an API key; the server ignores it.
    assert (await _post_spans(team_server, _span("a"), headers={"DD-API-KEY": "anything"})).status == 200
    assert (await _post_spans(team_server, _span("b"), path="/evp_proxy/v2/api/v2/llmobs")).status == 200
    url = "/api/unstable/llm-obs-query-rewriter/list?type=llmobs"
    resp = await team_server.post(url, json={"list": {}}, headers={"Origin": "https://lapdog.datadoghq.com"})
    assert resp.status == 200
    assert resp.headers["Access-Control-Allow-Origin"] == "https://lapdog.datadoghq.com"
    assert (await team_server.get("/api/lapdog/server/status")).status == 200


async def test_retentions_reports_server_retention(team_server):
    team_server.app[STATE_KEY].settings = Settings(retention_days=7, max_disk_bytes=100 * 1024**3)
    resp = await team_server.get("/api/unstable/llm-obs/v1/retentions")
    assert resp.status == 200
    assert (await resp.json())["data"]["attributes"] == {"llmobs": 7, "experiments": 7}


async def test_preflight_allows_private_network(team_server):
    resp = await team_server.options(
        "/api/unstable/llm-obs-query-rewriter/list",
        headers={
            "Origin": "https://lapdog.datadoghq.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Private-Network": "true",
        },
    )
    assert resp.status == 200
    assert resp.headers["Access-Control-Allow-Private-Network"] == "true"


# -- retention and disk cap --------------------------------------------------


def _days_ago(days):
    return time.time_ns() - days * DAY_NS


async def _partition_days(team_server):
    enforcer = team_server.app[ENFORCER_KEY]
    return [pid for pid, _ in await enforcer.partitions()]


async def test_retention_drops_old_days(team_server):
    state = team_server.app[STATE_KEY]
    state.settings = Settings(retention_days=7, max_disk_bytes=100 * 1024**3)
    await _post_spans(team_server, _span("old", _days_ago(10)), _span("recent", _days_ago(3)), _span("now"))
    assert len(await _partition_days(team_server)) == 3

    action = await team_server.app[ENFORCER_KEY].enforce()
    assert [d["reason"] for d in action["dropped_partitions"]] == ["retention"]
    assert sorted(s["span_id"] for s in await _list(team_server)) == ["now", "recent"]
    assert action["effective_retention_days"] == 4
    assert state.ingest_paused is False


async def test_disk_cap_drops_oldest_days_then_pauses_ingest(team_server):
    state = team_server.app[STATE_KEY]
    enforcer = team_server.app[ENFORCER_KEY]
    await _post_spans(team_server, _span("d2", _days_ago(2)), _span("d1", _days_ago(1)), _span("today"))

    state.settings = Settings(retention_days=30, max_disk_bytes=1)
    action = await enforcer.enforce()
    assert [d["reason"] for d in action["dropped_partitions"]] == ["max_disk", "max_disk"]
    assert [s["span_id"] for s in await _list(team_server)] == ["today"]
    assert state.ingest_paused is True
    assert state.last_action == action

    paused = await _post_spans(team_server, _span("more"))
    assert paused.status == 503
    assert [s["span_id"] for s in await _list(team_server)] == ["today"]

    state.settings = Settings(retention_days=30, max_disk_bytes=100 * 1024**3)
    await enforcer.enforce()
    assert state.ingest_paused is False
    assert (await _post_spans(team_server, _span("more"))).status == 200


async def test_settings_api_updates_ttl_and_saves(team_server, team_server_config):
    resp = await team_server.get("/api/lapdog/server/settings")
    assert (await resp.json())["retention_days"] == 3650

    resp = await team_server.post("/api/lapdog/server/settings", json={"retention": "2w", "max_disk": "5GB"})
    assert resp.status == 200, await resp.text()
    body = await resp.json()
    assert body["settings"]["retention_days"] == 14
    assert body["settings"]["max_disk_bytes"] == 5 * 1024**3

    enforcer = team_server.app[ENFORCER_KEY]
    rows = await enforcer.client.query(f"SHOW CREATE TABLE {team_server_config.database}.spans")
    assert "toIntervalDay(14)" in rows[0]["statement"]
    with open(f"{team_server_config.data_dir}/server.json") as f:
        assert json.load(f) == {"retention_days": 14, "max_disk_bytes": 5 * 1024**3}

    bad = await team_server.post("/api/lapdog/server/settings", json={"retention": "0d"})
    assert bad.status == 400


@pytest.mark.parametrize(
    "free,total,low",
    [(16 * 1024**3, 461 * 1024**3, False), (300 * 1024**2, 10 * 1024**3, True), (1024**3, 10 * 1024**3, False)],
)
def test_low_free_disk_threshold(free, total, low):
    from lapdog.team_server.retention import DiskUsage
    from lapdog.team_server.retention import LOW_FREE_CAP_BYTES
    from lapdog.team_server.retention import LOW_FREE_RATIO

    usage = DiskUsage(used_bytes=0, pending_free_bytes=0, free_bytes=free, total_bytes=total)
    assert usage.free_below(LOW_FREE_RATIO, LOW_FREE_CAP_BYTES) is low


async def test_status_reports_disk_and_days(team_server):
    await _post_spans(team_server, _span("a", _days_ago(1)), _span("b"))
    resp = await team_server.get("/api/lapdog/server/status")
    status = await resp.json()
    today = datetime.datetime.now(datetime.timezone.utc).date()
    assert status["settings"]["retention_days"] == 3650
    assert status["newest_day"] == today.isoformat()
    assert status["oldest_day"] == (today - datetime.timedelta(days=1)).isoformat()
    assert status["disk"]["used_bytes"] > 0
    assert status["span_rows"] == 2
    assert status["ingest_paused"] is False
    assert status["clickhouse"]["healthy"] is True


def test_foreground_start_writes_and_removes_pid_file(tmp_path, monkeypatch):
    seen = {}

    def fake_main(argv):
        seen["pid"] = server_cli.read_pid_file(str(tmp_path / "server.pid"))
        return 0

    monkeypatch.setattr("lapdog.team_server.__main__.main", fake_main)
    with pytest.raises(SystemExit) as exc:
        server_cli.cmd_server_start(["--foreground", "--data-dir", str(tmp_path), "--port", "9999"])
    assert exc.value.code == 0
    assert seen["pid"] == (os.getpid(), 9999)
    assert not (tmp_path / "server.pid").exists()
