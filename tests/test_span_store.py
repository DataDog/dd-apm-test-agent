import gzip
import importlib
import json
from unittest import mock

import msgpack
import pytest

from ddapm_test_agent.agent import Agent

from lapdog.claude_hooks import ClaudeHooksAPI
from lapdog.span_store import MAX_MEMORY_ENV
from lapdog.span_store import RawEventLog
from lapdog.span_store import SpanStore
from lapdog.span_store import estimate_size
from lapdog.span_store import DEFAULT_MAX_MEMORY
from lapdog.span_store import max_memory_from_env
from lapdog.span_store import parse_memory_limit
from lapdog.span_store import raw_event_budget
from lapdog.span_store import request_budget
from lapdog.span_store import span_budget
from lapdog.span_store import parse_memory_size

cli_main = importlib.import_module("lapdog.cli.main")


def _span(trace_id, span_id, payload_bytes=1000):
    return {"trace_id": trace_id, "span_id": span_id, "meta": {"input": {"value": "x" * payload_bytes}}}


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1048576", 1048576),
        ("512MB", 512 * 1024**2),
        ("512mb", 512 * 1024**2),
        ("2GiB", 2 * 1024**3),
        ("1.5g", int(1.5 * 1024**3)),
        ("64K", 64 * 1024),
    ],
)
def test_parse_memory_size(value, expected):
    assert parse_memory_size(value) == expected


@pytest.mark.parametrize("value", ["", "abc", "10XB", "0", "-5MB"])
def test_parse_memory_size_rejects_invalid(value):
    with pytest.raises(ValueError):
        parse_memory_size(value)


def test_max_memory_from_env(monkeypatch):
    monkeypatch.setenv(MAX_MEMORY_ENV, "1MB")
    assert max_memory_from_env() == 1024**2
    monkeypatch.setenv(MAX_MEMORY_ENV, "unlimited")
    assert max_memory_from_env() is None
    monkeypatch.setenv(MAX_MEMORY_ENV, "garbage")
    assert max_memory_from_env() == parse_memory_size(DEFAULT_MAX_MEMORY)
    monkeypatch.delenv(MAX_MEMORY_ENV)
    assert max_memory_from_env() == parse_memory_size(DEFAULT_MAX_MEMORY)


@pytest.mark.parametrize("value", ["unlimited", "NONE", " off "])
def test_parse_memory_limit_disables_limit(value):
    assert parse_memory_limit(value) is None


def test_budget_shares_do_not_exceed_limit():
    total = 1000 * 1024**2
    assert span_budget(total) + request_budget(total) + 3 * raw_event_budget(total) <= total


def test_estimate_size_counts_utf8_bytes():
    ascii_size = estimate_size({"v": "a" * 1000})
    cjk_size = estimate_size({"v": "日" * 1000})
    assert cjk_size - ascii_size == 2000


def test_unbounded_store_behaves_like_list():
    store = SpanStore()
    store.extend([_span("t1", "1"), _span("t2", "2")])
    store.insert(0, _span("t0", "0"))
    store.append(_span("t3", "3"))
    assert [s["span_id"] for s in store] == ["0", "1", "2", "3"]
    assert store.estimated_bytes == 0
    store.remove_where(lambda s: s["trace_id"] == "t1")
    assert [s["span_id"] for s in store] == ["0", "2", "3"]
    assert json.loads(json.dumps(store))[0]["span_id"] == "0"


def test_evicts_oldest_traces_first():
    span_size = estimate_size(_span("t0", "0"))
    store = SpanStore(max_bytes=span_size * 10)
    for trace in range(12):
        store.append(_span(f"t{trace}", str(trace)))

    retained = [s["trace_id"] for s in store]
    assert retained[-1] == "t11"
    assert "t0" not in retained
    assert store.estimated_bytes <= span_size * 10
    assert store.evicted_spans == store.evicted_traces == 12 - len(store)


def test_evicts_whole_traces():
    span_size = estimate_size(_span("t0", "0"))
    store = SpanStore(max_bytes=span_size * 5)
    store.extend([_span("old", str(i)) for i in range(3)])
    store.extend([_span("new", str(i)) for i in range(3)])
    assert {s["trace_id"] for s in store} == {"new"}
    assert len(store) == 3
    assert store.evicted_traces == 1


def test_active_traces_are_never_evicted():
    span_size = estimate_size(_span("t0", "0"))
    active = {"pinned"}
    store = SpanStore(max_bytes=span_size * 4)
    store.add_active_trace_source(lambda: active)
    store.append(_span("pinned", "p"))
    for trace in range(6):
        store.append(_span(f"t{trace}", str(trace)))
    assert "pinned" in {s["trace_id"] for s in store}

    active.clear()
    for trace in range(6, 12):
        store.append(_span(f"t{trace}", str(trace)))
    assert "pinned" not in {s["trace_id"] for s in store}


def test_store_stays_over_budget_when_everything_is_active():
    span_size = estimate_size(_span("t0", "0"))
    store = SpanStore(max_bytes=span_size * 2)
    store.add_active_trace_source(lambda: {"busy"})
    store.extend([_span("busy", str(i)) for i in range(5)])
    assert len(store) == 5
    assert store.evicted_spans == 0


def test_finished_traces_are_remeasured_after_growing():
    active = {"t1"}
    store = SpanStore(max_bytes=10 * 1024**2)
    store.add_active_trace_source(lambda: active)
    root = _span("t1", "root", payload_bytes=0)
    store.append(root)
    initial = store.estimated_bytes

    root["meta"]["output"] = {"value": "y" * 50_000}
    active.clear()
    store.append(_span("t2", "next", payload_bytes=0))

    assert store.estimated_bytes - initial >= 50_000


def test_remove_where_releases_accounted_bytes():
    store = SpanStore(max_bytes=10 * 1024**2)
    store.extend([_span("t1", "1"), _span("t2", "2")])
    before = store.estimated_bytes
    store.remove_where(lambda s: s["trace_id"] == "t1")
    assert store.estimated_bytes == before - estimate_size(_span("t1", "1"))


def test_eviction_follows_trace_ids_reassigned_after_append():
    span_size = estimate_size(_span("t0", "0"))
    store = SpanStore(max_bytes=span_size * 3)
    orphan = _span("orphan-trace", "o")
    store.append(orphan)
    orphan["trace_id"] = "t-late"
    for trace in range(5):
        store.append(_span(f"t{trace}", str(trace)))
    assert orphan not in store
    assert store.estimated_bytes <= span_size * 3


def test_raw_event_log_drops_oldest_events():
    event_size = estimate_size({"i": 0, "body": "z" * 500})
    log = RawEventLog(max_bytes=event_size * 5)
    for i in range(20):
        log.append({"i": i, "body": "z" * 500})
    assert log[-1]["i"] == 19
    assert log[0]["i"] > 0
    assert len(log) <= 5


def test_raw_event_log_keeps_newest_event_even_when_oversized():
    log = RawEventLog(max_bytes=100)
    log.append({"body": "z" * 10_000})
    log.append({"body": "w" * 10_000})
    assert len(log) == 1
    assert log[0]["body"][0] == "w"


def _run_claude_turn(hooks, session_id, turn):
    hooks._dispatch_hook({"session_id": session_id, "hook_event_name": "UserPromptSubmit", "prompt": f"turn {turn}"})
    tool_use_id = f"{session_id}-tool-{turn}"
    hooks._dispatch_hook(
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": tool_use_id,
            "tool_input": {"command": "cat big.txt"},
        }
    )
    hooks._dispatch_hook(
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": tool_use_id,
            "tool_response": "o" * 20_000,
        }
    )


def test_claude_hooks_evict_finished_turns_and_keep_active_turn():
    hooks = ClaudeHooksAPI(max_memory_bytes=1024**2)
    session_id = "bounded-session"
    for turn in range(40):
        _run_claude_turn(hooks, session_id, turn)
        hooks._dispatch_hook({"session_id": session_id, "hook_event_name": "Stop"})
    _run_claude_turn(hooks, session_id, 40)

    store = hooks._assembled_spans
    session = hooks._sessions[session_id]
    retained_traces = {span["trace_id"] for span in store}
    assert store.evicted_traces > 0
    assert session.trace_id in retained_traces
    assert store.estimated_bytes <= store.max_bytes
    assert len(hooks._raw_events) < 40 * 4


async def test_memory_endpoint_reports_budget(lapdog_agent):
    resp = await lapdog_agent.get("/lapdog/memory")
    assert resp.status == 200, await resp.text()
    data = await resp.json()
    assert data["max_memory_bytes"] == max_memory_from_env()
    assert data["evicted_spans"] == 0
    assert data["evicted_requests"] == 0


def test_max_memory_flag_sets_server_env(monkeypatch):
    monkeypatch.setenv(MAX_MEMORY_ENV, "")
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog", "--max-memory", "256MB", "claude"])
    monkeypatch.setattr(cli_main, "lapdog_alive", lambda: False)
    with mock.patch.object(cli_main, "cmd_claude") as cmd_claude:
        cli_main.main()
    cmd_claude.assert_called_once()
    assert cli_main.os.environ[MAX_MEMORY_ENV] == "256MB"


def test_max_memory_flag_rejects_invalid_size():
    with pytest.raises(SystemExit):
        cli_main._parse_lapdog_args(["--max-memory", "lots"])


@pytest.mark.parametrize(
    "argv",
    [["--max-memory", "1GB", "codex", "exec"], ["--max-memory=1GB", "codex", "exec"]],
)
def test_parse_command_consumes_max_memory_value(argv):
    lapdog_args, remaining = cli_main._parse_command(argv)
    assert remaining == ["codex", "exec"]
    assert cli_main._parse_lapdog_args(lapdog_args).max_memory == "1GB"


def test_agent_request_budget_is_off_by_default():
    agent = Agent()
    for _ in range(50):
        agent._store_dogstatsd_datagram(b"x" * 10_000)
    assert len(agent._requests) == 50
    assert agent.evicted_requests == 0


def test_agent_evicts_oldest_requests_over_budget():
    agent = Agent()
    agent.max_request_bytes = 100_000
    evicted = []
    agent.request_eviction_listener = evicted.extend
    for i in range(30):
        agent._store_dogstatsd_datagram(str(i).encode() + b"x" * 10_000)

    bodies = [req.get("_testagent_data")[:2] for req in agent._requests]
    assert bodies[-1] == b"29"
    assert agent.stored_request_bytes <= agent.max_request_bytes
    assert agent.evicted_requests == len(evicted) == 30 - len(agent._requests)
    assert evicted[0].get("_testagent_data").startswith(b"0x")


async def test_agent_recounts_request_bytes_after_session_clear(agent):
    test_agent = agent.app["agent"]
    test_agent.max_request_bytes = 10 * 1024**2
    test_agent._store_dogstatsd_datagram(b"x" * 10_000)
    assert test_agent.stored_request_bytes > 0
    resp = await agent.get("/test/session/clear")
    assert resp.status == 200
    assert test_agent.stored_request_bytes == 0


def _llmobs_request_body(index):
    payload = {
        "ml_app": "app",
        "spans": [
            {
                "name": f"span-{index}",
                "span_id": f"span-{index}",
                "trace_id": f"trace-{index}",
                "parent_id": "undefined",
                "start_ns": index,
                "duration": 1,
                "meta": {"span": {"kind": "llm"}, "input": {"value": "q" * 20_000}, "model_name": "gpt-4o"},
                "metrics": {"input_tokens": 10, "output_tokens": 10},
            }
        ],
    }
    return gzip.compress(msgpack.packb(payload))


async def test_lapdog_evicts_oldest_tracer_llmobs_requests(lapdog_agent):
    app = lapdog_agent.server.app
    test_agent = app["agent"]
    platform = app["llmobs_event_platform_api"]
    test_agent.max_request_bytes = 300_000
    for index in range(20):
        resp = await lapdog_agent.post(
            "/evp_proxy/v2/api/v2/llmobs",
            headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
            data=_llmobs_request_body(index),
        )
        assert resp.status == 200, await resp.text()
        platform.get_llmobs_spans()

    span_ids = {span["span_id"] for span in platform.get_llmobs_spans()}
    assert "span-19" in span_ids
    assert "span-0" not in span_ids
    assert test_agent.evicted_requests > 0
    assert test_agent.stored_request_bytes <= test_agent.max_request_bytes
    retained_ids = {id(span) for req in test_agent._requests for span in req.get("_lapdog_llmobs_spans") or []}
    assert platform._locally_priced_spans <= retained_ids


def test_refresh_evicts_trace_that_finished_over_budget():
    span_size = estimate_size(_span("t0", "0"))
    active = {"big"}
    store = SpanStore(max_bytes=span_size * 3)
    store.add_active_trace_source(lambda: active)
    store.extend([_span("big", str(i)) for i in range(6)])
    assert len(store) == 6

    active.clear()
    store.refresh()
    assert len(store) == 0
    assert store.estimated_bytes == 0


async def test_claude_stop_evicts_large_final_turn_without_new_spans(lapdog_agent):
    hooks = lapdog_agent.server.app["llmobs_event_platform_api"]._claude_hooks_api
    hooks._assembled_spans.max_bytes = 50_000
    session_id = "big-final-turn"
    for event in (
        {"hook_event_name": "UserPromptSubmit", "prompt": "read everything"},
        {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t1", "tool_input": {"command": "cat"}},
        {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "t1", "tool_response": "o" * 100_000},
    ):
        await lapdog_agent.post("/claude/hooks", json={"session_id": session_id, **event})
    assert hooks._assembled_spans.estimated_bytes > 50_000

    resp = await lapdog_agent.post("/claude/hooks", json={"session_id": session_id, "hook_event_name": "Stop"})
    assert resp.status == 200
    assert hooks._assembled_spans.estimated_bytes <= 50_000
    assert hooks._assembled_spans.evicted_traces == 1


async def test_lapdog_evicts_requests_when_decoding_exceeds_budget(lapdog_agent):
    app = lapdog_agent.server.app
    test_agent = app["agent"]
    platform = app["llmobs_event_platform_api"]
    test_agent.max_request_bytes = 600_000
    for index in range(20):
        resp = await lapdog_agent.post(
            "/evp_proxy/v2/api/v2/llmobs",
            headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
            data=_llmobs_request_body(index),
        )
        assert resp.status == 200, await resp.text()
    assert test_agent.evicted_requests == 0

    platform.get_llmobs_spans()

    assert test_agent.evicted_requests > 0
    assert test_agent.stored_request_bytes <= test_agent.max_request_bytes
    retained_ids = {id(span) for req in test_agent._requests for span in req.get("_lapdog_llmobs_spans") or []}
    assert platform._locally_priced_spans <= retained_ids
