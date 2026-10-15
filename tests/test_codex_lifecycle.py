"""Regression coverage for runtime hooks and the transcript supplement."""

import io
import json
from unittest import mock

import pytest

from lapdog import codex_hook
from lapdog.claude_hooks import ClaudeHooksAPI
from lapdog.cli import codex_setup
from lapdog.codex_hooks import CodexHooksAPI


def test_hook_command_url_wins_over_stale_daemon_environment(monkeypatch, capsys):
    monkeypatch.setenv("LAPDOG_URL", "http://localhost:8126")
    monkeypatch.setenv("LAPDOG_CODEX_CAPTURE", "isolated")
    monkeypatch.setattr(codex_hook.sys, "argv", ["codex_hook", "--url", "http://localhost:12345/", "--capture"])
    payload = {"session_id": "parent", "hook_event_name": "SessionStart"}
    monkeypatch.setattr(codex_hook.sys, "stdin", io.StringIO(json.dumps(payload)))
    with mock.patch.object(codex_hook, "forward") as forward:
        codex_hook.main()
    forward.assert_called_once_with("http://localhost:12345", payload)
    assert capsys.readouterr().out == "{}\n"


@pytest.fixture
def capture(monkeypatch):
    monkeypatch.setenv("DD_CODEX_ML_APP", "codex")
    return CodexHooksAPI(ClaudeHooksAPI())


def hook(api, event, sid="parent", turn="turn", seconds=1, **fields):
    body = {
        "hook_event_name": event,
        "session_id": sid,
        "turn_id": turn,
        "timestamp": f"2026-10-14T12:00:{seconds:02d}Z",
        "cwd": "/repo",
        "model": "gpt-5.5",
        **fields,
    }
    return api._lifecycle.dispatch(sid, body)


def spans(api, kind):
    return [s for s in api._hooks_api._assembled_spans if s["meta"]["span"]["kind"] == kind]


def test_parallel_tools_use_runtime_ids_not_source_or_position(capture):
    hook(capture, "UserPromptSubmit", prompt="ten tools")
    with mock.patch("lapdog.codex_hooks.extract_exec_calls", side_effect=AssertionError("must not parse JS")):
        for i in range(10):
            hook(capture, "PreToolUse", tool_use_id=str(i), tool_name="Bash", tool_input={"command": "same command"})
        for i in reversed(range(10)):
            hook(
                capture,
                "PostToolUse",
                seconds=3,
                tool_use_id=str(i),
                tool_name="Bash",
                tool_input={"command": "same command"},
                tool_response={"stdout": f"result {i}", "stderr": "", "exitCode": 0},
            )
    tools = spans(capture, "tool")
    assert len(tools) == 10
    assert {s["meta"]["metadata"]["hook_tool_use_id"]: s["meta"]["output"]["value"] for s in tools} == {
        str(i): f"result {i}" for i in range(10)
    }
    assert all(s["duration"] == 2_000_000_000 for s in tools)
    assert all("source:codex-hooks" in s["tags"] for s in tools)


def test_printed_exec_and_wait_outputs_do_not_emit_tools(capture):
    hook(capture, "UserPromptSubmit", prompt="run tools")
    records = [
        {
            "type": "custom_tool_call",
            "call_id": "exec",
            "name": "exec",
            "input": "const r=await tools[n](a); text(r.slice(0,2));",
        },
        {"type": "custom_tool_call_output", "call_id": "exec", "output": "Script running with cell ID 4"},
        {"type": "function_call", "call_id": "wait", "name": "wait", "arguments": '{"cell_id":"4"}'},
        {"type": "function_call_output", "call_id": "wait", "output": [{"type": "input_text", "text": "partial"}]},
    ]
    for payload in records:
        capture._lifecycle.ingest(
            "parent", {"type": "response_item", "timestamp": "2026-10-14T12:00:02Z", "payload": payload}
        )
    assert spans(capture, "tool") == []
    hook(
        capture,
        "PostToolUse",
        tool_use_id="clock",
        tool_name="clock__curr_time",
        tool_input={},
        tool_response={"current_time": "now"},
    )
    hook(capture, "PostToolUse", tool_use_id="goal", tool_name="get_goal", tool_input={}, tool_response={"goal": None})
    assert [json.loads(s["meta"]["output"]["value"]) for s in spans(capture, "tool")] == [
        {"current_time": "now"},
        {"goal": None},
    ]
    assert (
        len(capture._sessions["parent"].active_turn.pending_llm_input_messages)
        + len(capture._sessions["parent"].active_turn.llm_input_messages)
        >= 2
    )


@pytest.mark.parametrize(
    "response", [{"stdout": "bad", "stderr": "error", "exitCode": 1}, {"output": "baderror", "exit_code": 1}]
)
def test_failed_command_output_and_metadata(capture, response):
    hook(
        capture,
        "PostToolUse",
        tool_use_id="cmd",
        tool_name="Bash",
        tool_input={"command": "check"},
        tool_response=response,
    )
    tool = spans(capture, "tool")[0]
    assert tool["status"] == "error"
    assert tool["meta"]["output"]["value"] == "baderror"
    assert tool["meta"]["metadata"]["exit_code"] == 1
    assert tool["meta"]["error"]["message"] == "Exit code 1"


def test_mcp_text_is_unwrapped_without_losing_metadata(capture):
    hook(
        capture,
        "PostToolUse",
        tool_use_id="mcp",
        tool_name="mcp__fs__read",
        tool_response={
            "content": [{"type": "text", "text": '{"resources":[]}'}],
            "isError": False,
            "_meta": {"version": 1},
        },
    )
    tool = spans(capture, "tool")[0]
    assert json.loads(tool["meta"]["output"]["value"]) == {"resources": []}
    assert tool["meta"]["metadata"]["response_metadata"] == {"isError": False, "_meta": {"version": 1}}


def test_duplicate_and_out_of_order_tool_events(capture):
    args = {"tool_use_id": "call", "tool_name": "get_goal", "tool_input": {}}
    hook(capture, "PostToolUse", seconds=4, tool_response={"goal": None}, **args)
    hook(capture, "PostToolUse", seconds=4, tool_response={"goal": None}, **args)
    hook(capture, "PreToolUse", seconds=2, **args)
    assert len(spans(capture, "tool")) == 1
    assert spans(capture, "tool")[0]["duration"] == 2_000_000_000


def test_sibling_agents_and_child_tools_are_not_a_stack(capture):
    hook(capture, "UserPromptSubmit", prompt="delegate")
    for child in ("child-a", "child-b"):
        hook(capture, "SubagentStart", agent_id=child, agent_type="worker")
        hook(
            capture,
            "PostToolUse",
            sid=child,
            turn=child + "-turn",
            tool_use_id="read",
            tool_name="Bash",
            tool_input={"command": "pwd"},
            tool_response={"output": child, "exit_code": 0},
        )
        capture._lifecycle.link_child(child)
    hook(capture, "SubagentStop", seconds=5, agent_id="child-a", last_assistant_message="A done")
    hook(capture, "SubagentStop", seconds=6, agent_id="child-b", last_assistant_message="B done")
    agents = capture._lifecycle.agents
    assert agents["child-a"]["parent_id"] == agents["child-b"]["parent_id"]
    assert agents["child-a"]["meta"]["output"]["value"] == "A done"
    for child in agents:
        root = capture._sessions[child].active_turn.root_span_ref
        assert root["span_links"][0]["span_id"] == agents[child]["span_id"]
    assert capture._sessions["parent"].agent_span_stack == []
    assert all(s["session_id"] == "parent" for s in spans(capture, "tool"))


def test_transcript_flush_after_stop_does_not_create_another_turn(capture):
    hook(capture, "UserPromptSubmit", prompt="hello")
    hook(capture, "Stop", seconds=4, last_assistant_message="hello back")
    root = capture._sessions["parent"].active_turn.root_span_ref
    capture._lifecycle.ingest(
        "parent", {"type": "event_msg", "timestamp": "2026-10-14T12:00:05Z", "payload": {"type": "task_complete"}}
    )
    assert capture._sessions["parent"].active_turn.root_span_ref is root
    assert capture._sessions["parent"].active_turn.closed


def test_read_chunk_preserves_partial_line(tmp_path):
    path = tmp_path / "rollout.jsonl"
    path.write_bytes(b'{"type":"session_meta"}\n{"type":')
    records, offset = codex_hook.read_chunk(path, 0)
    assert records == [{"type": "session_meta"}]
    with path.open("ab") as target:
        target.write(b'"event_msg"}\n')
    assert codex_hook.read_chunk(path, offset)[0] == [{"type": "event_msg"}]


def test_forward_preserves_tool_when_transcript_fails(tmp_path, monkeypatch):
    path = tmp_path / "broken.jsonl"
    path.write_text("broken\n")
    send = mock.Mock(return_value={"registered": True})
    monkeypatch.setattr(codex_hook, "request", send)
    codex_hook.forward(
        "http://localhost:12345",
        {"session_id": "parent", "hook_event_name": "PostToolUse", "transcript_path": str(path)},
    )
    assert send.call_args.args[1]["hook"]["hook_event_name"] == "PostToolUse"


def test_install_and_uninstall_preserve_foreign_hooks(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.setattr(codex_setup, "supported", lambda _: True)
    path = tmp_path / "hooks.json"
    foreign = {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "other"}]}]}}
    legacy = json.loads(json.dumps(foreign))
    legacy["hooks"]["PostToolUse"][0]["hooks"].append(
        {"type": "command", "command": "old lapdog hook", "statusMessage": codex_setup.MARKER}
    )
    path.write_text(json.dumps(legacy))
    flags = codex_setup.install(12345)
    first = path.read_text()
    assert flags is None
    assert codex_setup.install(12345) == flags
    assert path.read_text() == first
    config = json.loads(first)
    assert set(config["hooks"]) == set(codex_hook.EVENTS)
    assert config["hooks"]["PostToolUse"][0] == foreign["hooks"]["PostToolUse"][0]
    for event in codex_hook.EVENTS:
        handler = config["hooks"][event][-1]["hooks"][0]
        assert "12345" in handler["command"]
        assert "--capture" in handler["command"]
        assert "trusted" not in handler
    codex_setup.install(23456)
    assert "23456" in path.read_text()
    assert "12345" not in path.read_text()
    codex_setup.uninstall()
    assert json.loads(path.read_text()) == foreign
    assert f"Cleared Lapdog Codex hook registrations from {path}." in capsys.readouterr().out
    path.write_text("{}")
    codex_setup.uninstall()
    assert path.read_text() == "{}"
    path.unlink()
    capsys.readouterr()
    codex_setup.uninstall()
    assert f"No Codex hooks file at {path}; nothing to remove." in capsys.readouterr().out
    assert not path.exists()
    codex_setup.install(12345)
    assert path.exists()


@pytest.fixture
def dd_api_key():
    return ""


async def test_cursor_conflict_and_event_retry(lapdog_agent):
    client = lapdog_agent
    body = {
        "session_id": "native",
        "path": "/transcript",
        "offset": 0,
        "end_offset": 20,
        "records": [{"type": "session_meta", "payload": {"id": "native"}}],
    }
    assert (await client.post("/codex/hooks/native", json=body)).status == 200
    assert (await client.post("/codex/hooks/native", json=body)).status == 409
    assert await (await client.get("/codex/hooks/cursor?path=/transcript")).json() == {"offset": 20}
    body = {
        "session_id": "native",
        "event_id": "id",
        "hook": {
            "hook_event_name": "PostToolUse",
            "tool_use_id": "clock",
            "tool_name": "clock__curr_time",
            "tool_input": {},
            "tool_response": {"current_time": "now"},
        },
    }
    for _ in range(2):
        assert (await client.post("/codex/hooks/native", json=body)).status == 200
    result = await (await client.get("/claude/hooks/spans")).json()
    assert len([s for s in result["spans"] if s["meta"]["span"]["kind"] == "tool"]) == 1


def test_llm_messages_usage_and_hosted_search_survive_native_capture(capture):
    hook(capture, "UserPromptSubmit", prompt="search")

    def ingest(record_type, payload, seconds=2):
        capture._lifecycle.ingest(
            "parent", {"type": record_type, "timestamp": f"2026-10-14T12:00:{seconds:02d}Z", "payload": payload}
        )

    ingest("event_msg", {"type": "user_message", "message": "search"})
    ingest("response_item", {"type": "web_search_call", "id": "search", "query": "example", "status": "completed"})
    ingest(
        "response_item",
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Found it"}]},
        3,
    )
    ingest(
        "event_msg",
        {
            "type": "token_count",
            "info": {"last_token_usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}},
        },
        4,
    )
    hook(capture, "Stop", seconds=5, last_assistant_message="Found it")
    assert len(spans(capture, "tool")) == 1  # Hosted search has no native hook.
    llms = spans(capture, "llm")
    assert sum(s["metrics"]["total_tokens"] for s in llms) == 120
    assert any(m.get("content") == "Found it" for s in llms for m in s["meta"]["output"]["messages"])
    assert any(m.get("content") == "search" for s in llms for m in s["meta"]["input"]["messages"])


def test_subagent_completion_after_parent_stop_keeps_parent_closed(capture):
    hook(capture, "SubagentStart", agent_id="child", agent_type="worker")
    hook(capture, "Stop", seconds=3)
    root = capture._sessions["parent"].active_turn.root_span_ref
    hook(capture, "SubagentStop", seconds=4, agent_id="child", last_assistant_message="done")
    assert capture._sessions["parent"].active_turn.closed
    assert capture._sessions["parent"].active_turn.root_span_ref is root
    assert capture._lifecycle.agents["child"]["meta"]["output"]["value"] == "done"


def test_permission_request_is_not_reported_as_approval(capture):
    hook(capture, "PreToolUse", tool_use_id="cmd", tool_name="Bash", tool_input={"command": "check"})
    hook(capture, "PermissionRequest", tool_name="Bash", tool_input={"command": "check", "description": "Run checks"})
    hook(
        capture,
        "PostToolUse",
        seconds=4,
        tool_use_id="cmd",
        tool_name="Bash",
        tool_response={"output": "ok", "exit_code": 0},
    )
    hidden = spans(capture, "tool")[0]["meta"]["metadata"]["_dd"]
    assert hidden["permission_request"]["justification"] == "Run checks"
    assert "auto_reviews" not in hidden
    assert "outcome" not in hidden["permission_request"]


def test_guardian_supplement_handles_session_classification(capture):
    sid = "review"
    capture._get_or_create_session(sid, 0).native_capture = True
    capture._lifecycle.ingest(sid, {"type": "turn_context", "payload": {"model": "codex-auto-review"}})
    capture._lifecycle.ingest(sid, {"type": "event_msg", "payload": {"type": "task_complete"}})
    assert sid in capture._auto_review_sessions
    assert not any(s["session_id"] == sid for s in capture._hooks_api._assembled_spans)


def test_transcript_cursor_conflict_retries_without_copying_files(tmp_path, monkeypatch):
    import urllib.error

    path = tmp_path / "rollout.jsonl"
    path.write_text(json.dumps({"type": "session_meta", "payload": {"id": "child"}}) + "\n")
    requests = []
    committed = False

    def send(url, body=None):
        nonlocal committed
        if body is None:
            return {"offset": path.stat().st_size if committed else 0}
        requests.append(body)
        committed = True
        raise urllib.error.HTTPError(url, 409, "stale", {}, None)

    monkeypatch.setattr(codex_hook, "request", send)
    assert codex_hook.send_transcript("http://localhost", path, "parent") == "child"
    assert requests[0]["session_id"] == "child"
    assert requests[0]["backfill"] is True
    assert list(tmp_path.iterdir()) == [path]


async def test_invalid_hook_does_not_advance_cursor(lapdog_agent):
    body = {"session_id": "native", "path": "/bad", "offset": 0, "end_offset": 10, "hook": {"hook_event_name": "Stop"}}
    assert (await lapdog_agent.post("/codex/hooks/native", json=body)).status == 400
    assert await (await lapdog_agent.get("/codex/hooks/cursor?path=/bad")).json() == {"offset": 0}


async def test_hook_relay_to_collector_preserves_full_output(lapdog_agent, tmp_path, monkeypatch):
    import asyncio

    monkeypatch.delenv("LAPDOG_URL", raising=False)
    path = tmp_path / "session.jsonl"

    def append(record_type, payload):
        with path.open("a") as target:
            target.write(
                json.dumps({"type": record_type, "timestamp": "2026-10-14T12:00:01Z", "payload": payload}) + "\n"
            )

    append("session_meta", {"id": "relay-session", "cwd": str(tmp_path)})
    append("turn_context", {"turn_id": "turn", "model": "gpt-5.5"})
    append("event_msg", {"type": "user_message", "message": "run commands"})
    base = {
        "session_id": "relay-session",
        "turn_id": "turn",
        "transcript_path": str(path),
        "tool_use_id": "actual-execution",
        "tool_name": "Bash",
        "tool_input": {"command": "pwd"},
        "cwd": str(tmp_path),
    }
    await lapdog_agent.post("/codex/hooks/registrations", json={"owner": "test", "session_ids": ["relay-session"]})
    url = str(lapdog_agent.make_url("/")).rstrip("/")
    await asyncio.to_thread(codex_hook.forward, url, {**base, "hook_event_name": "PreToolUse"})
    append(
        "response_item",
        {
            "type": "custom_tool_call",
            "call_id": "script",
            "name": "exec",
            "input": "for (const c of commands) await tools.exec_command(c)",
        },
    )
    output = "complete output\n" * 2000
    await asyncio.to_thread(
        codex_hook.forward,
        url,
        {**base, "hook_event_name": "PostToolUse", "tool_response": {"output": output, "exit_code": 0}},
    )
    append("response_item", {"type": "custom_tool_call_output", "call_id": "script", "output": "short summary"})
    append(
        "response_item", {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "done"}]}
    )
    append(
        "event_msg",
        {
            "type": "token_count",
            "info": {"last_token_usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}},
        },
    )
    await asyncio.to_thread(
        codex_hook.forward, url, {**base, "hook_event_name": "Stop", "last_assistant_message": "done"}
    )
    append("event_msg", {"type": "task_complete"})
    await asyncio.to_thread(codex_hook.forward, url, {**base, "hook_event_name": "SessionEnd"})
    result = await (await lapdog_agent.get("/claude/hooks/spans")).json()
    tools = [s for s in result["spans"] if s["meta"]["span"]["kind"] == "tool"]
    assert len(tools) == 1
    assert tools[0]["name"] == "Ran"
    assert tools[0]["meta"]["output"]["value"] == output
    assert len([s for s in result["spans"] if s["parent_id"] == "undefined"]) == 1
    llms = [s for s in result["spans"] if s["meta"]["span"]["kind"] == "llm"]
    assert sum(s["metrics"]["total_tokens"] for s in llms) == 15


@pytest.mark.parametrize("hook_first", [True, False])
def test_subagent_prompt_and_name_from_transcript_match_by_child_id(capture, hook_first):
    hook(capture, "UserPromptSubmit", prompt="delegate")
    if hook_first:
        hook(capture, "SubagentStart", agent_id="worker", agent_type="default")
    for payload in [
        {"type": "collab_agent_spawn_begin", "call_id": "spawn", "prompt": "inspect files"},
        {
            "type": "collab_agent_spawn_end",
            "call_id": "spawn",
            "new_thread_id": "worker",
            "new_agent_nickname": "Inspector",
            "new_agent_role": "explorer",
        },
    ]:
        capture._lifecycle.ingest(
            "parent", {"type": "event_msg", "timestamp": "2026-10-14T12:00:02Z", "payload": payload}
        )
    if not hook_first:
        hook(capture, "SubagentStart", agent_id="worker", agent_type="default")
    agent = capture._lifecycle.agents["worker"]
    assert agent["name"] == "Inspector"
    assert agent["meta"]["input"]["value"] == "inspect files"
    assert agent["meta"]["metadata"]["subagent"]["agent_role"] == "explorer"


@pytest.mark.parametrize("version, supported", [("0.123.0", False), ("0.124.0", True), ("0.162.1", True)])
def test_hook_version_requirement(version, supported, monkeypatch):
    monkeypatch.setattr(
        codex_setup.subprocess, "run", lambda *a, **kw: mock.Mock(returncode=0, stdout=f"codex-cli {version}\n")
    )
    assert codex_setup.supported("codex") is supported


def test_unsupported_version_does_not_install_hooks(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.setattr(codex_setup, "supported", lambda _: False)
    with pytest.raises(RuntimeError, match="0.124.0"):
        codex_setup.install(12345)
    assert not (tmp_path / "hooks.json").exists()


def test_hook_relay_preserves_session_name(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    (tmp_path / "session_index.jsonl").write_text('{"id":"parent","thread_name":"My session"}\n')
    send = mock.Mock()
    monkeypatch.setattr(codex_hook, "request", send)
    codex_hook.forward("http://localhost:12345", {"session_id": "parent", "hook_event_name": "SessionStart"})
    assert send.call_args.args[1]["records"] == [
        {"type": "event_msg", "payload": {"type": "session_name", "name": "My session"}}
    ]


@pytest.mark.parametrize("stop_before_usage", [False, True])
def test_llm_is_visible_before_tools_and_late_usage_updates_same_span(capture, stop_before_usage):
    hook(capture, "UserPromptSubmit", prompt="run pwd")

    def ingest(record_type, payload, second):
        capture._lifecycle.ingest(
            "parent", {"type": record_type, "timestamp": f"2026-10-14T12:00:{second:02d}Z", "payload": payload}
        )

    ingest(
        "response_item",
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "I will run pwd."}]},
        2,
    )
    llm = spans(capture, "llm")[0]
    assert llm["metrics"] == {}  # Unknown usage must not appear as zero tokens/cost.
    ingest(
        "response_item",
        {
            "type": "custom_tool_call",
            "call_id": "exec",
            "name": "exec",
            "input": 'text(await tools.exec_command({cmd: "pwd"}));',
        },
        3,
    )
    assert spans(capture, "llm") == [llm]
    assert llm["duration"] == 1_000_000_000
    hook(capture, "PreToolUse", seconds=3, tool_name="Bash", tool_use_id="pwd", tool_input={"command": "pwd"})
    hook(
        capture,
        "PostToolUse",
        seconds=8,
        tool_name="Bash",
        tool_use_id="pwd",
        tool_response={"stdout": "/repo\n", "exitCode": 0},
    )
    tool = spans(capture, "tool")[0]
    assert tool["parent_id"] == llm["parent_id"]
    ingest("response_item", {"type": "custom_tool_call_output", "call_id": "exec", "output": "/repo\n"}, 8)
    if stop_before_usage:
        hook(capture, "Stop", seconds=8)
    ingest(
        "event_msg",
        {
            "type": "token_count",
            "info": {"last_token_usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120}},
        },
        9,
    )
    assert spans(capture, "llm")[0] is llm
    assert llm["metrics"]["total_tokens"] == 120
    assert llm["duration"] == 1_000_000_000
    assert len(spans(capture, "llm")) == 1
    assert len([s for s in capture._hooks_api._assembled_spans if s["name"] == "inference-0"]) == 1
    if not stop_before_usage:
        ingest(
            "response_item",
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Done"}]},
            10,
        )
        second = spans(capture, "llm")[1]
        assert second["metrics"] == {}
        assert any(
            m.get("role") == "tool" and m.get("content") == "/repo\n" for m in second["meta"]["input"]["messages"]
        )
        ingest(
            "event_msg",
            {
                "type": "token_count",
                "info": {"last_token_usage": {"input_tokens": 150, "output_tokens": 5, "total_tokens": 155}},
            },
            11,
        )
        assert spans(capture, "llm")[1] is second
        assert second["metrics"]["total_tokens"] == 155
        assert llm["metrics"]["total_tokens"] == 120


@pytest.mark.parametrize("resume_hook", [True, False])
@pytest.mark.parametrize("indexed_name", [None, "Indexed session name"])
async def test_resume_primes_metadata_without_emitting_history(
    lapdog_agent, tmp_path, monkeypatch, resume_hook, indexed_name
):
    import asyncio

    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    monkeypatch.setattr(codex_hook, "CHUNK_BYTES", 300)  # History and current turn cross request boundaries.
    if indexed_name:
        (tmp_path / "session_index.jsonl").write_text(json.dumps({"id": "resumed", "thread_name": indexed_name}) + "\n")
    path = tmp_path / "resume.jsonl"
    records = [
        {"type": "session_meta", "payload": {"id": "resumed", "cwd": str(tmp_path), "cli_version": "0.162.1"}},
        {"type": "event_msg", "payload": {"type": "session_name", "name": "Transcript session name"}},
        {"type": "turn_context", "payload": {"turn_id": "old", "model": "gpt-5.5", "effort": "high"}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": "old question"}},
        {"type": "response_item", "payload": {"type": "web_search_call", "id": "old-search", "query": "old"}},
        {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "old answer"}],
            },
        },
        {
            "type": "event_msg",
            "payload": {
                "type": "token_count",
                "info": {"last_token_usage": {"input_tokens": 1000, "output_tokens": 200, "total_tokens": 1200}},
            },
        },
        {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "old"}},
    ]
    path.write_text("".join(json.dumps({"timestamp": "2026-10-14T12:00:01Z", **r}) + "\n" for r in records))
    await lapdog_agent.post("/codex/hooks/registrations", json={"owner": "test", "session_ids": ["resumed"]})
    url = str(lapdog_agent.make_url("/")).rstrip("/")
    base = {"session_id": "resumed", "transcript_path": str(path), "cwd": str(tmp_path)}
    if resume_hook:
        await asyncio.to_thread(
            codex_hook.forward, url, {**base, "hook_event_name": "SessionStart", "source": "resume"}
        )
        assert (await (await lapdog_agent.get("/claude/hooks/spans")).json())["spans"] == []
    with path.open("a") as out:
        for r in [
            {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "new"}},
            {"type": "turn_context", "payload": {"turn_id": "new", "model": "gpt-5.5"}},
            {"type": "event_msg", "payload": {"type": "user_message", "message": "new question"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "pwd",
                    "name": "exec_command",
                    "arguments": '{"cmd":"pwd"}',
                },
            },
        ]:
            out.write(json.dumps({"timestamp": "2026-10-14T12:01:01Z", **r}) + "\n")
    await asyncio.to_thread(
        codex_hook.forward,
        url,
        {
            **base,
            "hook_event_name": "PostToolUse",
            "turn_id": "new",
            "tool_use_id": "pwd",
            "tool_name": "Bash",
            "tool_input": {"command": "pwd"},
            "tool_response": {"stdout": "/repo", "exitCode": 0},
        },
    )
    result = (await (await lapdog_agent.get("/claude/hooks/spans")).json())["spans"]
    roots = [s for s in result if s["name"] == "codex-request"]
    assert len(roots) == 1
    assert roots[0]["meta"]["metadata"]["turn_id"] == "new"
    assert roots[0]["meta"]["input"]["value"] == "new question"
    assert roots[0]["meta"]["metadata"]["codex_cli_version"] == "0.162.1"
    assert roots[0]["meta"]["metadata"]["reasoning_effort"] == "high"
    assert roots[0]["meta"]["metadata"]["session_name"] == (indexed_name or "Transcript session name")
    tools = [s for s in result if s["meta"]["span"]["kind"] == "tool"]
    assert len(tools) == 1 and tools[0]["meta"]["output"]["value"] == "/repo"
    assert "old answer" not in json.dumps(result)
    # A later resume on this collector does not reread or duplicate the old turns.
    await asyncio.to_thread(codex_hook.forward, url, {**base, "hook_event_name": "SessionStart", "source": "resume"})
    assert len((await (await lapdog_agent.get("/claude/hooks/spans")).json())["spans"]) == len(result)


@pytest.mark.parametrize(
    "order", [[], ["event_msg"], ["response_item"], ["event_msg", "response_item"], ["response_item", "event_msg"]]
)
def test_hook_prompt_survives_stop_and_transcript_duplicates(capture, order):
    hook(capture, "UserPromptSubmit", prompt="keep this prompt")
    turn = capture._sessions["parent"].active_turn
    for record_type in order:
        payload = (
            {"type": "user_message", "message": "keep this prompt"}
            if record_type == "event_msg"
            else {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "keep this prompt"}]}
        )
        capture._lifecycle.ingest(
            "parent", {"type": record_type, "timestamp": "2026-10-14T12:00:02Z", "payload": payload}
        )
    hook(capture, "Stop", seconds=3)
    session = capture._sessions["parent"]
    assert session.active_turn is turn
    assert session.user_prompts == ["keep this prompt"]
    assert turn.root_span_ref["meta"]["input"]["value"] == "keep this prompt"
    assert turn.llm_input_messages == [{"role": "user", "content": "keep this prompt"}]
    hook(capture, "UserPromptSubmit", turn="next-turn", seconds=4, prompt="keep this prompt")
    hook(capture, "Stop", turn="next-turn", seconds=5)
    assert session.active_turn is not turn
    assert session.active_turn.root_span_ref["meta"]["input"]["value"] == "keep this prompt"
