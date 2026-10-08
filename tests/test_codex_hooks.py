"""Tests for Codex JSONL hooks."""

import gzip
import json
import subprocess

import msgpack
import pytest

from lapdog.claude_hooks import ClaudeHooksAPI
from lapdog.codex_exec import display_tool_name
from lapdog.codex_exec import extract_exec_calls
from lapdog.codex_exec import extract_exec_results


@pytest.fixture
def agent(lapdog_agent):
    return lapdog_agent


@pytest.fixture
def dd_api_key():
    return ""


@pytest.fixture
def codex_env_overrides(monkeypatch):
    monkeypatch.setenv("DD_CLAUDE_CODE_ML_APP", "lapdog")
    monkeypatch.setenv("DD_CODEX_ML_APP", "codex-custom")
    monkeypatch.setenv("DD_USER_HANDLE", "shared-user")


async def _post(agent, session_id, record, *, backfill=False, proxy_session_key=None):
    body = {"session_id": session_id, "record": record}
    if backfill:
        body["backfill"] = True
    if proxy_session_key:
        body["proxy_session_key"] = proxy_session_key
    return await agent.post(
        "/codex/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
    )


def _spans(body):
    return body["spans"]


def _by_kind(spans, kind):
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _span_index(spans, span):
    return next(index for index, candidate in enumerate(spans) if candidate["span_id"] == span["span_id"])


def _session_meta(session_id="codex-sess"):
    return {
        "timestamp": "2026-05-11T17:00:00.000Z",
        "type": "session_meta",
        "payload": {
            "id": session_id,
            "cwd": "/repo",
            "originator": "codex-tui",
            "cli_version": "0.130.0",
            "model_provider": "openai",
        },
    }


def _turn_context(turn_id="turn-1"):
    return {
        "timestamp": "2026-05-11T17:00:01.000Z",
        "type": "turn_context",
        "payload": {
            "turn_id": turn_id,
            "cwd": "/repo",
            "model": "gpt-5.5",
            "effort": "medium",
        },
    }


def _turn_context_without_turn_id(timestamp="2026-05-11T17:00:01.000Z"):
    return {
        "timestamp": timestamp,
        "type": "turn_context",
        "payload": {
            "cwd": "/repo",
            "model": "gpt-5.5",
            "effort": "medium",
        },
    }


def _event(event_type, timestamp="2026-05-11T17:00:02.000Z", **kwargs):
    return {
        "timestamp": timestamp,
        "type": "event_msg",
        "payload": {
            "type": event_type,
            **kwargs,
        },
    }


def _response_item(item_type, timestamp="2026-05-11T17:00:03.000Z", **kwargs):
    return {
        "timestamp": timestamp,
        "type": "response_item",
        "payload": {
            "type": item_type,
            **kwargs,
        },
    }


async def test_codex_turn_llm_and_tool_spans(agent, pricing_catalog):
    sid = "codex-basic"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect this repo"))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg codex"}',
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 20,
                    "output_tokens": 30,
                    "reasoning_output_tokens": 5,
                    "total_tokens": 130,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call_output", call_id="call-1", output="matches"),
    )
    await _post(agent, sid, _event("agent_message", message="found it"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]

    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    root = roots[0]
    assert root["name"] == "codex-request"
    assert root["meta"]["input"]["value"] == "inspect this repo"
    assert root["meta"]["output"]["value"] == "found it"
    assert "source:codex-jsonl" in root["tags"]
    assert "trajectory.semantic_type:turn" in root["tags"]

    steps = _by_kind(session_spans, "step")
    llms = _by_kind(session_spans, "llm")
    tools = _by_kind(session_spans, "tool")
    assert len(steps) == 1
    assert len(llms) == 1
    assert len(tools) == 1
    assert steps[0]["parent_id"] == root["span_id"]
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["name"] == "List"
    assert "tool_name:List" in tools[0]["tags"]
    assert "tool_name:exec_command" not in tools[0]["tags"]
    assert llms[0]["meta"]["output"]["messages"][-1]["tool_calls"][0]["name"] == "List"
    assert root["meta"]["metadata"]["_dd"]["agent_manifest"]["tools"] == [{"name": "List"}]
    assert tools[0]["meta"]["input"]["value"] == '{"cmd": "rg codex"}'
    assert tools[0]["meta"]["output"]["value"] == "matches"
    assert llms[0]["metrics"]["input_tokens"] == 100
    assert llms[0]["metrics"]["output_tokens"] == 30
    assert llms[0]["metrics"]["reasoning_output_tokens"] == 5
    assert llms[0]["metrics"]["cache_read_input_tokens"] == 20
    assert llms[0]["metrics"]["non_cached_input_tokens"] == 80
    assert llms[0]["metrics"]["estimated_input_cost"] == 410_000
    assert llms[0]["metrics"]["estimated_output_cost"] == 900_000
    assert llms[0]["metrics"]["estimated_total_cost"] == 1_310_000


def test_codex_exec_extracts_literal_arguments_without_running_javascript():
    source = (
        "// tools.ignored({value: 1})\n"
        'const label = "tools.also_ignored({value: 2})";\n'
        "const results = await Promise.allSettled(["
        'tools.exec_command({cmd: "echo hi", yield_time_ms: 1000, login: false}),'
        'tools.web__run({search_query: [{q: "hello"}]})]);'
    )
    assert extract_exec_calls(source) == [
        {"name": "exec_command", "arguments": {"cmd": "echo hi", "yield_time_ms": 1000, "login": False}},
        {"name": "web__run", "arguments": {"search_query": [{"q": "hello"}]}},
    ]


def test_codex_exec_resolves_simple_patch_literal():
    source = 'const patch = "*** Begin Patch\\n*** End Patch"; await tools.apply_patch(patch);'
    assert extract_exec_calls(source) == [{"name": "apply_patch", "arguments": "*** Begin Patch\n*** End Patch"}]


@pytest.mark.parametrize(
    "command,expected",
    [
        ("cat README.md", "Read"),
        ("sed -n '1,20p' file.py", "Read"),
        ("/usr/bin/sed -n 1p file.py", "Read"),
        ("rg -n 'pattern' .", "List"),
        ("find . -name '*.py'", "List"),
        ("ls -la", "List"),
        ("cd /repo && rg pattern .", "List"),
        ("curl -fsS https://example.com", "Web"),
        ("echo sed", "Ran"),
        ("yarn lint", "Ran"),
    ],
)
def test_codex_shell_tool_name_uses_command(command, expected):
    assert display_tool_name("exec_command", {"cmd": command}) == expected


def test_codex_other_shell_tool_name_is_ran():
    assert display_tool_name("write_stdin", {"session_id": 123, "chars": ""}) == "Ran"


async def test_codex_exec_emits_nested_tool_spans(agent):
    sid = "codex-exec-nested"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect"))
    script = (
        "const r = await Promise.allSettled(["
        'tools.exec_command({cmd:"pwd"}),'
        'tools.web__run({search_query:[{q:"example"}]})]);'
        "r.forEach((x,i)=>text(JSON.stringify({i,...x})));"
    )
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="program-1", input=script))
    output = [
        {"type": "input_text", "text": "Script completed\nWall time 1.2 seconds\nOutput:\n"},
        {
            "type": "input_text",
            "text": json.dumps(
                {
                    "i": 0,
                    "status": "fulfilled",
                    "value": {
                        "exit_code": 0,
                        "output": "/repo",
                        "chunk_id": "chunk-1",
                        "wall_time_seconds": 0.25,
                        "original_token_count": 3,
                    },
                }
            ),
        },
        {
            "type": "input_text",
            "text": json.dumps(
                {"i": 1, "status": "fulfilled", "value": {"content": [{"type": "text", "text": "found"}]}}
            ),
        },
    ]
    await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program-1", output=output))
    await _post(agent, sid, _event("task_complete"))
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    tools = [span for span in _by_kind(spans, "tool") if span.get("session_id") == sid]
    assert [span["name"] for span in tools] == ["Ran", "Web"]
    root = next(span for span in spans if span.get("session_id") == sid and span["parent_id"] == "undefined")
    assert root["meta"]["metadata"]["tools"] == ["Ran", "Web"]
    assert [span["meta"]["metadata"]["raw_tool_name"] for span in tools] == ["exec_command", "web__run"]
    assert [span["meta"]["metadata"]["tool_id"] for span in tools] == ["program-1:0", "program-1:1"]
    assert json.loads(tools[0]["meta"]["input"]["value"]) == {"cmd": "pwd"}
    assert json.loads(tools[1]["meta"]["input"]["value"]) == {"search_query": [{"q": "example"}]}
    assert tools[0]["meta"]["output"]["value"] == "/repo"
    assert tools[0]["meta"]["metadata"]["exit_code"] == 0
    assert tools[0]["meta"]["metadata"]["chunk_id"] == "chunk-1"
    assert tools[0]["meta"]["metadata"]["wall_time_seconds"] == 0.25
    assert tools[0]["meta"]["metadata"]["original_token_count"] == 3
    assert "output" not in tools[0]["meta"]["metadata"]
    assert tools[1]["meta"]["metadata"]["result_matched"] is True


async def test_codex_exec_does_not_guess_which_parallel_call_owns_unindexed_output(agent):
    sid = "codex-exec-unmatched"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect"))
    script = 'await Promise.all([tools.exec_command({cmd:"pwd"}), tools.exec_command({cmd:"ls"})]); text("summary");'
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="program-2", input=script))
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            call_id="program-2",
            output=[
                {"type": "input_text", "text": "Script completed\nWall time 1.2 seconds\nOutput:\n"},
                {"type": "input_text", "text": "summary"},
            ],
        ),
    )
    await _post(agent, sid, _event("task_complete"))
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    tools = [span for span in _by_kind(spans, "tool") if span.get("session_id") == sid]
    assert len(tools) == 2
    assert [span["meta"]["metadata"]["result_matched"] for span in tools] == [False, False]
    assert [span["meta"]["output"]["value"] for span in tools] == ["", ""]


@pytest.mark.parametrize("combined", [False, True])
def test_codex_exec_sequential_outputs(combined):
    script = "text(await tools.clock__curr_time({})); text(await tools.get_goal({}));"
    values = [{"current_time": "2026-10-08 19:33:25 UTC"}, {"goal": None}]
    blocks = [json.dumps(value) for value in values]
    if combined:
        blocks = ["\n".join(blocks)]
    output = [{"type": "input_text", "text": "Script completed\nOutput:\n"}]
    output.extend({"type": "input_text", "text": block} for block in blocks)
    results = extract_exec_results(output, 2, source=script)
    assert [json.loads(r["value"]) if isinstance(r["value"], str) else r["value"] for r in results.values()] == values


def test_codex_exec_combined_indexed_outputs():
    output = [{"type": "input_text", "text": '{"i":1,"value":"second"}\n{"i":0,"value":"first"}'}]
    assert extract_exec_results(output, 2) == {0: {"value": "first"}, 1: {"value": "second"}}


def test_codex_exec_named_parallel_outputs_survive_truncated_neighbor():
    script = """const calls = [
        ["clock.curr_time", () => tools.clock__curr_time({})],
        ["get_goal", () => tools.get_goal({})],
        ["list_mcp_resources", () => tools.list_mcp_resources({})],
        ["chrome_devtools.list_pages", () => tools.mcp__chrome_devtools__list_pages({})]
    ];"""
    output = [
        {
            "type": "input_text",
            "text": (
                "Warning: truncated output (original token count: 13039)\nTotal output lines: 4\n\n"
                '{"name":"clock.curr_time","status":"fulfilled","value":{"name":"clock.curr_time","result":{"current_time":"now"}}}\n'
                '{"name":"list_mcp_resources","status":"fulfilled","value": …truncated…}\n'
                '{"name":"get_goal","status":"fulfilled","value":{"name":"get_goal","result":{"goal":null}}}\n'
                '{"name":"chrome_devtools.list_pages","status":"rejected","reason":"unavailable"}'
            ),
        }
    ]
    assert extract_exec_results(output, 4, source=script) == {
        0: {"value": {"current_time": "now"}},
        1: {"value": {"goal": None}},
        3: {"value": "unavailable", "error": True},
    }


@pytest.mark.parametrize(
    "status,key,value", [("fulfilled", "value", "web output"), ("rejected", "reason", "web error")]
)
def test_codex_exec_tool_label_with_nested_settled_result(status, key, value):
    source = 'tools.read_mcp_resource({server:"trajectory",uri:"trajectory://sqlite/schema"}); tools.web__run({});'
    output = [
        {
            "type": "input_text",
            "text": (
                "Warning: truncated output (original token count: 14349)\nTotal output lines: 2\n\n"
                '{"tool":"read_mcp_resource","result": …truncated…}\n'
                + json.dumps({"tool": "web.run", "result": {"status": status, key: value}})
            ),
        }
    ]
    expected = {"value": value}
    if status == "rejected":
        expected["error"] = True
    assert extract_exec_results(output, 2, source=source) == {1: expected}


def test_codex_exec_named_output_does_not_guess_between_repeated_tools():
    script = 'tools.exec_command({cmd:"pwd"}); tools.exec_command({cmd:"ls"});'
    output = [{"type": "input_text", "text": '{"name":"exec_command","value":"ambiguous"}'}]
    assert extract_exec_results(output, 2, source=script) == {}


@pytest.mark.parametrize("field", ["value", "result"])
def test_codex_exec_named_top_level_result(field):
    source = "tools.clock__curr_time({}); tools.get_goal({});"
    values = [{"current_time": "now"}, {"goal": None, "remainingTokens": None, "completionBudgetReport": None}]
    output = [
        {"type": "input_text", "text": json.dumps({"name": name, "status": "fulfilled", field: json.dumps(value)})}
        for name, value in zip(("clock__curr_time", "get_goal"), values)
    ]
    assert [json.loads(r["value"]) for r in extract_exec_results(output, 2, source=source).values()] == values


def test_codex_exec_native_results_with_unrelated_prints():
    source = "text(ALL_TOOLS); text(await tools.clock__curr_time({})); text(await tools.get_goal({}));"
    goal = {"goal": None, "remainingTokens": None, "completionBudgetReport": None}
    output = [
        {"type": "input_text", "text": json.dumps(value)}
        for value in (
            {"name": "clock__curr_time", "description": "Tool description"},
            {"current_time": "now"},
            goal,
        )
    ]
    assert extract_exec_results(output, 2, source=source) == {0: {"value": {"current_time": "now"}}, 1: {"value": goal}}


def test_codex_exec_truncated_sequential_outputs_keep_intact_lines():
    script = "text(await tools.clock__curr_time({})); text(await tools.list_mcp_resources({})); text(await tools.get_goal({}));"
    output = [
        {
            "type": "input_text",
            "text": (
                "Warning: truncated output (original token count: 12000)\nTotal output lines: 3\n\n"
                '{"current_time":"now"}\n{"resources":[…truncated…]}\n{"goal":null}'
            ),
        }
    ]
    assert extract_exec_results(output, 3, source=script) == {
        0: {"value": {"current_time": "now"}},
        2: {"value": {"goal": None}},
    }


@pytest.mark.parametrize(
    "script",
    [
        'await Promise.all([tools.a({}), tools.b({})]); text("first"); text("second");',
        'text(await tools.a({})); text("extra"); text(await tools.b({}));',
    ],
)
def test_codex_exec_does_not_assign_arbitrary_prints_by_position(script):
    output = [{"type": "input_text", "text": '"first"\n"second"'}]
    assert extract_exec_results(output, 2, source=script) == {}


@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("late", [False, True])
async def test_codex_exec_uses_command_completion_outputs_in_reverse_order(agent, exit_code, late):
    sid = "codex-command-completions"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect"))
    script = 'await Promise.all([tools.exec_command({cmd:"cat README.md"}), tools.exec_command({cmd:"pwd"})]);'
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="program", input=script))
    if late:
        await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program", output="summary"))
    for command, output in [("pwd", "/repo\n"), ("cat README.md", "file contents\n")]:
        await _post(
            agent,
            sid,
            _event(
                "item_completed",
                item={
                    "type": "CommandExecution",
                    "id": command,
                    "command": ["/bin/zsh", "-lc", command],
                    "aggregated_output": output,
                    "exit_code": exit_code,
                    "status": "completed",
                },
            ),
        )
    if not late:
        await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program", output="summary"))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert [span["name"] for span in tools] == ["Read", "Ran"]
    assert [span["meta"]["output"]["value"] for span in tools] == ["file contents\n", "/repo\n"]
    assert all(span["meta"]["metadata"]["exit_code"] == exit_code for span in tools)
    assert all(span["meta"]["metadata"]["result_source"] == "item_completed" for span in tools)
    assert all(span["status"] == ("error" if exit_code else "ok") for span in tools)


@pytest.mark.parametrize("resource", [False, True])
async def test_codex_exec_uses_mcp_completion_output(agent, resource):
    sid = "codex-mcp-completion"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect"))
    tool_name = "read_mcp_resource" if resource else "mcp__example__lookup"
    inputs = [{"server": "example", "uri": f"example://{i}"} if resource else {"id": i} for i in (1, 2)]
    script = "await Promise.all([" + ",".join(f"tools.{tool_name}({json.dumps(args)})" for args in inputs) + "]);"
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="program", input=script))
    for index in (2, 1):
        await _post(
            agent,
            sid,
            _event(
                "item_completed",
                item={
                    "type": "McpToolCall",
                    "id": str(index),
                    "server": "example",
                    "tool": "read_mcp_resource" if resource else "lookup",
                    "arguments": inputs[index - 1],
                    "status": "completed",
                    "result": {"content": [{"type": "text", "text": f"result {index}"}], "isError": False},
                },
            ),
        )
    await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program", output="summary"))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 2
    assert [json.loads(span["meta"]["output"]["value"])["content"][0]["text"] for span in tools] == [
        "result 1",
        "result 2",
    ]


async def test_codex_exec_does_not_assign_ambiguous_completion(agent):
    sid = "codex-ambiguous-completion"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="inspect"))
    script = 'await Promise.all([tools.exec_command({cmd:"pwd"}), tools.exec_command({cmd:"pwd"})]);'
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="program", input=script))
    await _post(
        agent,
        sid,
        _event(
            "item_completed",
            item={
                "type": "CommandExecution",
                "command": ["/bin/zsh", "-lc", "pwd"],
                "aggregated_output": "/repo\n",
                "exit_code": 0,
                "status": "completed",
            },
        ),
    )
    await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program", output="summary"))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 2
    assert all(span["meta"]["metadata"]["result_matched"] is False for span in tools)


async def test_codex_shell_poll_updates_original_command_span(agent):
    sid = "codex-shell-poll"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="run the check"))
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            timestamp="2026-05-11T17:00:03.000Z",
            name="exec",
            call_id="program-command",
            input='const r = await tools.exec_command({cmd:"yarn lint"}); text(JSON.stringify({i:0,status:"fulfilled",value:r}));',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="program-command",
            output=[
                {"type": "input_text", "text": "Script completed\nWall time 1.0 seconds\nOutput:\n"},
                {
                    "type": "input_text",
                    "text": json.dumps(
                        {"i": 0, "status": "fulfilled", "value": {"session_id": 74738, "output": "started\n"}}
                    ),
                },
            ],
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            timestamp="2026-05-11T17:00:05.000Z",
            name="exec",
            call_id="program-poll",
            input='const r = await tools.write_stdin({session_id:74738,chars:"",yield_time_ms:1000}); text(JSON.stringify({i:0,status:"fulfilled",value:r}));',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            timestamp="2026-05-11T17:00:07.000Z",
            call_id="program-poll",
            output=[
                {"type": "input_text", "text": "Script completed\nWall time 2.0 seconds\nOutput:\n"},
                {
                    "type": "input_text",
                    "text": json.dumps(
                        {"i": 0, "status": "fulfilled", "value": {"exit_code": 0, "output": "lint passed\n"}}
                    ),
                },
            ],
        ),
    )
    await _post(agent, sid, _event("task_complete", timestamp="2026-05-11T17:00:08.000Z"))
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    tools = [span for span in _by_kind(spans, "tool") if span.get("session_id") == sid]
    assert len(tools) == 1
    assert tools[0]["name"] == "Ran"
    assert json.loads(tools[0]["meta"]["input"]["value"]) == {"cmd": "yarn lint"}
    assert tools[0]["meta"]["output"]["value"] == "started\nlint passed\n"
    assert tools[0]["meta"]["metadata"]["session_id"] == 74738
    assert tools[0]["meta"]["metadata"]["exit_code"] == 0
    assert tools[0]["meta"]["metadata"]["poll_count"] == 1
    assert tools[0]["duration"] == 4_000_000_000


@pytest.mark.parametrize("complete", [True, False])
async def test_codex_exec_wrapper_without_nested_calls_never_becomes_tool_span(agent, complete):
    sid = "codex-exec-empty-" + str(complete)
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="calculate"))
    await _post(
        agent,
        sid,
        _response_item("custom_tool_call", name="exec", call_id="program-empty", input="text(1 + 1)"),
    )
    if complete:
        await _post(agent, sid, _response_item("custom_tool_call_output", call_id="program-empty", output="2"))
    await _post(agent, sid, _event("task_complete"))
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    assert [span for span in _by_kind(spans, "tool") if span.get("session_id") == sid] == []


async def test_codex_response_item_user_message_sets_root_input(agent):
    sid = "codex-response-item-user"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            role="user",
            content=[
                {"type": "input_text", "text": "<image name=example.png>"},
                {"type": "input_image", "image_url": "data:image/png;base64,example"},
                {"type": "input_text", "text": "inspect this image"},
            ],
            internal_chat_message_metadata_passthrough={"content_item_kinds": ["user.text", "user.image", "user.text"]},
        ),
    )
    await _post(agent, sid, _event("task_complete", last_agent_message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert root["meta"]["input"]["value"] == "<image name=example.png>\n\ninspect this image"


async def test_codex_response_item_ignores_injected_user_context_and_deduplicates_legacy_event(agent):
    sid = "codex-response-item-user-filtering"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            role="user",
            content=[{"type": "input_text", "text": "# AGENTS.md instructions"}],
            internal_chat_message_metadata_passthrough={"content_item_kinds": ["agents_md.instructions"]},
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            role="user",
            content=[{"type": "input_text", "text": "inspect this repo"}],
            internal_chat_message_metadata_passthrough={"content_item_kinds": ["user.text"]},
        ),
    )
    await _post(agent, sid, _event("user_message", message="inspect this repo"))
    await _post(agent, sid, _event("task_complete", last_agent_message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == "inspect this repo"


async def test_codex_repeated_legacy_prompt_starts_a_new_trace(agent):
    sid = "codex-repeated-legacy-prompt"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:01.000Z", message="continue"))
    await _post(
        agent,
        sid,
        _event("task_complete", timestamp="2026-05-11T17:00:02.000Z", last_agent_message="first done"),
    )
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:03.000Z", message="continue"))
    await _post(
        agent,
        sid,
        _event("task_complete", timestamp="2026-05-11T17:00:04.000Z", last_agent_message="second done"),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 2
    assert [root["meta"]["input"]["value"] for root in roots] == ["continue", "continue"]


async def test_codex_repeated_response_item_prompt_starts_a_new_trace(agent):
    sid = "codex-repeated-response-item-prompt"
    prompt = {
        "role": "user",
        "content": [{"type": "input_text", "text": "continue"}],
        "internal_chat_message_metadata_passthrough": {"content_item_kinds": ["user.text"]},
    }
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _response_item("message", timestamp="2026-05-11T17:00:01.000Z", **prompt))
    await _post(
        agent,
        sid,
        _event("task_complete", timestamp="2026-05-11T17:00:02.000Z", last_agent_message="first done"),
    )
    await _post(agent, sid, _response_item("message", timestamp="2026-05-11T17:00:03.000Z", **prompt))
    await _post(
        agent,
        sid,
        _event("task_complete", timestamp="2026-05-11T17:00:04.000Z", last_agent_message="second done"),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 2
    assert [root["meta"]["input"]["value"] for root in roots] == ["continue", "continue"]


async def test_codex_session_tags_apply_to_existing_and_future_spans(agent):
    sid = "codex-custom-tags"
    session_token = "codex-launch-token"
    await _post(agent, sid, _session_meta(sid), proxy_session_key=session_token)
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="tag this Codex session"))

    response = await agent.get("/claude/hooks/spans")
    spans_before_tags = [span for span in _spans(await response.json()) if span.get("session_id") == sid]
    assert spans_before_tags

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={
            "session_id": sid,
            "tags": {"dd_auto_experiment_id": "experiment-id", "iteration": "2"},
        },
    )
    assert response.status == 200, await response.text()

    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            name="exec_command",
            call_id="call-after-tags",
            arguments='{"cmd": "pwd"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call_output", call_id="call-after-tags", output="/repo"),
    )
    await _post(agent, sid, _event("agent_message", message="done"))

    response = await agent.get("/claude/hooks/spans")
    session_spans = [span for span in _spans(await response.json()) if span.get("session_id") == sid]
    assert len(session_spans) > len(spans_before_tags)
    for span in session_spans:
        assert "dd_auto_experiment_id:experiment-id" in span["tags"]
        assert "iteration:2" in span["tags"]


async def test_codex_raw_events_redact_launch_token(agent):
    session_id = "codex-redacted-launch-token"
    await _post(
        agent,
        session_id,
        _session_meta(session_id),
        proxy_session_key="codex-secret-launch-token",
    )

    response = await agent.get("/codex/hooks/raw")
    assert response.status == 200
    raw_events = (await response.json())["events"]
    assert raw_events
    assert all("proxy_session_key" not in event for event in raw_events)
    assert "codex-secret-launch-token" not in json.dumps(raw_events)


async def test_codex_session_tags_target_only_requested_thread(agent):
    session_token = "shared-codex-app-token"
    targeted_sid = "codex-app-targeted"
    unrelated_sid = "codex-app-unrelated"
    for sid in (targeted_sid, unrelated_sid):
        await _post(agent, sid, _session_meta(sid), proxy_session_key=session_token)
        await _post(agent, sid, _turn_context(f"{sid}-turn"))
        await _post(agent, sid, _event("user_message", message=sid))

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"session_id": targeted_sid, "tags": {"iteration": "2"}},
    )
    assert response.status == 200, await response.text()
    assert (await response.json())["session_ids"] == [targeted_sid]

    for sid in (targeted_sid, unrelated_sid):
        await _post(
            agent,
            sid,
            _response_item(
                "function_call",
                name="exec_command",
                call_id=f"{sid}-call",
                arguments='{"cmd": "pwd"}',
            ),
        )
        await _post(
            agent,
            sid,
            _response_item("function_call_output", call_id=f"{sid}-call", output="/repo"),
        )

    response = await agent.get("/claude/hooks/spans")
    spans = _spans(await response.json())
    targeted_spans = [span for span in spans if span.get("session_id") == targeted_sid]
    unrelated_spans = [span for span in spans if span.get("session_id") == unrelated_sid]
    assert targeted_spans
    assert unrelated_spans
    assert all("iteration:2" in span["tags"] for span in targeted_spans)
    assert all("iteration:2" not in span["tags"] for span in unrelated_spans)


async def test_codex_session_tags_can_target_thread_before_watcher_posts(agent):
    sid = "codex-app-watcher-race"
    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": "app-launch-token"},
        json={"session_id": sid, "tags": {"iteration": "2"}},
    )
    assert response.status == 200, await response.text()
    assert (await response.json())["session_id"] == sid

    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="watcher arrived"))

    response = await agent.get("/claude/hooks/spans")
    session_spans = [span for span in _spans(await response.json()) if span.get("session_id") == sid]
    assert session_spans
    assert all("iteration:2" in span["tags"] for span in session_spans)


async def test_codex_project_metadata_from_session_git(agent):
    sid = "codex-project-metadata"
    session_meta = _session_meta(sid)
    session_meta["git"] = {"repository_url": "git@github.com:DataDog/dd-apm-test-agent.git"}

    await _post(agent, sid, session_meta)
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="hello"))
    await _post(agent, sid, _event("agent_message", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert "project_name:dd-apm-test-agent" in root["tags"]
    assert "git.repository_url:github.com/DataDog/dd-apm-test-agent" in root["tags"]
    assert root["meta"]["metadata"]["project_name"] == "dd-apm-test-agent"
    assert root["meta"]["metadata"]["git_repository_url"] == "github.com/DataDog/dd-apm-test-agent"
    assert not any("commit" in tag for span in session_spans for tag in span.get("tags", []))
    assert not any("commit" in key for key in root["meta"]["metadata"])


async def test_codex_project_metadata_uses_local_git_fallback(agent, tmp_path, monkeypatch):
    from lapdog.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "qa@local"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "QA"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/DataDog/local-codex-repo.git"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    (tmp_path / "README.md").write_text("# repo\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp_path, check=True, capture_output=True)
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    sid = "codex-local-git-project"
    session_meta = _session_meta(sid)
    session_meta["payload"]["cwd"] = str(tmp_path)
    turn_context = _turn_context()
    turn_context["payload"]["cwd"] = str(tmp_path)

    await _post(agent, sid, session_meta)
    await _post(agent, sid, turn_context)
    await _post(agent, sid, _event("user_message", message="hello"))
    await _post(agent, sid, _event("agent_message", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert "project_name:local-codex-repo" in root["tags"]
    assert "git.repository_url:github.com/DataDog/local-codex-repo" in root["tags"]
    assert f"git.commit.sha:{sha}" in root["tags"]


async def test_codex_project_metadata_uses_cwd_basename_without_git(agent, tmp_path, monkeypatch):
    from lapdog.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    cwd = tmp_path / "plain-codex-project"
    cwd.mkdir()

    sid = "codex-no-git-project"
    session_meta = _session_meta(sid)
    session_meta["payload"]["cwd"] = str(cwd)
    turn_context = _turn_context()
    turn_context["payload"]["cwd"] = str(cwd)

    await _post(agent, sid, session_meta)
    await _post(agent, sid, turn_context)
    await _post(agent, sid, _event("user_message", message="hello"))
    await _post(agent, sid, _event("agent_message", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert "project_name:plain-codex-project" in root["tags"]
    assert not any(tag.startswith("git.repository_url:") for tag in root["tags"])
    assert root["meta"]["metadata"]["project_name"] == "plain-codex-project"
    assert "git_repository_url" not in root["meta"]["metadata"]


async def test_codex_tool_status_reasoning_and_large_output_are_tracked_safely(agent):
    sid = "codex-status-reasoning"
    large_output = "x" * 9000
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="run it"))
    await _post(
        agent,
        sid,
        _response_item(
            "reasoning",
            timestamp="2026-05-11T17:00:03.000Z",
            id="rs_1",
            status="completed",
            summary=[{"type": "summary_text", "text": "Need shell output"}],
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "make test"}',
            status="in_progress",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:06.000Z",
            call_id="call-1",
            output=large_output,
            status="failed",
        ),
    )
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:07.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:08.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "failed"}],
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:09.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 120,
                    "cached_input_tokens": 0,
                    "output_tokens": 5,
                    "total_tokens": 125,
                }
            },
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llms = sorted(_by_kind(session_spans, "llm"), key=lambda s: s["start_ns"])
    tool = _by_kind(session_spans, "tool")[0]

    tool_call = llms[0]["meta"]["output"]["messages"][0]["tool_calls"][0]
    assert tool_call["status"] == "failed"
    assert tool_call["reasoning"][0]["id"] == "rs_1"
    assert tool_call["reasoning"][0]["text"] == "Need shell output"
    assert llms[0]["meta"]["metadata"]["reasoning"][0]["text"] == "Need shell output"

    assert tool["status"] == "error"
    assert tool["meta"]["metadata"]["status"] == "failed"
    assert tool["meta"]["metadata"]["reasoning"][0]["text"] == "Need shell output"
    assert tool["meta"]["metadata"]["output_format"] == "verbatim"
    assert tool["meta"]["metadata"]["_dd"]["display"]["output"] == "code"
    assert "[truncated " in tool["meta"]["output"]["value"]
    assert len(tool["meta"]["output"]["value"]) < len(large_output)

    tool_input_message = llms[1]["meta"]["input"]["messages"][-1]
    assert tool_input_message["role"] == "tool"
    assert tool_input_message["status"] == "failed"
    assert "[truncated " in tool_input_message["content"]
    assert len(tool_input_message["content"]) < len(large_output)


async def test_codex_active_turn_keeps_root_duration_zero_for_live_badge(agent):
    sid = "codex-live-root-duration"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="run it"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = [s for s in session_spans if s["parent_id"] == "undefined"][0]
    assert root["duration"] == 0
    trace_id = root["trace_id"]

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@trace_id:{trace_id} @parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 0

    resp = await agent.get(f"/api/ui/llm-obs/v1/trace/{trace_id}")
    assert resp.status == 200
    data = await resp.json()
    attrs = data["data"]["attributes"]
    assert attrs["spans"][attrs["root_id"]]["duration"] == 0

    await _post(
        agent,
        sid,
        _event("task_complete", timestamp="2026-05-11T17:00:05.000Z", last_agent_message="done"),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = [s for s in session_spans if s["parent_id"] == "undefined"][0]
    assert root["duration"] == 4_000_000_000

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@trace_id:{trace_id} @parent_id:undefined"}, "limit": 50}},
    )
    assert resp.status == 200
    data = await resp.json()
    assert data["result"]["events"][0]["event"]["custom"]["duration"] == 4_000_000_000


async def test_codex_pending_tool_is_marked_failed_when_turn_ends(agent):
    sid = "codex-pending-tool-status"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="run it"))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:03.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "sleep 100"}',
            status="in_progress",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:04.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(agent, sid, _event("turn_aborted", timestamp="2026-05-11T17:00:05.000Z"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llm = _by_kind(session_spans, "llm")[0]
    tool = _by_kind(session_spans, "tool")[0]

    tool_call = llm["meta"]["output"]["messages"][0]["tool_calls"][0]
    assert tool_call["status"] == "failed"
    assert tool["status"] == "error"
    assert tool["meta"]["metadata"]["status"] == "failed"


async def test_codex_real_turn_context_without_id_does_not_split_turn(agent):
    sid = "codex-real-turn-order"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:01.000Z", message="list files"))
    await _post(agent, sid, _turn_context_without_turn_id(timestamp="2026-05-11T17:00:01.100Z"))
    await _post(agent, sid, _event("task_started", timestamp="2026-05-11T17:00:01.200Z", turn_id="turn-real"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="README.md"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 1
    assert roots[0]["meta"]["metadata"]["turn_id"] == "turn-real"
    assert roots[0]["meta"]["input"]["value"] == "list files"
    assert roots[0]["meta"]["output"]["value"] == "README.md"
    assert roots[0]["meta"]["model_name"] == "gpt-5.5"


async def test_codex_handles_real_tool_and_permission_event_types(agent):
    sid = "codex-real-tool-types"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="patch and search"))
    await _post(agent, sid, _response_item("web_search_call", call_id="web_search_1", status="completed"))
    await _post(
        agent,
        sid,
        _event(
            "apply_patch_approval_request",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="patch-approval-1",
            reason="write access",
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="custom-1",
            name="apply_patch",
            input="*** Begin Patch ***",
            status="completed",
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="custom-1",
            output="Success",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "patch_apply_end",
            timestamp="2026-05-11T17:00:05.000Z",
            call_id="patch-approval-1",
            stdout="Success. Updated files.",
            stderr="",
            success=True,
            changes={"/repo/main.py": {"type": "modify", "content": "print('ok')"}},
            status="completed",
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")
    tools = _by_kind(session_spans, "tool")

    assert [tool["name"] for tool in tools] == ["web_search", "apply_patch", "apply_patch"]
    assert tools[0]["meta"]["metadata"]["tool_id"] == "web_search_1"
    assert tools[1]["meta"]["output"]["value"] == "Success"
    assert tools[2]["meta"]["input"]["value"] == "/repo/main.py"
    approvals = root["meta"]["metadata"]["_dd"]["codex_approvals"]
    assert approvals[0]["tool"] == "apply_patch"
    assert approvals[0]["call_id"] == "patch-approval-1"


async def test_codex_populates_step_and_late_llm_output(agent):
    sid = "codex-late-output"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:04.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 2,
                    "total_tokens": 12,
                }
            },
        ),
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="Hello."))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    step = _by_kind(session_spans, "step")[0]
    llm = _by_kind(session_spans, "llm")[0]

    assert step["meta"]["input"]["value"] == "hello"
    assert step["meta"]["output"]["value"] == "Hello."
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "hello"}]
    assert llm["meta"]["output"]["messages"] == [{"role": "assistant", "content": "Hello."}]


async def test_codex_ignores_token_usage_without_model_output(agent):
    sid = "codex-empty-usage"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:03.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 10,
                }
            },
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llms = _by_kind(session_spans, "llm")

    assert llms == []
    assert all(span["name"] != "codex-model" for span in session_spans)


async def test_codex_duplicate_usage_does_not_create_second_llm_in_step(agent):
    sid = "codex-duplicate-usage"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:04.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "Hello."}],
        ),
    )
    usage_event = _event(
        "token_count",
        timestamp="2026-05-11T17:00:05.000Z",
        info={
            "last_token_usage": {
                "input_tokens": 10,
                "cached_input_tokens": 0,
                "output_tokens": 2,
                "total_tokens": 12,
            }
        },
    )
    await _post(agent, sid, usage_event)
    await _post(agent, sid, {**usage_event, "timestamp": "2026-05-11T17:00:06.000Z"})

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = _by_kind(session_spans, "step")
    llms = _by_kind(session_spans, "llm")

    assert len(steps) == 1
    assert len(llms) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]


async def test_codex_creates_step_and_llm_span_per_model_call(agent):
    sid = "codex-multi-llm"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="use a tool"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "pwd"}',
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 20,
                    "output_tokens": 10,
                    "reasoning_output_tokens": 4,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:07.000Z",
            call_id="call-1",
            output="/repo",
        ),
    )
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:08.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:10.000Z",
            role="assistant",
            content=[{"type": "output_text", "text": "done"}],
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:11.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 120,
                    "cached_input_tokens": 30,
                    "output_tokens": 20,
                    "reasoning_output_tokens": 5,
                    "total_tokens": 140,
                }
            },
        ),
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:12.000Z", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = sorted(_by_kind(session_spans, "step"), key=lambda s: s["name"])
    llms = sorted(_by_kind(session_spans, "llm"), key=lambda s: s["start_ns"])
    tools = _by_kind(session_spans, "tool")

    assert [s["name"] for s in steps] == ["inference-0", "inference-1"]
    assert len(llms) == 2
    assert len(tools) == 1
    assert llms[0]["parent_id"] == steps[0]["span_id"]
    assert tools[0]["parent_id"] == steps[0]["span_id"]
    assert llms[1]["parent_id"] == steps[1]["span_id"]
    assert llms[0]["duration"] == 2_000_000_000
    assert llms[1]["duration"] == 3_000_000_000
    assert steps[0]["duration"] == 4_000_000_000
    assert steps[1]["duration"] == 3_000_000_000
    assert llms[0]["metrics"]["output_tokens"] == 10
    assert llms[1]["metrics"]["output_tokens"] == 20
    assert llms[1]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "done"}]
    assert steps[0]["meta"]["input"]["value"] == "use a tool"
    assert json.loads(steps[1]["meta"]["input"]["value"]) == [
        {"role": "user", "content": "use a tool"},
        {"role": "tool", "tool_call_id": "call-1", "content": "/repo", "status": "completed"},
    ]
    assert steps[0]["meta"]["output"]["value"] == '{"cmd": "pwd"}'
    assert llms[0]["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "pwd"}',
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "Ran",
                    "arguments": {"cmd": "pwd"},
                    "status": "completed",
                }
            ],
        }
    ]
    assert llms[1]["meta"]["input"]["messages"][-2:] == [
        {
            "role": "assistant",
            "content": '{"cmd": "pwd"}',
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "Ran",
                    "arguments": {"cmd": "pwd"},
                    "status": "completed",
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call-1", "content": "/repo", "status": "completed"},
    ]
    assert tools[0]["meta"]["metadata"]["status"] == "completed"


async def test_codex_orders_tool_call_llm_before_tool_when_usage_arrives_late(agent):
    sid = "codex-late-usage-tool"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="list files"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:04.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg --files"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:04.300Z",
            call_id="call-1",
            output="README.md",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    llm = _by_kind(session_spans, "llm")[0]
    tool = _by_kind(session_spans, "tool")[0]

    assert _span_index(session_spans, llm) < _span_index(session_spans, tool)
    assert llm["meta"]["input"]["messages"] == [{"role": "user", "content": "list files"}]
    assert llm["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "rg --files"}',
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "List",
                    "arguments": {"cmd": "rg --files"},
                    "status": "completed",
                }
            ],
        }
    ]
    assert tool["meta"]["metadata"]["status"] == "completed"


async def test_codex_late_tool_call_stays_in_completed_llm_step(agent):
    sid = "codex-late-tool-call"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="list files"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:04.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 100,
                    "cached_input_tokens": 0,
                    "output_tokens": 10,
                    "total_tokens": 110,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:05.000Z",
            name="exec_command",
            call_id="call-1",
            arguments='{"cmd": "rg --files"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:06.000Z",
            call_id="call-1",
            output="README.md",
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    steps = _by_kind(session_spans, "step")
    llm = _by_kind(session_spans, "llm")[0]
    tool = _by_kind(session_spans, "tool")[0]

    assert len(steps) == 1
    assert llm["parent_id"] == steps[0]["span_id"]
    assert tool["parent_id"] == steps[0]["span_id"]
    assert llm["meta"]["output"]["messages"] == [
        {
            "role": "assistant",
            "content": '{"cmd": "rg --files"}',
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "List",
                    "arguments": {"cmd": "rg --files"},
                    "status": "completed",
                }
            ],
        }
    ]
    assert tool["meta"]["metadata"]["status"] == "completed"


async def test_codex_new_turn_finalizes_previous_turn(agent):
    sid = "codex-two-turns"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", message="first"))
    await _post(agent, sid, _event("agent_message", message="done first"))
    await _post(agent, sid, _turn_context("turn-b"))
    await _post(agent, sid, _event("user_message", message="second"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    first = next(s for s in roots if s["meta"]["metadata"]["turn_id"] == "turn-a")
    second = next(s for s in roots if s["meta"]["metadata"]["turn_id"] == "turn-b")
    assert first["duration"] > 0
    assert first["meta"]["output"]["value"] == "done first"
    assert second["meta"]["input"]["value"] == "second"


async def test_codex_task_started_creates_turn_before_user_message(agent):
    sid = "codex-task-started-turn"
    turn_id = "task-turn-a"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _event("task_started", timestamp="2026-05-11T17:00:01.000Z", turn_id=turn_id))
    await _post(agent, sid, _turn_context(turn_id))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="first"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:03.000Z", message="done first"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 1
    assert roots[0]["meta"]["metadata"]["turn_id"] == turn_id
    assert roots[0]["meta"]["input"]["value"] == "first"
    assert roots[0]["meta"]["output"]["value"] == "done first"


async def test_codex_task_started_keeps_parent_turn_when_child_replays_same_turn(agent):
    parent_sid = "codex-parent-review-turn"
    child_sid = "codex-child-review-turn"
    turn_id = "shared-review-turn"

    await _post(agent, parent_sid, _session_meta(parent_sid))
    await _post(agent, parent_sid, _event("task_started", timestamp="2026-05-11T17:00:01.000Z", turn_id=turn_id))
    await _post(agent, parent_sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="review"))

    await _post(agent, child_sid, _session_meta(child_sid))
    await _post(agent, child_sid, _event("task_started", timestamp="2026-05-11T17:00:03.000Z", turn_id=turn_id))
    await _post(agent, child_sid, _turn_context(turn_id))
    await _post(agent, child_sid, _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="replay"))
    await _post(agent, child_sid, _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="child"))

    await _post(agent, parent_sid, _event("agent_message", timestamp="2026-05-11T17:00:06.000Z", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    parent_roots = [s for s in spans if s.get("session_id") == parent_sid and s["parent_id"] == "undefined"]

    assert len(parent_roots) == 1
    assert parent_roots[0]["meta"]["metadata"]["turn_id"] == turn_id
    assert parent_roots[0]["meta"]["input"]["value"] == "review"
    assert parent_roots[0]["meta"]["output"]["value"] == "done"
    assert [s for s in spans if s.get("session_id") == child_sid] == []


@pytest.mark.parametrize("batched", [False, True])
async def test_codex_guardian_reviews_annotate_only_parent_tools(agent, pricing_catalog, batched):
    parent_sid = "codex-parent-with-reviews"
    review_sid = "codex-guardian-review"
    await _post(agent, parent_sid, _session_meta(parent_sid))
    await _post(agent, parent_sid, _turn_context("parent-turn"))
    await _post(agent, parent_sid, _event("user_message", message="check the file"))
    review_meta = _session_meta(review_sid)
    review_meta["payload"].update({"thread_source": "guardian_review", "parent_thread_id": parent_sid})
    await _post(agent, review_sid, review_meta)

    command = "node --check my-agent.js" if not batched else "node --check my-agent.js\nprintf 'done'"
    script = "tools.exec_command(" + json.dumps({"cmd": command}) + ")"
    if batched:
        script = "tools.clock__curr_time({}); " + script
    for index, minute in enumerate(("00", "01"), 1):
        call_id = f"exec-{index}"
        requested = f"2026-05-11T17:{minute}:03.000Z"
        started = f"2026-05-11T17:{minute}:03.100Z"
        finished = f"2026-05-11T17:{minute}:04.000Z"
        returned = f"2026-05-11T17:{minute}:05.000Z"
        await _post(
            agent,
            parent_sid,
            _response_item(
                "custom_tool_call",
                timestamp=requested,
                call_id=call_id,
                name="exec",
                input=script,
            ),
        )
        await _post(agent, review_sid, _event("task_started", timestamp=started, turn_id=f"review-{index}"))
        context = _turn_context(f"review-{index}")
        context["timestamp"] = started
        context["payload"]["model"] = "codex-auto-review" if index == 1 else "gpt-5.5"
        await _post(agent, review_sid, context)
        await _post(
            agent,
            review_sid,
            _response_item(
                "message",
                timestamp=started,
                role="user",
                content=[
                    {
                        "type": "input_text",
                        "text": (
                            "Reviewed Codex session id: " + parent_sid + "\n"
                            "APPROVAL REQUEST START\nPlanned action JSON:\n"
                            + json.dumps({"command": ["/bin/zsh", "-lc", command]})
                        ),
                    }
                ],
            ),
        )
        await _post(
            agent,
            review_sid,
            _response_item(
                "message",
                timestamp=finished,
                role="assistant",
                content=[
                    {
                        "type": "output_text",
                        "text": (
                            '{"outcome":"allow","risk_level":"low",'
                            '"rationale":"The command only checks JavaScript syntax."}'
                        ),
                    }
                ],
            ),
        )
        await _post(
            agent,
            review_sid,
            _event(
                "token_count",
                timestamp=finished,
                info={"last_token_usage": {"input_tokens": 100 + index, "output_tokens": 10}},
            ),
        )
        await _post(agent, review_sid, _event("task_complete", timestamp=finished, turn_id=f"review-{index}"))
        await _post(
            agent,
            parent_sid,
            _response_item(
                "custom_tool_call_output",
                timestamp=returned,
                call_id=call_id,
                output="ok",
            ),
        )

    await _post(agent, parent_sid, _event("task_complete", timestamp="2026-05-11T17:01:06.000Z"))
    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    assert not [s for s in spans if s.get("session_id") == review_sid]
    assert not [s for s in _by_kind(spans, "llm") if s.get("name") == "codex-auto-review"]
    assert _by_kind(spans, "task") == []
    tools = [s for s in _by_kind(spans, "tool") if s.get("session_id") == parent_sid and s["name"] == "Ran"]
    for span in _by_kind(spans, "tool"):
        if span["name"] == "Curr time":
            assert "auto_reviews" not in span["meta"]["metadata"].get("_dd", {})
    assert len(tools) == 2
    for index, tool in enumerate(tools, 1):
        review = tool["meta"]["metadata"]["_dd"]["auto_reviews"][0]
        assert "auto_reviews" not in tool["meta"]["metadata"]
        assert set(review) == {"outcome", "risk_level", "explanation", "usage", "tool_id", "model"}
        assert review["tool_id"] == f"exec-{index}"
        assert review["outcome"] == "allow"
        assert review["explanation"] == "The command only checks JavaScript syntax."
        assert review["usage"]["input_tokens"] == 100 + index
        if index == 1:
            assert review["model"] == "codex-auto-review"
            assert review["usage"]["estimated_cost_model"] is None
            assert review["usage"]["estimated_total_cost"] is None
            assert review["usage"]["estimated_total_cost_usd"] is None
        else:
            assert review["model"] == "gpt-5.5"
            assert review["usage"]["estimated_cost_model"] == "gpt-5.5"
            assert review["usage"]["estimated_total_cost"] == (100 + index) * 5000 + 10 * 30000
            assert review["usage"]["estimated_total_cost_usd"] == review["usage"]["estimated_total_cost"] / 1e9
        step = next(s for s in spans if s["span_id"] == tool["parent_id"])
        assert "auto_reviews" not in step["meta"]["metadata"].get("_dd", {})


@pytest.mark.parametrize("batched", [False, True])
async def test_codex_guardian_review_arriving_after_tool_output(agent, batched):
    parent_sid = "codex-parent-late-review"
    review_sid = "codex-late-guardian"
    command = "node --check my-agent.js" if not batched else "node --check my-agent.js\nprintf 'done'"
    script = "tools.exec_command(" + json.dumps({"cmd": command}) + ")"
    if batched:
        script = "tools.clock__curr_time({}); " + script
    await _post(agent, parent_sid, _session_meta(parent_sid))
    await _post(agent, parent_sid, _turn_context("parent-turn"))
    await _post(
        agent,
        parent_sid,
        _response_item(
            "custom_tool_call",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="exec-1",
            name="exec",
            input=script,
        ),
    )
    await _post(
        agent,
        parent_sid,
        _response_item(
            "custom_tool_call_output",
            timestamp="2026-05-11T17:00:05.000Z",
            call_id="exec-1",
            output="ok",
        ),
    )
    meta = _session_meta(review_sid)
    meta["payload"].update({"thread_source": "guardian_review", "parent_thread_id": parent_sid})
    await _post(agent, review_sid, meta)
    await _post(agent, review_sid, _event("task_started", timestamp="2026-05-11T17:00:03.100Z"))
    await _post(
        agent,
        review_sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:03.200Z",
            role="user",
            content=[
                {
                    "type": "input_text",
                    "text": (
                        "Reviewed Codex session id: " + parent_sid + "\n"
                        "APPROVAL REQUEST START\nPlanned action JSON:\n"
                        + json.dumps({"command": ["/bin/zsh", "-lc", command]})
                    ),
                }
            ],
        ),
    )
    await _post(agent, review_sid, _event("task_complete", timestamp="2026-05-11T17:00:04.000Z"))
    await _post(agent, review_sid, _event("task_complete", timestamp="2026-05-11T17:00:04.000Z"))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    tool = next(s for s in _by_kind(spans, "tool") if s.get("session_id") == parent_sid and s["name"] == "Ran")
    for span in _by_kind(spans, "tool"):
        if span["name"] == "Curr time":
            assert "auto_reviews" not in span["meta"]["metadata"].get("_dd", {})
    assert tool["meta"]["metadata"]["_dd"]["auto_reviews"][0]["tool_id"] == "exec-1"
    assert len(tool["meta"]["metadata"]["_dd"]["auto_reviews"]) == 1
    assert not [s for s in spans if s.get("session_id") == review_sid]
    assert _by_kind(spans, "task") == []


@pytest.mark.parametrize("include_context", [True, False])
async def test_codex_guardian_review_resume_without_session_meta(agent, include_context):
    parent_sid = "codex-parent-resumed-review"
    review_sid = "codex-review-without-meta"
    await _post(agent, parent_sid, _session_meta(parent_sid))
    await _post(agent, parent_sid, _turn_context("parent-turn"))
    await _post(
        agent,
        parent_sid,
        _response_item(
            "custom_tool_call",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="exec-1",
            name="exec",
            input='tools.exec_command({cmd:"node --check my-agent.js"})',
        ),
    )
    await _post(agent, review_sid, _event("thread_settings_applied", timestamp="2026-05-11T17:00:03.100Z"))
    await _post(agent, review_sid, _event("task_started", timestamp="2026-05-11T17:00:03.200Z"))
    context = _turn_context("review-turn")
    context["timestamp"] = "2026-05-11T17:00:03.300Z"
    context["payload"]["model"] = "codex-auto-review"
    if include_context:
        await _post(agent, review_sid, context)
    await _post(
        agent,
        review_sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:03.400Z",
            role="user",
            content=[
                {
                    "type": "input_text",
                    "text": (
                        f"Reviewed Codex session id: {parent_sid}\n"
                        "APPROVAL REQUEST START\nPlanned action JSON:\n"
                        '{"command":["/bin/zsh","-lc","node --check my-agent.js"]}'
                    ),
                }
            ],
        ),
    )
    await _post(agent, review_sid, _event("task_complete", timestamp="2026-05-11T17:00:04.000Z"))
    await _post(
        agent,
        parent_sid,
        _response_item("custom_tool_call_output", timestamp="2026-05-11T17:00:05.000Z", call_id="exec-1", output="ok"),
    )

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    assert not [span for span in spans if span.get("session_id") == review_sid]
    tool = next(span for span in _by_kind(spans, "tool") if span.get("session_id") == parent_sid)
    review = tool["meta"]["metadata"]["_dd"]["auto_reviews"][0]
    assert review["tool_id"] == "exec-1"
    assert review["explanation"] == ""
    if not include_context:
        assert "model" not in review
        assert review["usage"]["estimated_total_cost"] is None
    assert _by_kind(spans, "task") == []


async def test_codex_user_message_starts_new_trace_without_turn_context(agent):
    sid = "codex-multi-message-session"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="first"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:03.000Z", message="done first"))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="second"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="done second"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 2
    first = next(s for s in roots if s["meta"]["input"]["value"] == "first")
    second = next(s for s in roots if s["meta"]["input"]["value"] == "second")
    assert first["trace_id"] != second["trace_id"]
    assert first["meta"]["output"]["value"] == "done first"
    assert second["meta"]["output"]["value"] == "done second"


async def test_codex_new_turn_forwards_completed_trace_before_repointing_session(agent, monkeypatch):
    forwarded_payloads = []
    descriptions = []

    def fake_resolve_backend_target(self, *args, **kwargs):
        return "http://backend.example", {}

    async def fake_post_to_backend(self, url, headers, data, description):
        descriptions.append(description)
        forwarded_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))

    monkeypatch.setattr(ClaudeHooksAPI, "_resolve_backend_target", fake_resolve_backend_target)
    monkeypatch.setattr(ClaudeHooksAPI, "_post_to_backend", fake_post_to_backend)

    sid = "codex-forward-two-turns"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", message="first"))
    await _post(agent, sid, _event("agent_message", message="done first"))
    await _post(agent, sid, _turn_context("turn-b"))

    assert len(forwarded_payloads) == 1
    forwarded_spans = forwarded_payloads[0]["spans"]
    forwarded_turn_ids = {span["meta"]["metadata"].get("turn_id") for span in forwarded_spans}
    assert forwarded_turn_ids == {"turn-a"}
    assert "Codex spans" in descriptions[0]


async def test_codex_backfill_does_not_forward_completed_trace(agent, monkeypatch):
    forwarded_payloads = []

    def fake_resolve_backend_target(self, *args, **kwargs):
        return "http://backend.example", {}

    async def fake_post_to_backend(self, url, headers, data, description):
        forwarded_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))

    monkeypatch.setattr(ClaudeHooksAPI, "_resolve_backend_target", fake_resolve_backend_target)
    monkeypatch.setattr(ClaudeHooksAPI, "_post_to_backend", fake_post_to_backend)

    sid = "codex-backfill-no-forward"
    await _post(agent, sid, _session_meta(sid), backfill=True)
    await _post(agent, sid, _turn_context("turn-a"), backfill=True)
    await _post(agent, sid, _event("user_message", message="historical"), backfill=True)
    await _post(agent, sid, _event("agent_message", message="done"), backfill=True)
    await _post(agent, sid, _turn_context("turn-b"), backfill=True)

    assert forwarded_payloads == []
    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    historical_roots = [root for root in roots if root["meta"].get("input", {}).get("value") == "historical"]
    assert len(historical_roots) == 1


async def test_codex_user_message_forwards_previous_trace_without_turn_context(agent, monkeypatch):
    forwarded_payloads = []

    def fake_resolve_backend_target(self, *args, **kwargs):
        return "http://backend.example", {}

    async def fake_post_to_backend(self, url, headers, data, description):
        forwarded_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))

    monkeypatch.setattr(ClaudeHooksAPI, "_resolve_backend_target", fake_resolve_backend_target)
    monkeypatch.setattr(ClaudeHooksAPI, "_post_to_backend", fake_post_to_backend)

    sid = "codex-forward-multi-message"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-a"))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="first"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:03.000Z", message="done first"))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="second"))

    assert len(forwarded_payloads) == 1
    forwarded_roots = [span for span in forwarded_payloads[0]["spans"] if span["parent_id"] == "undefined"]
    assert len(forwarded_roots) == 1
    assert forwarded_roots[0]["meta"]["input"]["value"] == "first"
    assert forwarded_roots[0]["meta"]["output"]["value"] == "done first"


async def test_codex_shutdown_complete_forwards_active_trace(agent, monkeypatch):
    forwarded_payloads = []

    def fake_resolve_backend_target(self, *args, **kwargs):
        return "http://backend.example", {}

    async def fake_post_to_backend(self, url, headers, data, description):
        forwarded_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))

    monkeypatch.setattr(ClaudeHooksAPI, "_resolve_backend_target", fake_resolve_backend_target)
    monkeypatch.setattr(ClaudeHooksAPI, "_post_to_backend", fake_post_to_backend)

    sid = "codex-forward-shutdown"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-shutdown"))
    await _post(agent, sid, _event("user_message", message="finish on shutdown"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:03.000Z", message="partial done"))
    await _post(agent, sid, _event("shutdown_complete", timestamp="2026-05-11T17:00:04.000Z"))

    assert len(forwarded_payloads) == 1
    forwarded_roots = [span for span in forwarded_payloads[0]["spans"] if span["parent_id"] == "undefined"]
    assert len(forwarded_roots) == 1
    assert forwarded_roots[0]["meta"]["metadata"]["turn_id"] == "turn-shutdown"
    assert forwarded_roots[0]["meta"]["input"]["value"] == "finish on shutdown"
    assert forwarded_roots[0]["meta"]["output"]["value"] == "partial done"


async def test_codex_ignores_duplicate_session_for_existing_task_id(agent):
    parent_sid = "codex-parent-task"
    duplicate_sid = "codex-duplicate-task"
    turn_id = "turn-shared"

    await _post(agent, parent_sid, _session_meta(parent_sid))
    await _post(agent, parent_sid, _turn_context(turn_id))
    await _post(agent, parent_sid, _event("user_message", message="real work"))

    await _post(agent, duplicate_sid, _session_meta(duplicate_sid))
    await _post(
        agent,
        duplicate_sid,
        _event("task_started", timestamp="2026-05-11T17:00:03.000Z", id=turn_id),
    )
    await _post(
        agent,
        duplicate_sid,
        _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="stale replay"),
    )
    await _post(
        agent,
        duplicate_sid,
        _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="stale output"),
    )

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())

    assert [span for span in spans if span.get("session_id") == duplicate_sid] == []
    parent_roots = [span for span in spans if span.get("session_id") == parent_sid and span["parent_id"] == "undefined"]
    assert len(parent_roots) == 1
    assert parent_roots[0]["meta"]["input"]["value"] == "real work"


async def test_codex_accepts_raw_jsonl_records_like_curl(agent):
    sid = "codex-raw-curl"
    await agent.post("/codex/hooks", json=_session_meta(sid))
    await agent.post("/codex/hooks", json=_turn_context())
    await agent.post("/codex/hooks", json=_event("user_message", message="raw curl input"))
    await agent.post("/codex/hooks", json=_event("agent_message", message="raw curl output"))
    await agent.post("/codex/hooks", json=_event("task_complete", timestamp="2026-05-11T17:00:03.000Z"))

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == "raw curl input"
    assert roots[0]["meta"]["output"]["value"] == "raw curl output"
    assert roots[0]["duration"] > 0


async def test_codex_list_rewriter_returns_posted_message_spans(agent):
    sid = "codex-list-rewriter"
    await agent.post("/codex/hooks", json=_session_meta(sid))
    await agent.post("/codex/hooks", json=_turn_context())
    await agent.post("/codex/hooks", json=_event("user_message", message="list rewriter input"))
    await agent.post("/codex/hooks", json=_event("agent_message", message="list rewriter output"))

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@session_id:{sid}"}, "limit": 10}},
    )
    assert resp.status == 200
    data = await resp.json()
    root = next(
        event["event"]["custom"] for event in data["result"]["events"] if event["event"]["custom"]["kind"] == "agent"
    )

    assert root["name"] == "codex-request"
    assert root["session_id"] == sid
    assert root["meta"]["input"]["value"] == "list rewriter input"
    assert root["meta"]["output"]["value"] == "list rewriter output"


async def test_codex_tui_task_complete_finalizes_single_turn(agent, pricing_catalog):
    sid = "codex-tui-hello"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    await _post(
        agent,
        sid,
        _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="Hello. How can I help?"),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:04.100Z",
            role="assistant",
            content=[{"type": "output_text", "text": "Hello. How can I help?"}],
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "token_count",
            timestamp="2026-05-11T17:00:05.000Z",
            info={
                "last_token_usage": {
                    "input_tokens": 14784,
                    "cached_input_tokens": 6528,
                    "output_tokens": 11,
                    "reasoning_output_tokens": 0,
                    "total_tokens": 14795,
                }
            },
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "task_complete",
            timestamp="2026-05-11T17:00:05.100Z",
            last_agent_message="Hello. How can I help?",
        ),
    )

    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"search": {"query": f"@session_id:{sid}"}, "limit": 10}},
    )
    assert resp.status == 200
    data = await resp.json()
    session_events = [event["event"]["custom"] for event in data["result"]["events"]]
    roots = [event for event in session_events if event["kind"] == "agent"]
    steps = [event for event in session_events if event["kind"] == "step"]
    llms = [event for event in session_events if event["kind"] == "llm"]

    assert len(roots) == 1
    assert len(steps) == 1
    assert len(llms) == 1
    assert roots[0]["meta"]["input"]["value"] == "hello"
    assert roots[0]["meta"]["output"]["value"] == "Hello. How can I help?"
    assert roots[0]["duration"] == 4_100_000_000
    assert llms[0]["duration"] == 2_000_000_000
    assert llms[0]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "Hello. How can I help?"}]
    assert llms[0]["metrics"]["input_tokens"] == 14784
    assert llms[0]["metrics"]["estimated_total_cost"] > 0


async def test_codex_ignores_duplicate_replayed_records(agent):
    sid = "codex-replay"
    records = [
        _session_meta(sid),
        _turn_context(),
        _event("user_message", message="replayed input"),
        _event("agent_message", message="replayed output"),
    ]
    for record in records:
        await _post(agent, sid, record)
    for record in records:
        await _post(agent, sid, record)

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == "replayed input"
    assert roots[0]["meta"]["output"]["value"] == "replayed output"


async def test_codex_only_uses_own_ml_app_override(codex_env_overrides, agent):
    sid = "codex-env"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="env input"))
    await _post(agent, sid, _response_item("function_call", name="exec_command", call_id="call-env"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    root = next(s for s in session_spans if s["parent_id"] == "undefined")

    assert root["ml_app"] == "codex-custom"
    assert root["service"] == "codex-custom"
    assert root["env"] == "local"
    assert "ml_app:codex-custom" in root["tags"]
    assert "service:codex-custom" in root["tags"]
    assert "env:local" in root["tags"]
    assert "user_handle:shared-user" in root["tags"]
    assert "ml_app:lapdog" not in root["tags"]

    manifest = root["meta"]["metadata"]["_dd"]["agent_manifest"]
    assert manifest["name"] == "codex-custom"
    assert manifest["model"] == "gpt-5.5"
    assert manifest["model_provider"] == "openai"
    assert manifest["model_settings"]["reasoning_effort"] == "medium"
    assert manifest["tools"] == [{"name": "Ran"}]


async def test_codex_duplicate_call_id_emits_distinct_tool_spans(agent):
    """Codex reuses tool call_ids (e.g. ``web_search_2``) across turns.

    Each occurrence must produce its own tool span with a unique
    ``tool_use_id`` so trace consumers can pair calls with outputs.
    """
    sid = "codex-dedup"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="search twice"))
    await _post(
        agent,
        sid,
        _response_item("function_call", name="web_search", call_id="web_search_2", arguments='{"q": "a"}'),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call_output", call_id="web_search_2", output="result-a"),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call", name="web_search", call_id="web_search_2", arguments='{"q": "b"}'),
    )
    await _post(
        agent,
        sid,
        _response_item("function_call_output", call_id="web_search_2", output="result-b"),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    tools = _by_kind(session_spans, "tool")
    # Without dedup, the second call would have overwritten the first
    # ``pending_tools["web_search_2"]`` and the first output would land
    # nowhere, producing only one (mis-paired) tool span.
    assert len(tools) == 2
    inputs = sorted(t["meta"]["input"]["value"] for t in tools)
    outputs = sorted(t["meta"]["output"]["value"] for t in tools)
    assert inputs == ['{"q": "a"}', '{"q": "b"}']
    assert outputs == ["result-a", "result-b"]
    # Spans must have distinct span_ids — the second was not a no-op overwrite.
    assert tools[0]["span_id"] != tools[1]["span_id"]


async def test_codex_subagent_spawn_emits_agent_span(agent):
    sid = "codex-subagent"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="delegate"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="do the thing",
        ),
    )
    # Tool call emitted while the subagent is active should nest under it.
    await _post(
        agent,
        sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:03.000Z",
            name="exec_command",
            call_id="call-sub",
            arguments='{"cmd": "ls"}',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:03.500Z",
            call_id="call-sub",
            output="files",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="spawn-1",
            new_thread_id="child-thread",
            new_agent_nickname="researcher",
            new_agent_role="researcher",
            status="ok",
        ),
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:05.000Z", message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    agents = _by_kind(session_spans, "agent")
    # One root + one subagent of kind=agent.
    assert len(agents) == 2
    root = next(s for s in agents if s["parent_id"] == "undefined")
    subagent = next(s for s in agents if s["span_id"] != root["span_id"])
    assert subagent["name"] == "researcher"
    assert subagent["duration"] > 0
    assert subagent["meta"]["metadata"]["subagent"]["child_session_id"] == "child-thread"
    assert subagent["meta"]["metadata"]["subagent"]["status"] == "ok"
    # Tool span emitted between begin and end must parent to the subagent.
    tools = _by_kind(session_spans, "tool")
    assert len(tools) == 1
    assert tools[0]["parent_id"] == subagent["span_id"]


async def test_codex_unterminated_subagent_finalizes_as_error(agent):
    sid = "codex-subagent-unterminated"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="delegate"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="do the thing",
        ),
    )

    await _post(agent, sid, _turn_context("next-turn"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    subagent = next(s for s in _by_kind(session_spans, "agent") if s["parent_id"] != "undefined")
    assert subagent["status"] == "error"
    assert subagent["meta"]["metadata"]["subagent"]["status"] == "unterminated"


async def test_codex_child_thread_spans_are_grouped_with_parent_session(agent):
    sid = "codex-parent-session"
    child_sid = "codex-child-session"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="delegate"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id=sid,
            prompt="do the thing",
        ),
    )

    await _post(agent, child_sid, _session_meta(child_sid))
    await _post(agent, child_sid, _turn_context("child-turn"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == child_sid]
    assert len(session_spans) == 1

    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="spawn-1",
            new_thread_id=child_sid,
            new_agent_nickname="researcher",
            status="ok",
        ),
    )

    await _post(agent, child_sid, _event("user_message", timestamp="2026-05-11T17:00:05.000Z", message="child work"))

    resp = await agent.get("/claude/hooks/spans")
    spans = _spans(await resp.json())
    child_turn = next(s for s in spans if s.get("meta", {}).get("metadata", {}).get("turn_id") == "child-turn")

    assert child_turn["session_id"] == sid
    assert f"session_id:{sid}" in child_turn["tags"]
    assert f"session_id:{child_sid}" not in child_turn["tags"]
    assert [s for s in spans if s.get("session_id") == child_sid] == []


async def test_codex_grouped_sessions_keep_latest_tags_on_future_child_spans(agent):
    parent_sid = "codex-tagged-parent"
    child_sid = "codex-tagged-child"
    session_token = "codex-grouped-token"
    await _post(agent, parent_sid, _session_meta(parent_sid), proxy_session_key=session_token)
    await _post(agent, parent_sid, _turn_context())
    await _post(agent, parent_sid, _event("user_message", message="delegate"))
    await _post(
        agent,
        parent_sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-tagged-child",
            sender_thread_id=parent_sid,
            prompt="do the thing",
        ),
    )

    await _post(agent, child_sid, _session_meta(child_sid), proxy_session_key=session_token)
    await _post(agent, child_sid, _turn_context("child-turn"))
    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"session_id": child_sid, "tags": {"iteration": "child"}},
    )
    assert response.status == 200, await response.text()

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"session_id": parent_sid, "tags": {"iteration": "parent"}},
    )
    assert response.status == 200, await response.text()

    await _post(
        agent,
        parent_sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="spawn-tagged-child",
            new_thread_id=child_sid,
            new_agent_nickname="researcher",
            status="ok",
        ),
    )

    await _post(
        agent,
        child_sid,
        _event(
            "user_message",
            timestamp="2026-05-11T17:00:05.000Z",
            message="child work after parent tag update",
        ),
    )
    await _post(
        agent,
        child_sid,
        _response_item(
            "function_call",
            timestamp="2026-05-11T17:00:06.000Z",
            name="exec_command",
            call_id="child-call-after-tag-update",
            arguments='{"cmd": "pwd"}',
        ),
    )
    await _post(
        agent,
        child_sid,
        _response_item(
            "function_call_output",
            timestamp="2026-05-11T17:00:07.000Z",
            call_id="child-call-after-tag-update",
            output="/tmp/project",
        ),
    )

    response = await agent.get("/claude/hooks/spans")
    spans = _spans(await response.json())
    child_turn = next(span for span in spans if span.get("meta", {}).get("metadata", {}).get("turn_id") == "child-turn")
    child_tool = next(
        span
        for span in _by_kind(spans, "tool")
        if span.get("meta", {}).get("metadata", {}).get("tool_id") == "child-call-after-tag-update"
    )
    assert child_turn["session_id"] == parent_sid
    assert "iteration:parent" in child_turn["tags"]
    assert "iteration:child" not in child_turn["tags"]
    assert "iteration:parent" in child_tool["tags"]
    assert "iteration:child" not in child_tool["tags"]


async def test_codex_compaction_event_msg_annotates_active_span(agent):
    sid = "codex-compact-event"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="long history"))
    await _post(agent, sid, _event("context_compacted", timestamp="2026-05-11T17:00:03.000Z"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="ok"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    compactions: list = []
    for span in session_spans:
        entries = span.get("meta", {}).get("metadata", {}).get("_dd", {}).get("compactions", [])
        compactions.extend(entries)
    assert len(compactions) == 1
    assert compactions[0]["trigger"] == "context_compacted"


async def test_codex_compaction_top_level_record_annotates_active_span(agent):
    sid = "codex-compact-top"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", message="long history"))
    await _post(
        agent,
        sid,
        {"timestamp": "2026-05-11T17:00:03.000Z", "type": "compacted", "payload": {}},
    )
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="ok"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    compactions: list = []
    for span in session_spans:
        entries = span.get("meta", {}).get("metadata", {}).get("_dd", {}).get("compactions", [])
        compactions.extend(entries)
    assert len(compactions) == 1
    assert compactions[0]["trigger"] == "compacted"


async def test_codex_hook_requires_session_id(agent):
    resp = await agent.post("/codex/hooks", json={"type": "event_msg", "payload": {"type": "user_message"}})
    assert resp.status == 400
    body = await resp.json()
    assert "session_id" in body["error"]


async def test_codex_subagent_call_id_reused_across_turns_yields_distinct_spans(agent):
    """Codex sometimes reuses spawn call_ids across turns; each spawn must get
    its own agent span. Regression test guarding the pending_subagents map
    against silent overwrites.
    """
    sid = "codex-subagent-reuse"
    await _post(agent, sid, _session_meta(sid))
    # Turn 1
    await _post(agent, sid, _turn_context("turn-1"))
    await _post(agent, sid, _event("user_message", message="first"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="first sub",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="spawn-1",
            new_thread_id="child-1",
            new_agent_nickname="agent-a",
            status="ok",
        ),
    )
    await _post(agent, sid, _event("task_complete", timestamp="2026-05-11T17:00:03.500Z", last_agent_message="done"))
    # Turn 2 — same spawn call_id
    await _post(agent, sid, _turn_context("turn-2"))
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:04.000Z", message="second"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:04.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="second sub",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:05.000Z",
            call_id="spawn-1",
            new_thread_id="child-2",
            new_agent_nickname="agent-b",
            status="ok",
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    agents = _by_kind(session_spans, "agent")
    subagents = [s for s in agents if s["parent_id"] != "undefined"]
    assert len(subagents) == 2, f"Expected two distinct subagent spans, got {len(subagents)}"
    nicknames = sorted(s["meta"]["metadata"]["subagent"]["agent_nickname"] for s in subagents)
    assert nicknames == ["agent-a", "agent-b"]


async def test_codex_subagent_call_id_reused_within_turn_yields_distinct_spans(agent):
    """Two sequential spawns within a single turn that reuse the same call_id —
    each must still produce its own span.
    """
    sid = "codex-subagent-reuse-within"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context("turn-1"))
    await _post(agent, sid, _event("user_message", message="delegate twice"))
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:02.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="first sub",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:03.000Z",
            call_id="spawn-1",
            new_thread_id="child-1",
            new_agent_nickname="agent-a",
            status="ok",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_begin",
            timestamp="2026-05-11T17:00:03.500Z",
            call_id="spawn-1",
            sender_thread_id="parent-thread",
            prompt="second sub",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "collab_agent_spawn_end",
            timestamp="2026-05-11T17:00:04.000Z",
            call_id="spawn-1",
            new_thread_id="child-2",
            new_agent_nickname="agent-b",
            status="ok",
        ),
    )

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    subagents = [s for s in _by_kind(session_spans, "agent") if s["parent_id"] != "undefined"]
    assert len(subagents) == 2
    nicknames = sorted(s["meta"]["metadata"]["subagent"]["agent_nickname"] for s in subagents)
    assert nicknames == ["agent-a", "agent-b"]
