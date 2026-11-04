"""Tests for Codex JSONL hooks."""

import gzip
import json
import subprocess

import msgpack
import pytest

from lapdog.claude_hooks import ClaudeHooksAPI
from lapdog.codex_hooks import _display_tool_name as display_tool_name


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


_INFERENCE_BASE_NS = 1778518800000000000  # 2026-05-11T17:00:00Z


@pytest.fixture
def codex_inference():
    from lapdog.codex_hooks import CodexHooksAPI
    from lapdog.codex_proxy import CodexProxyAPI

    hooks = ClaudeHooksAPI()
    parser = CodexHooksAPI(hooks)
    metadata = _session_meta("session")
    metadata["payload"]["cli_version"] = "0.166.0"
    for value in [
        metadata,
        _turn_context(),
        _event("user_message", timestamp="2026-05-11T17:00:01.100Z", message="inspect files"),
    ]:
        parser._dispatch("session", value)
    return hooks, parser, CodexProxyAPI(parser)


def _custom_call(index, second, **kwargs):
    return _response_item(
        "custom_tool_call",
        timestamp=f"2026-05-11T17:00:{second:06.3f}Z",
        name="exec",
        call_id=f"call-{index}",
        input=f'await tools.exec_command({{cmd:"echo {index}"}});',
        status="completed",
        **kwargs,
    )


def _usage_record(index, second):
    return {
        "type": "token_usage_record",
        "timestamp": f"2026-05-11T17:00:{second:06.3f}Z",
        "payload": {
            "turn_id": "turn-1",
            "response_id": f"resp-{index}",
            "usage": {"input_tokens": index * 100, "output_tokens": index * 10, "total_tokens": index * 110},
        },
    }


def _command_completion(index, second):
    return _event(
        "item_completed",
        timestamp=f"2026-05-11T17:00:{second:06.3f}Z",
        item={
            "type": "CommandExecution",
            "id": f"exec-{index}",
            "command": ["/bin/sh", "-lc", f"echo {index}"],
            "status": "completed",
            "exit_code": 0,
            "aggregated_output": str(index),
            "duration": {"secs": 0, "nanos": 10_000_000},
        },
    )


def _proxy_span(proxy, index):
    return proxy._create_llm_span(
        {"model": "gpt-5.5", "input": "inspect files"},
        {
            "id": f"resp-{index}",
            "status": "completed",
            "output": [
                {"type": "reasoning", "id": f"reason-{index}", "summary": []},
                _custom_call(index, 3)["payload"],
            ],
            "usage": {"input_tokens": index * 100, "output_tokens": index * 10},
        },
        _INFERENCE_BASE_NS + index * 2_000_000_000,
        1_000_000_000,
    )


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
    await _post(
        agent,
        sid,
        _event(
            "item_completed",
            timestamp="2026-05-11T17:00:07.000Z",
            item={
                "type": "CommandExecution",
                "id": "command-1",
                "process_id": "74738",
                "command": ["/bin/zsh", "-lc", "yarn lint"],
                "aggregated_output": "started\nlint passed\n",
                "exit_code": 0,
                "duration": {"secs": 4, "nanos": 0},
            },
        ),
    )
    await _post(agent, sid, _event("task_complete", timestamp="2026-05-11T17:00:08.000Z"))
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    tools = [span for span in _by_kind(spans, "tool") if span.get("session_id") == sid]
    assert len(tools) == 1
    assert tools[0]["name"] == "Ran"
    assert json.loads(tools[0]["meta"]["input"]["value"]) == {"cmd": "yarn lint"}
    assert tools[0]["meta"]["output"]["value"] == "started\nlint passed\n"
    assert tools[0]["meta"]["metadata"]["process_id"] == "74738"
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


@pytest.mark.parametrize("prompt", ["inspect this repo", "inspect this repo\n", "inspect\tthis  repo"])
@pytest.mark.parametrize("event_first", [False, True])
async def test_codex_response_item_ignores_injected_user_context_and_deduplicates_legacy_event(
    agent, prompt, event_first
):
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
    item = _response_item(
        "message",
        role="user",
        content=[{"type": "input_text", "text": prompt}],
        internal_chat_message_metadata_passthrough={"content_item_kinds": ["user.text"]},
    )
    event = _event("user_message", message="inspect this repo")
    for record in ([event, item] if event_first else [item, event]):
        await _post(agent, sid, record)
    await _post(agent, sid, _event("task_complete", last_agent_message="done"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    roots = [s for s in session_spans if s["parent_id"] == "undefined"]

    assert len(roots) == 1
    assert roots[0]["meta"]["input"]["value"] == ("inspect this repo" if event_first else prompt)


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


@pytest.mark.parametrize("limit", [None, 8192])
async def test_codex_tool_status_reasoning_and_large_output_are_tracked_safely(agent, monkeypatch, limit):
    monkeypatch.setattr("lapdog.codex_hooks.MAX_LLM_MESSAGE_CHARS", limit)
    monkeypatch.setattr("lapdog.codex_hooks.MAX_TOOL_VALUE_CHARS", limit)
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
    if limit is None:
        assert tool["meta"]["output"]["value"] == large_output
    else:
        assert "[truncated " in tool["meta"]["output"]["value"]
        assert len(tool["meta"]["output"]["value"]) < len(large_output)

    tool_input_message = llms[1]["meta"]["input"]["messages"][-1]
    assert tool_input_message["role"] == "tool"
    assert tool_input_message["status"] == "failed"
    if limit is None:
        assert tool_input_message["content"] == large_output
    else:
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
    await _post(
        agent, sid, _response_item("web_search_call", call_id="web_search_1", query="test query", status="completed")
    )
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

    assert [tool["name"] for tool in tools] == ["Web search", "Apply patch", "Apply patch"]
    assert tools[0]["meta"]["metadata"]["tool_id"] == "web_search_1"
    assert tools[0]["meta"]["input"]["value"] == "test query"
    assert tools[1]["meta"]["output"]["value"] == "Success"
    assert "/repo/main.py" in json.loads(tools[2]["meta"]["input"]["value"])
    approvals = root["meta"]["metadata"]["_dd"]["codex_approvals"]
    assert approvals[0]["tool"] == "apply_patch"
    assert approvals[0]["call_id"] == "patch-approval-1"
    assert approvals[0]["status"] == "completed"
    assert approvals[0]["resolved_timestamp_ns"] > approvals[0]["timestamp_ns"]


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


@pytest.mark.parametrize("order", ["review_first", "tool_first", "next_turn_first"])
@pytest.mark.parametrize("ambiguous", [False, True])
@pytest.mark.parametrize("identity", ["metadata", "attribution", "context"])
async def test_codex_guardian_reviews_use_source_identity_and_parent_session(agent, order, ambiguous, identity):
    parent, reviewer = "review-parent", "review-child"
    meta = _session_meta(reviewer)
    meta["payload"].update(thread_source="guardian_review", parent_thread_id=parent)
    reviews = [meta] if identity == "metadata" else []
    tools = []
    for index in range(2):
        start = 3 + index * 4
        reviews += [
            _event(
                "task_started",
                turn_id=f"review-{index}",
                turn_attribution=(
                    {"parent_turn_id": "parent-turn", "turn_trigger": "guardian_review"}
                    if identity == "attribution"
                    else {}
                ),
                root_turn_id="parent-turn",
                timestamp=f"2026-05-11T17:00:0{start}.000Z",
            ),
            {**_turn_context(f"review-{index}"), "payload": {"model": "codex-auto-review"}},
            _response_item(
                "message",
                role="assistant",
                content=[
                    {
                        "type": "output_text",
                        "text": json.dumps(
                            {
                                "outcome": "allow" if index == 0 else "deny",
                                "rationale": f"reason-{index}",
                            }
                        ),
                    }
                ],
                timestamp=f"2026-05-11T17:00:0{start + 1}.000Z",
            ),
            (
                {"type": "token_usage_record", "payload": {"usage": {"input_tokens": 100 + index, "output_tokens": 1}}}
                if index == 0
                else _event("token_count", info={"last_token_usage": {"input_tokens": 101, "output_tokens": 1}})
            ),
            _event("task_complete", turn_id=f"review-{index}", timestamp=f"2026-05-11T17:00:0{start + 1}.000Z"),
        ]
        for suffix in (["", "-overlap"] if ambiguous else [""]):
            tools.append(
                _event(
                    "item_completed",
                    turn_id="parent-turn",
                    timestamp=f"2026-05-11T17:00:0{start + 2}.000Z",
                    started_at_ms=1778518800000 + (start - 1) * 1000,
                    completed_at_ms=1778518800000 + (start + 2) * 1000,
                    item={
                        "type": "CommandExecution",
                        "id": f"tool-{index}{suffix}",
                        "command": ["/bin/sh", "-c", "pwd"],
                        "status": "completed",
                        "exit_code": 0,
                    },
                )
            )

    async def send_reviews():
        for record in reviews:
            await _post(agent, reviewer, record)
        # Watcher retries must not add a second annotation.
        await _post(agent, reviewer, reviews[-1])

    if order == "review_first":
        await send_reviews()
    await _post(agent, parent, _session_meta(parent))
    await _post(agent, parent, _turn_context("parent-turn"))
    for record in tools:
        await _post(agent, parent, record)
    if order == "tool_first":
        await send_reviews()
    await _post(agent, parent, _event("task_complete", turn_id="parent-turn", timestamp="2026-05-11T17:00:10.000Z"))
    if order == "next_turn_first":
        await _post(agent, parent, _turn_context("next-turn"))
        await send_reviews()
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    assert not [s for s in spans if s.get("session_id") == reviewer]
    for root in _by_kind(spans, "agent"):
        assert "auto_reviews" not in root["meta"]["metadata"].get("_dd", {})
    for tool in _by_kind(spans, "tool"):
        annotations = tool["meta"]["metadata"].get("_dd", {}).get("auto_reviews", [])
        if ambiguous:
            assert annotations == []
            continue
        assert len(annotations) == 1
        entry = annotations[0]
        index = int(tool["meta"]["metadata"]["tool_id"][-1])
        assert entry["tool_id"] == f"tool-{index}"
        assert entry["outcome"] == ("allow" if index == 0 else "deny")
        assert entry["explanation"] == f"reason-{index}"
        assert entry["usage"]["input_tokens"] == 100 + index
        assert "estimated_total_cost_usd" in entry["usage"]


async def test_codex_review_prompt_text_does_not_classify_a_user_session(agent):
    sid = "ordinary-user"
    await _post(agent, sid, _session_meta(sid))
    await _post(
        agent,
        sid,
        _event(
            "user_message", message="Reviewed Codex session id: parent\nAPPROVAL REQUEST START\nPlanned action JSON: {}"
        ),
    )
    spans = _spans(await (await agent.get("/claude/hooks/spans")).json())
    assert len(_by_kind(spans, "agent")) == 1


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


@pytest.mark.parametrize("completion_only", [False, True])
async def test_codex_tui_task_complete_finalizes_single_turn(agent, pricing_catalog, completion_only):
    sid = "codex-tui-hello"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(agent, sid, _event("user_message", timestamp="2026-05-11T17:00:02.000Z", message="hello"))
    await _post(agent, sid, _event("token_count", timestamp="2026-05-11T17:00:03.000Z", info=None))
    if not completion_only:
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
    assert llms[0]["meta"]["output"]["messages"] == [{"role": "assistant", "content": "Hello. How can I help?"}]
    assert llms[0]["metrics"]["input_tokens"] == 14784
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


@pytest.mark.parametrize("status", ["ok", "error"])
async def test_codex_subagent_spawn_emits_agent_span(agent, status):
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
            status=status,
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
    assert subagent["meta"]["metadata"]["subagent"]["status"] == status
    assert subagent["status"] == status
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
            agent_nickname="helper",
            prompt="do the thing",
        ),
    )

    await _post(agent, sid, _turn_context("next-turn"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    subagent = next(s for s in _by_kind(session_spans, "agent") if s["parent_id"] != "undefined")
    assert subagent["status"] == "error"
    assert subagent["meta"]["metadata"]["subagent"]["status"] == "unterminated"
    assert subagent["name"] == "helper"
    assert "subagent:true" in subagent["tags"]
    assert subagent["meta"]["metadata"]["subagent"]["sender_thread_id"] == "parent-thread"
    assert subagent["meta"]["metadata"]["subagent"]["agent_nickname"] == "helper"


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
    await _post(agent, sid, _event("context_compacted", timestamp="2026-05-11T17:00:03.500Z"))
    await _post(agent, sid, _event("agent_message", timestamp="2026-05-11T17:00:04.000Z", message="ok"))

    resp = await agent.get("/claude/hooks/spans")
    session_spans = [s for s in _spans(await resp.json()) if s.get("session_id") == sid]
    compactions: list = []
    for span in session_spans:
        entries = span.get("meta", {}).get("metadata", {}).get("_dd", {}).get("compactions", [])
        compactions.extend(entries)
    assert len(compactions) == 2
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


@pytest.mark.parametrize("late", [False, True])
async def test_structured_command_replaces_wrapper_output(agent, late):
    sid = "structured-command"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call", name="exec", call_id="batch", input='text(await tools.exec_command({cmd:"pwd"}));'
        ),
    )
    completion = _event(
        "item_completed",
        timestamp="2026-05-11T17:00:04.000Z",
        item={
            "type": "CommandExecution",
            "id": "exec-1",
            "process_id": "123",
            "command": ["/bin/sh", "-lc", "pwd"],
            "aggregated_output": "/repo\n",
            "exit_code": 0,
            "status": "completed",
            "duration": {"secs": 1, "nanos": 0},
        },
    )
    output = _response_item(
        "custom_tool_call_output",
        call_id="batch",
        output=[
            {"type": "input_text", "text": "Script completed\nOutput:\n"},
            {"type": "input_text", "text": '{"session_id":123,"output":"partial"}'},
        ],
    )
    for record in ([output, completion] if late else [completion, output]):
        await _post(agent, sid, record)
    await _post(agent, sid, completion)  # Replayed completion must not duplicate the span.
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 1
    assert tools[0]["meta"]["output"]["value"] == "/repo\n"
    assert tools[0]["meta"]["metadata"]["exit_code"] == 0
    assert tools[0]["meta"]["metadata"]["result_source"] == "item_completed"


async def test_structured_mcp_and_patch_without_printed_results(agent):
    sid = "structured-tools"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    patch = "*** Begin Patch\n*** Update File: a.py\n@@\n-old\n+new\n*** End Patch"
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            name="exec",
            call_id="batch",
            input=(
                "await tools.list_mcp_resources({}); await tools.apply_patch(" + json.dumps(patch) + '); text("done");'
            ),
        ),
    )
    result = {"content": [{"type": "text", "text": "resource result"}], "isError": False}
    for item in [
        {
            "type": "McpToolCall",
            "id": "mcp-1",
            "server": "codex",
            "tool": "list_mcp_resources",
            "arguments": {},
            "result": result,
            "status": "completed",
        },
        {
            "type": "FileChange",
            "id": "patch-1",
            "changes": {"/repo/a.py": {"type": "update", "unified_diff": "diff"}},
            "stdout": "Success",
            "stderr": "",
            "status": "completed",
        },
    ]:
        await _post(agent, sid, _event("item_completed", timestamp="2026-05-11T17:00:04.000Z", item=item))
    await _post(agent, sid, _response_item("custom_tool_call_output", call_id="batch", output="done"))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 2
    assert json.loads(tools[0]["meta"]["output"]["value"]) == result
    assert tools[1]["meta"]["output"]["value"] == "Success"
    # Wrapper source is opaque; tool identity comes from the structured item.


@pytest.mark.parametrize("has_wrapper_result", [True, False])
async def test_structured_mcp_direct_call_does_not_duplicate(agent, has_wrapper_result):
    sid = "structured-direct"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent, sid, _response_item("function_call", name="mcp__test__read", call_id="mcp-1", arguments='{"key":"a"}')
    )
    await _post(
        agent,
        sid,
        _event(
            "item_completed",
            timestamp="2026-05-11T17:00:04.000Z",
            item={
                "type": "McpToolCall",
                "id": "mcp-1",
                "server": "test",
                "tool": "read",
                "arguments": {"key": "a"},
                "result": {"content": [], "isError": True},
                "status": "failed",
            },
        ),
    )
    if has_wrapper_result:
        await _post(agent, sid, _response_item("function_call_output", call_id="mcp-1", output="wrapper text"))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 1
    assert tools[0]["status"] == "error"
    assert json.loads(tools[0]["meta"]["output"]["value"])["isError"] is True


async def test_late_identical_commands_match_process_ids_and_do_not_repeat_poll_output(agent):
    sid = "structured-parallel"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            name="exec",
            call_id="batch",
            input='await Promise.all([tools.exec_command({cmd:"work"}), tools.exec_command({cmd:"work"})]);',
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            call_id="batch",
            output=[
                {"type": "input_text", "text": json.dumps({"i": i, "value": {"session_id": pid, "output": "partial"}})}
                for i, pid in enumerate([100, 200])
            ],
        ),
    )
    for pid in [200, 100]:
        await _post(
            agent,
            sid,
            _event(
                "item_completed",
                timestamp="2026-05-11T17:00:05.000Z",
                item={
                    "type": "CommandExecution",
                    "id": f"exec-{pid}",
                    "process_id": str(pid),
                    "command": ["/bin/sh", "-lc", "work"],
                    "aggregated_output": f"complete {pid}",
                    "exit_code": 1 if pid == 100 else 0,
                    "status": "completed",
                },
            ),
        )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            name="exec",
            call_id="poll",
            timestamp="2026-05-11T17:00:06.000Z",
            input="text(await tools.write_stdin({session_id:100}));",
        ),
    )
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call_output",
            call_id="poll",
            output={
                "session_id": 100,
                "output": "complete 100",
                "exit_code": 1,
            },
        ),
    )
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 2
    assert sorted(s["meta"]["output"]["value"] for s in tools) == ["complete 100", "complete 200"]
    assert {s["meta"]["output"]["value"]: s["status"] for s in tools} == {"complete 100": "error", "complete 200": "ok"}


async def test_structured_tool_is_captured_when_javascript_has_no_literal_tool_call(agent):
    sid = "structured-dynamic"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            name="exec",
            call_id="batch",
            input="const run = tools.list_mcp_resources; await run({});",
        ),
    )
    await _post(
        agent,
        sid,
        _event(
            "item_completed",
            timestamp="2026-05-11T17:00:04.000Z",
            item={
                "type": "McpToolCall",
                "id": "mcp-1",
                "server": "codex",
                "tool": "list_mcp_resources",
                "arguments": {},
                "result": {"resources": []},
                "status": "completed",
            },
        ),
    )
    await _post(agent, sid, _response_item("custom_tool_call_output", call_id="batch", output=""))
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 1
    assert tools[0]["name"] == "List mcp resources"
    assert json.loads(tools[0]["meta"]["output"]["value"]) == {"resources": []}


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize(
    "server,tool,name,arguments",
    [
        (
            "trajectory",
            "read_mcp_resource",
            "read_mcp_resource",
            {"server": "trajectory", "uri": "trajectory://status"},
        ),
        ("trajectory", "list_mcp_resources", "list_mcp_resources", {"server": "trajectory"}),
        ("trajectory", "list_mcp_resource_templates", "list_mcp_resource_templates", {"server": "trajectory"}),
        ("chrome-devtools", "list_pages", "mcp__chrome_devtools__list_pages", {}),
        (
            "codex_apps",
            "codex_document_control.list_document_sessions",
            "mcp__codex_apps__codex_document_control_list_document_sessions",
            {},
        ),
    ],
)
async def test_structured_mcp_name_variants_produce_one_span(agent, late, server, tool, name, arguments):
    sid = "mcp-name-variants"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    await _post(
        agent,
        sid,
        _response_item(
            "custom_tool_call",
            name="exec",
            call_id="batch",
            input=f"await tools.{name}({json.dumps(arguments)}); await tools.get_goal({{}});",
        ),
    )
    result = {"content": [{"type": "text", "text": "authoritative result"}]}
    completion = _event(
        "item_completed",
        timestamp="2026-05-11T17:00:04.000Z",
        item={
            "type": "McpToolCall",
            "id": "mcp-1",
            "server": server,
            "tool": tool,
            "arguments": arguments,
            "result": result,
            "status": "completed",
        },
    )
    wrapper = _response_item("custom_tool_call_output", call_id="batch", output="summary")
    for record in ([wrapper, completion] if late else [completion, wrapper]):
        await _post(agent, sid, record)
    await _post(agent, sid, _event("task_complete"))
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == 1  # No tool is invented from the JavaScript source.
    mcp = next(s for s in tools if s["name"] != "Get goal")
    assert json.loads(mcp["meta"]["output"]["value"]) == result
    assert mcp["meta"]["metadata"]["tool_id"] == "mcp-1"
    assert mcp["meta"]["metadata"]["raw_tool_name"] == name


@pytest.mark.parametrize("name", ["DD_CODEX_MAX_LLM_MESSAGE_CHARS", "DD_CODEX_MAX_TOOL_VALUE_CHARS"])
def test_codex_optional_limits(monkeypatch, name):
    from lapdog.codex_hooks import _optional_limit
    from lapdog.codex_hooks import _truncate_text

    monkeypatch.delenv(name, raising=False)
    assert _optional_limit(name) is None
    assert _truncate_text("x" * 20000, _optional_limit(name)) == ("x" * 20000, False)
    monkeypatch.setenv(name, "10")
    assert _truncate_text("x" * 20, _optional_limit(name)) == ("x" * 10 + "\n\n[truncated 10 chars]", True)
    monkeypatch.setenv(name, "0")
    assert _truncate_text("output", _optional_limit(name)) == ("", True)


@pytest.mark.parametrize("in_loop", [False, True])
async def test_connector_alias_and_loop_calls_use_structured_invocations(agent, in_loop):
    sid = "connector-loop"
    await _post(agent, sid, _session_meta(sid))
    await _post(agent, sid, _turn_context())
    name = "mcp__codex_apps__enterprise_ai__gmail_mcp__enterprise_ai_gmail_mcp_get_message"
    script = (
        f"await Promise.all(ids.map(message_id=>tools.{name}({{message_id}})));"
        if in_loop
        else f'await tools.{name}({{"message_id":"first"}});'
    )
    await _post(agent, sid, _response_item("custom_tool_call", name="exec", call_id="batch", input=script))
    ids = ["first", "second", "third"] if in_loop else ["first"]
    for message_id in ids:
        await _post(
            agent,
            sid,
            _event(
                "item_completed",
                timestamp="2026-05-11T17:00:04.000Z",
                item={
                    "type": "McpToolCall",
                    "id": "exec-" + message_id,
                    "server": "codex_apps",
                    "tool": "enterprise_ai_gmail_mcp.get_message",
                    "arguments": {"message_id": message_id},
                    "result": {"message": message_id},
                    "status": "completed",
                },
            ),
        )
    await _post(
        agent,
        sid,
        _response_item("custom_tool_call_output", call_id="batch", output="done", timestamp="2026-05-11T17:00:05.000Z"),
    )
    tools = _by_kind(_spans(await (await agent.get("/claude/hooks/spans")).json()), "tool")
    assert len(tools) == len(ids)
    assert len({s["meta"]["metadata"]["tool_id"] for s in tools}) == len(ids)
    assert [json.loads(s["meta"]["output"]["value"])["message"] for s in tools] == ids
    # Wrapper source is opaque; tool identity comes from the structured item.


@pytest.mark.parametrize("proxy_timing", ["before_jsonl", "after_usage", "after_next_response", "absent"])
def test_response_ids_keep_llms_and_delayed_tools_in_their_own_steps(codex_inference, proxy_timing):
    hooks, parser, proxy = codex_inference

    def attach(index):
        span = _proxy_span(proxy, index)
        assert span is not None
        parser.register_proxy_llm_span("session", span, span["start_ns"], span["start_ns"] + span["duration"])

    def dispatch(value):
        parser._dispatch("session", value)

    if proxy_timing == "before_jsonl":
        attach(1)
    dispatch(_custom_call(1, 3))
    dispatch(_usage_record(1, 3.1))
    original_llm = next(s for s in hooks._assembled_spans if s["meta"]["span"]["kind"] == "llm")
    original_id = original_llm["span_id"]
    if proxy_timing == "after_usage":
        attach(1)

    # The next HTTP request starts before the previous tool's JSONL completion
    # reaches Lapdog. That completion must not create a tool-first step.
    dispatch(_command_completion(1, 4.1))
    dispatch(
        _response_item("custom_tool_call_output", timestamp="2026-05-11T17:00:04.200Z", call_id="call-1", output="done")
    )
    dispatch(
        _event("token_count", timestamp="2026-05-11T17:00:04.300Z", info={"last_token_usage": {"input_tokens": 100}})
    )
    dispatch(_custom_call(2, 5))
    dispatch(_usage_record(2, 5.1))
    if proxy_timing == "after_next_response":
        attach(1)
    if proxy_timing != "absent":
        attach(2)
    dispatch(_command_completion(2, 6))
    dispatch(
        _response_item("custom_tool_call_output", timestamp="2026-05-11T17:00:06.100Z", call_id="call-2", output="done")
    )
    dispatch(
        _event("token_count", timestamp="2026-05-11T17:00:06.200Z", info={"last_token_usage": {"input_tokens": 200}})
    )
    dispatch(_usage_record(1, 6.3))  # Same response, different record timestamp.
    dispatch(_event("task_complete", timestamp="2026-05-11T17:00:07.000Z"))

    spans = hooks._assembled_spans
    steps = _by_kind(spans, "step")
    llms = _by_kind(spans, "llm")
    tools = _by_kind(spans, "tool")
    assert len(steps) == len(llms) == len(tools) == 2
    assert llms[0]["span_id"] == original_id
    for index, (step, llm, tool) in enumerate(zip(steps, llms, tools), 1):
        assert llm["parent_id"] == tool["parent_id"] == step["span_id"]
        assert llm["start_ns"] <= tool["start_ns"]
        assert step["start_ns"] <= llm["start_ns"]
        assert step["start_ns"] + step["duration"] >= tool["start_ns"] + tool["duration"]
        assert llm["meta"]["metadata"]["response_id"] == f"resp-{index}"
        assert llm["metrics"]["input_tokens"] == index * 100
        # Wrapper source is opaque; tool identity comes from the structured item.
        assert len(llm["meta"]["output"]["messages"]) == 1


def test_proxy_response_after_turn_completion_replaces_existing_fallback(codex_inference):
    hooks, parser, proxy = codex_inference
    for value in [
        _custom_call(1, 3),
        _usage_record(1, 3.1),
        _response_item(
            "custom_tool_call_output", timestamp="2026-05-11T17:00:04.000Z", call_id="call-1", output="done"
        ),
        _event("task_complete", timestamp="2026-05-11T17:00:05.000Z"),
    ]:
        parser._dispatch("session", value)
    before_ids = [s["span_id"] for s in hooks._assembled_spans]
    for forwarded in hooks._assembled_spans:
        forwarded["tags"].append("lapdog_forwarded:true")
    parser._dispatch("session", _usage_record(1, 6))
    span = _proxy_span(proxy, 1)
    parser.register_proxy_llm_span("session", span, span["start_ns"], span["start_ns"] + span["duration"])
    assert [s["span_id"] for s in hooks._assembled_spans] == before_ids
    llm = next(s for s in hooks._assembled_spans if s["meta"]["span"]["kind"] == "llm")
    assert "source:codex-proxy" in llm["tags"]
    assert "lapdog_forwarded:true" in llm["tags"]
    assert not parser._pending_proxy


def test_response_creation_time_precedes_reasoning_and_tool_output(codex_inference):
    hooks, parser, _ = codex_inference
    for value in [
        _event(
            "item_completed",
            timestamp="2026-05-11T17:00:04.000Z",
            turn_id="turn-1",
            started_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 3000,
            completed_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 3900,
            item={"type": "Reasoning", "id": "reason-1"},
        ),
        _response_item("reasoning", timestamp="2026-05-11T17:00:04.000Z", id="reason-1", summary=[]),
        _custom_call(
            1,
            7,
            internal_chat_message_metadata_passthrough={
                "turn_id": "turn-1",
                "create_time": _INFERENCE_BASE_NS / 1e9 + 2.125,
            },
        ),
        _usage_record(1, 7.01),
        _command_completion(1, 8),
        _response_item(
            "custom_tool_call_output", timestamp="2026-05-11T17:00:08.100Z", call_id="call-1", output="done"
        ),
    ]:
        parser._dispatch("session", value)
    (llm,) = _by_kind(hooks._assembled_spans, "llm")
    (step,) = _by_kind(hooks._assembled_spans, "step")
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    assert llm["start_ns"] == step["start_ns"] == _INFERENCE_BASE_NS + 2_125_000_000
    assert llm["duration"] == 4_885_000_000
    assert llm["meta"]["metadata"]["timing"] == "response_create_time"
    assert tool["start_ns"] > llm["start_ns"] + llm["duration"]
    assert step["start_ns"] + step["duration"] >= tool["start_ns"] + tool["duration"]


@pytest.mark.parametrize("created", [None, "bad", True, float("nan"), float("inf"), 1, _INFERENCE_BASE_NS / 1e9 + 20])
def test_invalid_creation_time_uses_model_item_start(codex_inference, created):
    hooks, parser, _ = codex_inference
    parser._dispatch(
        "session",
        _event(
            "item_completed",
            timestamp="2026-05-11T17:00:05.000Z",
            started_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 2000,
            completed_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 4999,
            item={"type": "AgentMessage", "id": "msg-1"},
        ),
    )
    parser._dispatch(
        "session",
        _response_item(
            "message",
            timestamp="2026-05-11T17:00:05.000Z",
            id="msg-1",
            role="assistant",
            content=[{"type": "output_text", "text": "Done"}],
            internal_chat_message_metadata_passthrough={"create_time": created},
        ),
    )
    parser._dispatch("session", _usage_record(1, 5.01))
    (llm,) = _by_kind(hooks._assembled_spans, "llm")
    assert llm["start_ns"] == _INFERENCE_BASE_NS + 2_000_000_000
    assert llm["duration"] == 3_010_000_000
    assert llm["meta"]["metadata"]["timing"] == "item_completed"


@pytest.mark.parametrize("proxy_first", [True, False])
def test_proxy_timing_takes_precedence_over_response_creation(codex_inference, proxy_first):
    hooks, parser, proxy = codex_inference
    span = _proxy_span(proxy, 1)

    def attach():
        parser.register_proxy_llm_span("session", span, span["start_ns"], span["start_ns"] + span["duration"])

    if proxy_first:
        attach()
    parser._dispatch(
        "session",
        _custom_call(
            1,
            3,
            internal_chat_message_metadata_passthrough={"create_time": _INFERENCE_BASE_NS / 1e9 + 2.5},
        ),
    )
    parser._dispatch("session", _usage_record(1, 3.01))
    if not proxy_first:
        attach()
    (llm,) = _by_kind(hooks._assembled_spans, "llm")
    assert llm["start_ns"] == _INFERENCE_BASE_NS + 2_000_000_000
    assert llm["duration"] == 1_000_000_000
    assert "source:codex-proxy" in llm["tags"]


@pytest.mark.parametrize("late", [True, False])
@pytest.mark.parametrize("kind", ["mcp", "web_search", "web_open", "web_dynamic"])
def test_structured_tool_interval_replaces_wrapper_timing(codex_inference, kind, late):
    hooks, parser, _ = codex_inference
    if kind == "mcp":
        script = 'await tools.mcp__server__read({key:"x"});'
        item = {"type": "McpToolCall", "server": "server", "tool": "read", "arguments": {"key": "x"}, "result": "done"}
    elif kind == "web_search":
        script = 'await tools.web__run({search_query:[{q:"one"},{q:"two"}],open:[{ref_id:"https://example.com"}]});'
        item = {
            "type": "Extension",
            "kind": "web.search",
            "action": {"type": "search", "queries": ["one", "two"]},
            "results": ["done"],
        }
    else:
        script = 'await tools.web__run({open:[{ref_id:"https://example.com"}]});'
        item = {
            "type": "Extension",
            "kind": "web.search",
            "action": {"type": "openPage", "url": "https://example.com"},
            "results": ["done"],
        }
    item.update(id="exec-1", duration={"secs": 1, "nanos": 0})
    if kind == "web_dynamic":
        script = "await tools.web__run(request);"
    call = _custom_call(1, 3)
    call["payload"]["input"] = script
    parser._dispatch("session", call)
    parser._dispatch("session", _usage_record(1, 3.01))
    completed = _event(
        "item_completed",
        timestamp="2026-05-11T17:00:09.000Z" if late else "2026-05-11T17:00:08.751Z",
        item=item,
        started_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 4250,
        completed_at_ms=_INFERENCE_BASE_NS // 1_000_000 + 8751,
    )
    output = _response_item(
        "custom_tool_call_output", timestamp="2026-05-11T17:00:08.900Z", call_id="call-1", output="done"
    )
    for value in ([output, completed] if late else [completed, output]):
        parser._dispatch("session", value)
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    assert tool["start_ns"] == _INFERENCE_BASE_NS + 4_250_000_000
    assert tool["duration"] == 4_501_000_000
    assert tool["meta"]["metadata"]["timing"] == "item_completed"
    # Wrapper source is opaque; tool identity comes from the structured item.
    if kind == "web_search":
        assert json.loads(tool["meta"]["input"]["value"]) == item["action"]


@pytest.mark.parametrize("start,end", [(None, None), (6000, 5000), (5000, 5000), ("4000", 5000), (4000, 9000)])
def test_invalid_tool_interval_preserves_duration_fallback(codex_inference, start, end):
    hooks, parser, _ = codex_inference
    parser._dispatch("session", _custom_call(1, 3))
    parser._dispatch("session", _usage_record(1, 3.01))
    value = _command_completion(1, 6)
    value["payload"].update(
        started_at_ms=_INFERENCE_BASE_NS // 1_000_000 + start if isinstance(start, int) else start,
        completed_at_ms=_INFERENCE_BASE_NS // 1_000_000 + end if isinstance(end, int) else end,
    )
    parser._dispatch("session", value)
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    assert tool["start_ns"] == _INFERENCE_BASE_NS + 5_990_000_000
    assert tool["duration"] == 10_000_000


def test_identical_commands_in_distinct_responses_remain_distinct(codex_inference):
    hooks, parser, _ = codex_inference
    for index in (1, 2):
        call = _custom_call(index, index * 3)
        call["payload"]["input"] = 'await tools.exec_command({cmd:"pwd"});'
        parser._dispatch("session", call)
        parser._dispatch("session", _usage_record(index, index * 3 + 0.1))
        completion = _command_completion(index, index * 3 + 1)
        completion["payload"]["item"]["command"][-1] = "pwd"
        parser._dispatch("session", completion)
    spans = hooks._assembled_spans
    assert len(_by_kind(spans, "llm")) == len(_by_kind(spans, "step")) == len(_by_kind(spans, "tool")) == 2
    assert len({s["parent_id"] for s in _by_kind(spans, "tool")}) == 2


@pytest.mark.parametrize("complete", [True, False])
def test_structured_tool_start_has_one_live_span_until_completion(codex_inference, complete):
    hooks, parser, _ = codex_inference
    parser._dispatch("session", _custom_call(1, 3))
    parser._dispatch("session", _usage_record(1, 3.1))
    item = {"type": "CommandExecution", "id": "command", "command": ["/bin/sh", "-lc", "pwd"]}
    parser._dispatch("session", _event("item_started", timestamp="2026-05-11T17:00:04.000Z", item=item))
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    tool_id = tool["span_id"]
    assert tool["duration"] == 0
    assert tool["meta"]["metadata"]["status"] == "running"
    if complete:
        parser._dispatch(
            "session",
            _event(
                "item_completed",
                timestamp="2026-05-11T17:00:05.000Z",
                item={**item, "exit_code": 0, "aggregated_output": "/repo"},
            ),
        )
    parser._dispatch("session", _event("task_complete", timestamp="2026-05-11T17:00:06.000Z"))
    assert [s["span_id"] for s in _by_kind(hooks._assembled_spans, "tool")] == [tool_id]
    assert tool["status"] == ("ok" if complete else "error")
    assert tool["duration"] == (1 if complete else 2) * 1_000_000_000


def test_late_completion_updates_closed_turn_without_reopening_it(codex_inference):
    hooks, parser, _ = codex_inference
    parser._dispatch("session", _custom_call(1, 3))
    parser._dispatch("session", _usage_record(1, 3.1))
    parser._dispatch("session", _event("task_complete", timestamp="2026-05-11T17:00:04.000Z"))
    parser._dispatch("session", _turn_context("turn-2"))
    completion = _command_completion(1, 5)
    completion["payload"]["turn_id"] = "turn-1"
    parser._dispatch("session", completion)
    completion["timestamp"] = "2026-05-11T17:00:06.000Z"
    parser._dispatch("session", completion)
    roots = [s for s in hooks._assembled_spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    assert tool["trace_id"] == roots[0]["trace_id"]
    assert roots[1]["duration"] == 0
    assert len(_by_kind(hooks._assembled_spans, "step")) == 1


def test_completed_state_expires_without_losing_canonical_spans(codex_inference, monkeypatch):
    from lapdog import codex_hooks

    hooks, parser, proxy = codex_inference
    parser._dispatch("session", _custom_call(1, 3))
    parser._dispatch("session", _usage_record(1, 3.1))
    parser._dispatch("session", _event("task_complete"))
    response = parser._responses[("session", "resp-1")][2]
    assert response.inputs == response.output == response.reasoning == []
    orphan = _proxy_span(proxy, 2)
    parser.register_proxy_llm_span(None, orphan, orphan["start_ns"], orphan["start_ns"] + orphan["duration"])
    parser._dispatch("review", {"type": "session_meta", "payload": {"thread_source": "guardian_review"}})
    parser._dispatch("review", _event("task_complete", root_turn_id="unknown"))
    assert parser._pending_reviews
    ids = [s["span_id"] for s in hooks._assembled_spans]
    now = codex_hooks.time.monotonic()
    monkeypatch.setattr(codex_hooks.time, "monotonic", lambda: now + codex_hooks.LATE_EVENT_SECONDS + 1)
    parser._expire()
    assert not parser._turns
    assert not parser._responses
    assert not parser._pending_proxy
    assert not parser._pending_reviews
    assert not parser._sessions
    assert [s["span_id"] for s in hooks._assembled_spans] == ids
    late = _command_completion(1, 6)
    late["payload"]["turn_id"] = "turn-1"
    parser._dispatch("session", late)
    assert [s["span_id"] for s in hooks._assembled_spans] == ids


@pytest.mark.parametrize("body", [None, [], "invalid", {"session_id": "s", "record": None}])
async def test_codex_hook_rejects_invalid_record_shapes(agent, body):
    response = await agent.post("/codex/hooks", data=json.dumps(body), headers={"Content-Type": "application/json"})
    assert response.status == 400


@pytest.mark.parametrize("command", [["/bin/sh", "-c", "pwd"], ["git", "status", "--short"]])
@pytest.mark.parametrize("completion_first", [False, True])
@pytest.mark.parametrize("extra_args", [{}, {"workdir": "/repo", "yield_time_ms": 1000}])
def test_direct_call_and_structured_item_share_one_tool(codex_inference, command, completion_first, extra_args):
    hooks, parser, _ = codex_inference
    cmd = "pwd" if command[0] == "/bin/sh" else "git status --short"
    parser._dispatch("session", _event("exec_approval_request", call_id="call", command=command))
    call = _response_item(
        "function_call", name="exec_command", call_id="call", arguments=json.dumps({"cmd": cmd, **extra_args})
    )
    parser._dispatch("session", call)
    parser._dispatch("session", {**call, "timestamp": "2026-05-11T17:00:02.100Z"})
    assert len(_by_kind(hooks._assembled_spans, "tool")) == 1
    completion = _event(
        "item_completed",
        timestamp="2026-05-11T17:00:04.000Z",
        item={
            "type": "CommandExecution",
            "id": "item",
            "command": command,
            "status": "completed",
            "aggregated_output": "result",
            "duration": {"secs": 1, "nanos": 0},
        },
    )
    output = _response_item(
        "function_call_output", call_id="call", output="result", timestamp="2026-05-11T17:00:03.000Z"
    )
    for record in ([completion, output] if completion_first else [output, completion]):
        parser._dispatch("session", record)
    parser._dispatch("session", _event("task_complete", timestamp="2026-05-11T17:00:05.000Z"))
    (tool,) = _by_kind(hooks._assembled_spans, "tool")
    assert json.loads(tool["meta"]["input"]["value"]) == {"cmd": cmd, **extra_args}
    assert tool["meta"]["metadata"]["item_id"] == "item"
    assert tool["meta"]["output"]["value"] == "result"
    approval = hooks._assembled_spans[0]["meta"]["metadata"]["_dd"]["codex_approvals"][0]
    assert approval["status"] == "completed"


@pytest.mark.parametrize("paths,expected_tools", [(["a.txt"], 1), (["a.txt", "a.txt"], 3), (["b.txt"], 2)])
@pytest.mark.parametrize("completion_first", [False, True])
def test_direct_patch_matches_only_one_structured_result(codex_inference, paths, expected_tools, completion_first):
    hooks, parser, _ = codex_inference
    for index, path in enumerate(paths):
        parser._dispatch(
            "session",
            _response_item(
                "custom_tool_call",
                name="apply_patch",
                call_id=f"patch-{index}",
                input=f"*** Begin Patch\n*** Update File: {path}\n@@\n-old\n+new\n*** End Patch",
            ),
        )
    completion = _event(
        "item_completed",
        timestamp="2026-05-11T17:00:04.000Z",
        item={
            "type": "FileChange",
            "id": "item",
            "changes": {"/repo/a.txt": {"type": "update"}},
            "stdout": "updated",
            "status": "completed",
            "duration": {"secs": 1},
        },
    )
    outputs = [
        _response_item("custom_tool_call_output", call_id=f"patch-{index}", output="updated")
        for index in range(len(paths))
    ]
    for record in ([completion, *outputs] if completion_first else [*outputs, completion]):
        parser._dispatch("session", record)
    parser._dispatch("session", _event("task_complete", timestamp="2026-05-11T17:00:05.000Z"))
    tools = _by_kind(hooks._assembled_spans, "tool")
    assert len(tools) == expected_tools
    structured = next(span for span in tools if span["meta"]["metadata"].get("item_id") == "item")
    assert structured["meta"]["output"]["value"] == "updated"
    if expected_tools == 1:
        assert structured["meta"]["metadata"]["call_id"] == "patch-0"
        assert "*** Update File: a.txt" in structured["meta"]["input"]["value"]


@pytest.mark.parametrize("decision", ["not JSON", "[]", "null"])
def test_review_invalid_decision_does_not_attach(codex_inference, decision):
    hooks, parser, _ = codex_inference
    parser._dispatch("session", _custom_call(1, 2))
    parser._dispatch("session", _command_completion(1, 6))
    parser._dispatch("session", _event("task_complete", timestamp="2026-05-11T17:00:07.000Z"))
    parser._dispatch(
        "review",
        _event(
            "task_started",
            turn_id="r",
            root_turn_id="turn-1",
            turn_attribution={"turn_trigger": "guardian_review"},
            timestamp="2026-05-11T17:00:04.000Z",
        ),
    )
    parser._dispatch("review", _response_item("message", role="assistant", content=decision))
    parser._dispatch("review", _event("task_complete", timestamp="2026-05-11T17:00:05.000Z"))
    assert all("auto_reviews" not in span["meta"]["metadata"].get("_dd", {}) for span in hooks._assembled_spans)
    assert not any(span["session_id"] == "review" for span in hooks._assembled_spans)


def test_structured_item_does_not_merge_with_same_command_in_another_response(codex_inference):
    hooks, parser, _ = codex_inference
    for record in [
        _response_item("function_call", name="exec_command", call_id="direct", arguments='{"cmd":"echo 2"}'),
        _response_item("function_call_output", call_id="direct", output="first"),
        _usage_record(1, 2.5),
        _custom_call(2, 3),
        _usage_record(2, 3.5),
        _command_completion(2, 4),
    ]:
        parser._dispatch("session", record)
    tools = _by_kind(hooks._assembled_spans, "tool")
    assert len(tools) == 2
    assert tools[0]["meta"]["output"]["value"] == "first"
    assert tools[1]["meta"]["output"]["value"] == "2"
    assert tools[0]["parent_id"] != tools[1]["parent_id"]


@pytest.mark.parametrize(
    "event_type,kind,closed",
    [
        ("item_started", "CommandExecution", True),
        ("item_completed", "Unknown", False),
        ("item_completed", "CommandExecution", True),
    ],
)
def test_unusable_item_does_not_create_spans(codex_inference, event_type, kind, closed):
    hooks, parser, _ = codex_inference
    if closed:
        parser._dispatch("session", _event("task_complete"))
    before = len(hooks._assembled_spans)
    parser._dispatch(
        "session",
        _event(
            event_type,
            turn_id="turn-1",
            item={
                "type": kind,
                "id": "unused",
                "command": ["pwd"],
            },
        ),
    )
    assert len(hooks._assembled_spans) == before


def test_codex_indexes_evict_without_removing_spans(codex_inference, monkeypatch):
    from lapdog import codex_hooks

    hooks, parser, _ = codex_inference
    monkeypatch.setattr(codex_hooks, "RECENT_TURNS", 2)
    monkeypatch.setattr(codex_hooks, "RECENT_RECORDS", 3)
    for index in range(4):
        parser._dispatch("session", _turn_context(f"bounded-{index}"))
        parser._dispatch("session", _event("task_complete", turn_id=f"bounded-{index}"))
        parser._dispatch(f"review-{index}", {"type": "session_meta", "payload": {"thread_source": "guardian_review"}})
    parser._expire()
    assert len(parser._turns) <= 2
    assert len(parser._reviews) == 2
    assert len(parser._seen) == 3
    assert ("session", "bounded-3") in parser._turns
    assert len(_by_kind(hooks._assembled_spans, "agent")) == 5
