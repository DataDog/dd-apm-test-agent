"""Tests for Claude Code ``step`` span kind — one span per inference cycle."""

import subprocess
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from ddapm_test_agent._clock import monotonic_wall_ns
from ddapm_test_agent.claude_hooks import ClaudeHooksAPI
from ddapm_test_agent.claude_link_tracker import ClaudeLinkTracker
from ddapm_test_agent.claude_proxy import ClaudeProxyAPI

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _make_apis():
    link_tracker = ClaudeLinkTracker()
    hooks_api = ClaudeHooksAPI(link_tracker=link_tracker)
    proxy_api = ClaudeProxyAPI(hooks_api=hooks_api, link_tracker=link_tracker)
    return hooks_api, proxy_api, link_tracker


def _session_start(session_id: str, instrumented: bool = True) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "hook_event_name": "SessionStart",
        "model": "claude-sonnet-4-5-20250929",
        "lapdog_instrumented": instrumented,
    }


def _user_prompt(session_id: str, prompt: str = "hi") -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "hook_event_name": "UserPromptSubmit",
        "user_prompt": prompt,
    }


def _pre_tool(session_id: str, name: str, tool_use_id: str, **input_: Any) -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": name,
        "tool_use_id": tool_use_id,
        "tool_input": input_,
    }


def _post_tool(session_id: str, name: str, tool_use_id: str, response: str = "ok") -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "hook_event_name": "PostToolUse",
        "tool_name": name,
        "tool_use_id": tool_use_id,
        "tool_response": response,
    }


def _stop(session_id: str) -> Dict[str, Any]:
    return {"session_id": session_id, "hook_event_name": "Stop"}


def _subagent_start(session_id: str, name: str = "explore-agent") -> Dict[str, Any]:
    return {
        "session_id": session_id,
        "hook_event_name": "SubagentStart",
        "agent_type": name,
    }


def _subagent_stop(session_id: str) -> Dict[str, Any]:
    return {"session_id": session_id, "hook_event_name": "SubagentStop"}


def _response(
    tool_uses: Optional[List[Dict[str, Any]]] = None,
    text: str = "",
    stop_reason: str = "end_turn",
    thinking: str = "",
    model: str = "claude-sonnet-4-5-20250929",
) -> Dict[str, Any]:
    content: List[Dict[str, Any]] = []
    if thinking:
        content.append({"type": "thinking", "thinking": thinking})
    if text:
        content.append({"type": "text", "text": text})
    for tu in tool_uses or []:
        content.append({"type": "tool_use", "id": tu["id"], "name": tu["name"], "input": tu.get("input", {})})
    return {
        "model": model,
        "content": content,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        },
    }


def _request(messages: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {"messages": messages or [{"role": "user", "content": "hi"}]}


def _simulate_llm_call(
    proxy_api: ClaudeProxyAPI,
    session_id: str,
    response_data: Dict[str, Any],
    request_body: Optional[Dict[str, Any]] = None,
    start_ns: Optional[int] = None,
    duration_ns: int = 10_000_000,
) -> Dict[str, Any]:
    """Call _create_llm_span directly (bypasses HTTP) and append the span."""
    if start_ns is None:
        start_ns = monotonic_wall_ns()
    session = proxy_api._hooks_api._sessions.get(session_id)
    span = proxy_api._create_llm_span(
        session=session,
        request_body=request_body or _request(),
        response_data=response_data,
        start_ns=start_ns,
        duration_ns=duration_ns,
    )
    proxy_api._hooks_api._assembled_spans.append(span)
    return span


def _spans_for_session(hooks_api: ClaudeHooksAPI, session_id: str) -> List[Dict[str, Any]]:
    return [s for s in hooks_api._assembled_spans if s.get("session_id") == session_id]


def _by_kind(spans: List[Dict[str, Any]], kind: str) -> List[Dict[str, Any]]:
    return [s for s in spans if s.get("meta", {}).get("span", {}).get("kind") == kind]


def _find_root(spans: List[Dict[str, Any]]) -> Dict[str, Any]:
    return [s for s in spans if s["parent_id"] == "undefined"][0]


def _git(repo: Any, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _init_repo(path: Any, remote: str) -> str:
    _git(path, "init")
    _git(path, "config", "user.email", "qa@local")
    _git(path, "config", "user.name", "QA")
    _git(path, "remote", "add", "origin", remote)
    (path / "README.md").write_text("# repo\n")
    _git(path, "add", "-A")
    _git(path, "commit", "-m", "initial commit")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


def test_instrumented_session_creates_step():
    """Step span sits between the root agent and its LLM + tool children."""
    sid = "sess-step-basic"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    llm_span = _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-1", "name": "Bash", "input": {"command": "ls"}}], stop_reason="tool_use"),
    )

    hooks_api._dispatch_hook(_pre_tool(sid, "Bash", "tu-1", command="ls"))
    hooks_api._dispatch_hook(_post_tool(sid, "Bash", "tu-1", "file1\nfile2"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    root = _find_root(spans)
    steps = _by_kind(spans, "step")
    tools = _by_kind(spans, "tool")

    assert len(steps) == 1
    step = steps[0]
    assert step["parent_id"] == root["span_id"]
    assert step["name"] == "inference-0"
    assert step["meta"]["span"]["kind"] == "step"
    assert llm_span["parent_id"] == step["span_id"]

    assert len(tools) == 1
    assert tools[0]["parent_id"] == step["span_id"]


def test_non_instrumented_session_no_step():
    """Without `lapdog_instrumented=True`, no step spans are created."""
    sid = "sess-no-instr"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid, instrumented=False))
    hooks_api._dispatch_hook(_user_prompt(sid))

    llm_span = _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-1", "name": "Bash"}], stop_reason="tool_use"),
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Bash", "tu-1"))
    hooks_api._dispatch_hook(_post_tool(sid, "Bash", "tu-1"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    assert _by_kind(spans, "step") == []

    # LLM and tool still parent to the root (flat hierarchy).
    root = _find_root(spans)
    assert llm_span["parent_id"] == root["span_id"]
    tools = _by_kind(spans, "tool")
    assert len(tools) == 1
    assert tools[0]["parent_id"] == root["span_id"]


def test_multiple_inferences_produce_sibling_steps():
    """Three LLM calls in one turn → three step siblings under root."""
    sid = "sess-multi-step"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    base_ns = 1_000_000_000_000
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-1", "name": "Read"}], stop_reason="tool_use"),
        start_ns=base_ns,
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Read", "tu-1"))
    hooks_api._dispatch_hook(_post_tool(sid, "Read", "tu-1"))

    _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-2", "name": "Edit"}], stop_reason="tool_use"),
        start_ns=base_ns + 100_000_000,
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Edit", "tu-2"))
    hooks_api._dispatch_hook(_post_tool(sid, "Edit", "tu-2"))

    _simulate_llm_call(
        proxy_api,
        sid,
        _response(text="All done.", stop_reason="end_turn"),
        start_ns=base_ns + 200_000_000,
    )
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    root = _find_root(spans)
    steps = _by_kind(spans, "step")

    assert len(steps) == 3
    names = sorted(s["name"] for s in steps)
    assert names == ["inference-0", "inference-1", "inference-2"]
    for step in steps:
        assert step["parent_id"] == root["span_id"]


def test_step_without_tools():
    """Text-only LLM response produces a step with no tool children."""
    sid = "sess-text-only"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    llm_span = _simulate_llm_call(
        proxy_api,
        sid,
        _response(text="Hello!", stop_reason="end_turn"),
    )
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    assert len(steps) == 1
    step = steps[0]
    assert llm_span["parent_id"] == step["span_id"]
    assert _by_kind(spans, "tool") == []
    # Stop finalizes the step with non-zero duration.
    assert step["duration"] > 0
    assert step["meta"]["metadata"]["stop_reason"] == "end_turn"


def test_step_duration_spans_to_next_llm():
    """Prior step ends exactly at next LLM's start_ns (no overlap, no gap)."""
    sid = "sess-duration"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    t0 = 2_000_000_000_000
    t1 = t0 + 50_000_000
    t2 = t1 + 30_000_000
    _simulate_llm_call(proxy_api, sid, _response(text="first"), start_ns=t0)
    _simulate_llm_call(proxy_api, sid, _response(text="second"), start_ns=t1)
    _simulate_llm_call(proxy_api, sid, _response(text="third"), start_ns=t2)
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = sorted(_by_kind(spans, "step"), key=lambda s: s["start_ns"])
    assert len(steps) == 3

    # Step[0] ends at step[1] start; step[1] ends at step[2] start.
    assert steps[0]["start_ns"] + steps[0]["duration"] == steps[1]["start_ns"]
    assert steps[1]["start_ns"] + steps[1]["duration"] == steps[2]["start_ns"]
    # Last step ends at or after the Stop event.
    assert steps[2]["duration"] > 0


def test_subagent_has_own_step():
    """A subagent gets its own step, independent of the root agent's steps."""
    sid = "sess-subagent-step"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    # Root agent inference with a Task tool that spawns a subagent.
    hooks_api._dispatch_hook(_pre_tool(sid, "Task", "task-1", description="sub", prompt="do it"))
    hooks_api._dispatch_hook(_subagent_start(sid))

    # Subagent's LLM call — parent resolves to the subagent stack top.
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-sub-1", "name": "Grep"}], stop_reason="tool_use"),
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Grep", "tu-sub-1"))
    hooks_api._dispatch_hook(_post_tool(sid, "Grep", "tu-sub-1"))
    hooks_api._dispatch_hook(_subagent_stop(sid))
    hooks_api._dispatch_hook(_post_tool(sid, "Task", "task-1", "result"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    agent_spans = _by_kind(spans, "agent")

    # One step, parented to the subagent (not the root).
    assert len(steps) == 1
    step = steps[0]
    subagents = [a for a in agent_spans if a["parent_id"] != "undefined"]
    assert len(subagents) == 1
    assert step["parent_id"] == subagents[0]["span_id"]

    # The Grep tool is parented to the step.
    tools = _by_kind(spans, "tool")
    grep = [t for t in tools if t["name"].startswith("Grep")][0]
    assert grep["parent_id"] == step["span_id"]


def test_interrupted_turn_finalizes_open_step():
    """A new UserPromptSubmit before Stop marks the open step as errored."""
    sid = "sess-interrupted"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid, "first"))
    _simulate_llm_call(proxy_api, sid, _response(tool_uses=[{"id": "tu-1", "name": "Read"}]))
    hooks_api._dispatch_hook(_pre_tool(sid, "Read", "tu-1"))
    # Simulate Ctrl+C — no PostToolUse, no Stop.
    hooks_api._dispatch_hook(_user_prompt(sid, "second"))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    # The first turn's open step is now finalized.
    assert len(steps) == 1
    step = steps[0]
    assert step["status"] == "error"
    assert step["duration"] > 0
    assert step["meta"]["error"]["message"] == "interrupted"


def test_stop_finalizes_open_step():
    """Stop populates duration and metadata on the active step."""
    sid = "sess-stop-finalizes"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(text="done", stop_reason="end_turn"),
    )
    hooks_api._dispatch_hook(_stop(sid))

    step = _by_kind(_spans_for_session(hooks_api, sid), "step")[0]
    assert step["duration"] > 0
    metadata = step["meta"]["metadata"]
    assert metadata["message_index"] == 0
    assert metadata["stop_reason"] == "end_turn"


def test_step_metadata_populated():
    """Text + thinking + tool_use all show up in step metadata."""
    sid = "sess-meta"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(
            text="I'll read the file.",
            thinking="Let me think about this.",
            tool_uses=[
                {"id": "tu-1", "name": "Read"},
                {"id": "tu-2", "name": "Bash"},
            ],
            stop_reason="tool_use",
        ),
    )
    hooks_api._dispatch_hook(_stop(sid))

    step = _by_kind(_spans_for_session(hooks_api, sid), "step")[0]
    meta = step["meta"]["metadata"]
    assert meta["message_index"] == 0
    assert meta["tool_use_ids"] == ["tu-1", "tu-2"]
    assert meta["has_thinking"] is True
    assert meta["stop_reason"] == "tool_use"


def test_step_output_value_is_assistant_text():
    """``meta.output.value`` on the step equals the concatenated text blocks."""
    sid = "sess-output"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))
    _simulate_llm_call(
        proxy_api,
        sid,
        {
            "model": "claude-sonnet-4-5-20250929",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 1,
                "output_tokens": 1,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            "content": [
                {"type": "text", "text": "first block"},
                {"type": "text", "text": "second block"},
            ],
        },
    )
    hooks_api._dispatch_hook(_stop(sid))

    step = _by_kind(_spans_for_session(hooks_api, sid), "step")[0]
    assert step["meta"]["output"]["value"] == "first block\n\nsecond block"


def test_step_has_semantic_type_tag():
    sid = "sess-tag"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))
    _simulate_llm_call(proxy_api, sid, _response(text="ok"))
    hooks_api._dispatch_hook(_stop(sid))

    step = _by_kind(_spans_for_session(hooks_api, sid), "step")[0]
    assert "trajectory.semantic_type:agent_message" in step["tags"]


def test_proxy_llm_span_uses_session_base_tags_with_git_commit_sha(tmp_path, monkeypatch):
    from ddapm_test_agent.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    sha = _init_repo(tmp_path, "https://github.com/DataDog/claude-project.git")

    sid = "sess-proxy-commit-sha"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook({**_session_start(sid), "cwd": str(tmp_path)})
    hooks_api._dispatch_hook({**_user_prompt(sid), "cwd": str(tmp_path)})
    llm_span = _simulate_llm_call(proxy_api, sid, _response(text="ok"))

    assert f"git.commit.sha:{sha}" in llm_span["tags"]
    assert "git.repository_url:github.com/DataDog/claude-project" in llm_span["tags"]
    assert "source:claude-code-proxy" in llm_span["tags"]


def test_concurrent_subagents_each_have_steps():
    """Two concurrent subagents each get their own step, parented correctly."""
    sid = "sess-concurrent-steps"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    hooks_api._dispatch_hook(_pre_tool(sid, "Task", "task-A", description="a", prompt="search-foo"))
    hooks_api._dispatch_hook(_pre_tool(sid, "Task", "task-B", description="b", prompt="read-bar"))
    hooks_api._dispatch_hook(_subagent_start(sid))
    hooks_api._dispatch_hook(_subagent_start(sid))

    # Two concurrent subagents are on the stack; send one LLM call per subagent.
    # Route each by making the subagent's task_prompt appear in the request body.
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-a", "name": "Grep"}], stop_reason="tool_use"),
        request_body={"messages": [{"role": "user", "content": "search-foo please"}]},
    )
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-b", "name": "Read"}], stop_reason="tool_use"),
        request_body={"messages": [{"role": "user", "content": "read-bar please"}]},
    )

    hooks_api._dispatch_hook(_pre_tool(sid, "Grep", "tu-a"))
    hooks_api._dispatch_hook(_post_tool(sid, "Grep", "tu-a"))
    hooks_api._dispatch_hook(_pre_tool(sid, "Read", "tu-b"))
    hooks_api._dispatch_hook(_post_tool(sid, "Read", "tu-b"))
    hooks_api._dispatch_hook(_subagent_stop(sid))
    hooks_api._dispatch_hook(_subagent_stop(sid))
    hooks_api._dispatch_hook(_post_tool(sid, "Task", "task-A", "done"))
    hooks_api._dispatch_hook(_post_tool(sid, "Task", "task-B", "done"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    subagents = [a for a in _by_kind(spans, "agent") if a["parent_id"] != "undefined"]

    assert len(subagents) == 2
    assert len(steps) == 2
    # Each step's parent must be one of the subagents.
    sub_ids = {a["span_id"] for a in subagents}
    for step in steps:
        assert step["parent_id"] in sub_ids
    # The two steps must not share a parent (one per subagent).
    assert steps[0]["parent_id"] != steps[1]["parent_id"]


def test_consecutive_inferences_with_tool_result_are_siblings():
    """Regression: when LLM N+1's request carries a tool_result for tool-N,
    the parent_hint returned by the link tracker must resolve to the agent
    (not to step-N), so step-(N+1) opens as a sibling of step-N — never as
    a child. Without this, the tool_result correlation path produces
    step-under-step nesting.
    """
    sid = "sess-step-nesting"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    base_ns = 1_000_000_000_000

    # LLM-1 dispatches tool-1
    llm1 = _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-1", "name": "Read"}], stop_reason="tool_use"),
        start_ns=base_ns,
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Read", "tu-1"))
    hooks_api._dispatch_hook(_post_tool(sid, "Read", "tu-1"))

    # LLM-2 request carries a tool_result for tu-1 — this is the path
    # that previously re-parented step-2 to step-1.
    request_with_tool_result = {
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu-1", "content": "ok"},
                ],
            },
        ],
    }
    llm2 = _simulate_llm_call(
        proxy_api,
        sid,
        _response(tool_uses=[{"id": "tu-2", "name": "Edit"}], stop_reason="tool_use"),
        request_body=request_with_tool_result,
        start_ns=base_ns + 100_000_000,
    )
    hooks_api._dispatch_hook(_pre_tool(sid, "Edit", "tu-2"))
    hooks_api._dispatch_hook(_post_tool(sid, "Edit", "tu-2"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    root = _find_root(spans)
    steps = _by_kind(spans, "step")
    tools = _by_kind(spans, "tool")

    assert len(steps) == 2
    names = sorted(s["name"] for s in steps)
    assert names == ["inference-0", "inference-1"]

    # No step may parent to another step — siblings under root.
    step_ids = {s["span_id"] for s in steps}
    for step in steps:
        assert step["parent_id"] == root["span_id"]
        assert step["parent_id"] not in step_ids

    # LLMs parent to their respective steps.
    step0 = next(s for s in steps if s["name"] == "inference-0")
    step1 = next(s for s in steps if s["name"] == "inference-1")
    assert llm1["parent_id"] == step0["span_id"]
    assert llm2["parent_id"] == step1["span_id"]

    # Tools parent to the step that dispatched them.
    tool1 = next(t for t in tools if "Read" in t.get("name", ""))
    tool2 = next(t for t in tools if "Edit" in t.get("name", ""))
    assert tool1["parent_id"] == step0["span_id"]
    assert tool2["parent_id"] == step1["span_id"]


def test_pretool_race_with_llm_span_creation():
    """Regression: parallel tools stay under the step even when PreToolUse
    fires before ``_create_llm_span`` finishes (streaming-proxy race).

    Claude Code's streaming proxy can hand back a response and trigger
    PreToolUse before the proxy's span-creation task populates the link
    tracker. Without re-resolution at PostToolUse, ``pending.parent_id``
    stays frozen at the PreToolUse-time fallback (the current agent),
    producing tool spans parented to the agent instead of the step.
    """
    sid = "sess-pretool-race"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    # PreToolUse arrives BEFORE the LLM span is created. get_parent_for_tool
    # returns None; pending.parent_id falls back to the root agent.
    hooks_api._dispatch_hook(_pre_tool(sid, "Bash", "tu-A", command="a"))
    hooks_api._dispatch_hook(_pre_tool(sid, "Bash", "tu-B", command="b"))

    # LLM span creation registers the tool_use ids and sets
    # _llm_span_parents[llm_id] = step_span_id.
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(
            tool_uses=[
                {"id": "tu-A", "name": "Bash", "input": {"command": "a"}},
                {"id": "tu-B", "name": "Bash", "input": {"command": "b"}},
            ],
            stop_reason="tool_use",
        ),
    )

    hooks_api._dispatch_hook(_post_tool(sid, "Bash", "tu-A", "out-a"))
    hooks_api._dispatch_hook(_post_tool(sid, "Bash", "tu-B", "out-b"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    tools = _by_kind(spans, "tool")

    assert len(steps) == 1
    step = steps[0]
    assert len(tools) == 2
    for tool in tools:
        assert (
            tool["parent_id"] == step["span_id"]
        ), f"{tool['name']} parented to {tool['parent_id']!r}, expected step {step['span_id']!r}"


def test_subagent_posttool_race_reparents_under_step():
    """Regression: a sub-agent's tools land under the sub-agent's step even
    when PreToolUse *and* PostToolUse fire before the proxy finishes building
    the sub-agent's LLM span.

    This is the bug behind the original report: fast tools (e.g. Glob)
    inside a sub-agent complete before the streamed LLM response is parsed
    by the proxy, so the link tracker can't map ``tool_use_id -> llm_span
    -> step`` at PostToolUse time. The tool span is emitted with the sub-
    agent as parent. Step creation must retroactively repair it.
    """
    sid = "sess-subagent-race"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    # Root agent dispatches Task and a sub-agent starts. No LLM calls have
    # been observed yet (simulating the tight race where the root agent's
    # LLM span hasn't been created either, but we focus on the sub-agent
    # below).
    hooks_api._dispatch_hook(_pre_tool(sid, "Task", "task-1", description="sub", prompt="do it"))
    hooks_api._dispatch_hook(_subagent_start(sid))

    # Sub-agent's fast tools race ahead of its LLM span creation.
    hooks_api._dispatch_hook(_pre_tool(sid, "Glob", "tu-A", pattern="*.py"))
    hooks_api._dispatch_hook(_post_tool(sid, "Glob", "tu-A", "a.py\nb.py"))
    hooks_api._dispatch_hook(_pre_tool(sid, "Read", "tu-B", file_path="/tmp/x"))
    hooks_api._dispatch_hook(_post_tool(sid, "Read", "tu-B", "contents"))

    # Proxy finally finishes the sub-agent's LLM span. It knows the
    # tool_use_ids the inference produced and must retroactively re-parent
    # the already-emitted tool spans under the just-created step.
    _simulate_llm_call(
        proxy_api,
        sid,
        _response(
            tool_uses=[
                {"id": "tu-A", "name": "Glob", "input": {"pattern": "*.py"}},
                {"id": "tu-B", "name": "Read", "input": {"file_path": "/tmp/x"}},
            ],
            stop_reason="tool_use",
        ),
    )

    hooks_api._dispatch_hook(_subagent_stop(sid))
    hooks_api._dispatch_hook(_post_tool(sid, "Task", "task-1", "result"))
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    steps = _by_kind(spans, "step")
    tools = _by_kind(spans, "tool")
    agents = _by_kind(spans, "agent")
    subagents = [a for a in agents if a["parent_id"] != "undefined"]

    # Single sub-agent, single step under it.
    assert len(subagents) == 1
    subagent = subagents[0]
    sub_steps = [s for s in steps if s["parent_id"] == subagent["span_id"]]
    assert len(sub_steps) == 1
    sub_step = sub_steps[0]

    # Both sub-agent tools are parented to the sub-agent's step, not the
    # sub-agent directly.
    sub_tools = [t for t in tools if t["name"].startswith(("Glob", "Read"))]
    assert len(sub_tools) == 2
    for tool in sub_tools:
        assert tool["parent_id"] == sub_step["span_id"], (
            f"{tool['name']} parented to {tool['parent_id']!r}, " f"expected sub-agent step {sub_step['span_id']!r}"
        )


def test_context_delta_attached_to_root_agent_through_step():
    """Root agent span carries ``context_delta`` aggregated from LLM spans
    that sit under its step children. Instrumented sessions interpose a
    ``step`` span between agent and llm, so the lookup must traverse it.
    """
    sid = "sess-context-delta-step"
    hooks_api, proxy_api, _ = _make_apis()

    hooks_api._dispatch_hook(_session_start(sid))
    hooks_api._dispatch_hook(_user_prompt(sid))

    llm_span = _simulate_llm_call(
        proxy_api,
        sid,
        _response(text="Hello!", stop_reason="end_turn"),
    )
    hooks_api._dispatch_hook(_stop(sid))

    spans = _spans_for_session(hooks_api, sid)
    root = _find_root(spans)
    step = _by_kind(spans, "step")[0]

    assert llm_span["parent_id"] == step["span_id"]
    assert step["parent_id"] == root["span_id"]

    context_delta = root.get("meta", {}).get("metadata", {}).get("_dd", {}).get("context_delta")
    assert context_delta is not None, "context_delta missing on root agent span"
    assert context_delta["last_input_tokens"] == 100
