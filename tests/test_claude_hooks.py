import asyncio
import gzip
import json
import os
import subprocess
import tempfile
from typing import Any
from typing import Dict
from typing import List

import msgpack

from ddapm_test_agent import claude_hooks as claude_hooks_module
from ddapm_test_agent.claude_hooks import ClaudeHooksAPI
from ddapm_test_agent.claude_link_tracker import ClaudeLinkTracker
from ddapm_test_agent.claude_proxy import ClaudeProxyAPI


async def _post_hook(agent, event):
    return await agent.post(
        "/claude/hooks",
        headers={"Content-Type": "application/json"},
        data=json.dumps(event),
    )


async def test_hook_endpoint_returns_ok(agent):
    resp = await _post_hook(
        agent,
        {
            "session_id": "sess-1",
            "hook_event_name": "Notification",
            "message": "hello",
        },
    )
    assert resp.status == 200
    body = await resp.json()
    assert body["status"] == "ok"


async def test_hook_missing_session_id(agent):
    resp = await _post_hook(agent, {"hook_event_name": "Notification"})
    assert resp.status == 400
    body = await resp.json()
    assert "session_id" in body["error"]


async def test_trace_forwarding_chunks_payloads_at_twenty_spans(monkeypatch):
    cases = [
        (20, [20]),
        (21, [20, 1]),
        (45, [20, 20, 5]),
    ]
    for span_count, expected_chunk_sizes in cases:
        hooks = ClaudeHooksAPI()
        session = hooks._get_or_create_session(f"chunk-session-{span_count}")
        trace_id = f"chunk-trace-{span_count}"
        session.trace_id = trace_id
        hooks._assembled_spans = [
            {
                "span_id": str(index),
                "trace_id": trace_id,
                "tags": [],
            }
            for index in range(span_count)
        ]
        posted_payloads = []
        descriptions = []

        monkeypatch.setattr(
            hooks,
            "_resolve_backend_target",
            lambda *args, **kwargs: ("http://backend.example/api/v2/llmobs", {"Content-Type": "application/msgpack"}),
        )

        async def fake_post_to_backend(url, headers, data, description):
            assert url == "http://backend.example/api/v2/llmobs"
            assert headers["Content-Type"] == "application/msgpack"
            posted_payloads.append(msgpack.unpackb(gzip.decompress(data), raw=False))
            descriptions.append(description)

        monkeypatch.setattr(hooks, "_post_to_backend", fake_post_to_backend)

        await hooks._forward_trace_to_backend(session.session_id)

        assert [len(payload["spans"]) for payload in posted_payloads] == expected_chunk_sizes
        assert all(payload["_dd.stage"] == "raw" for payload in posted_payloads)
        assert all(payload["event_type"] == "span" for payload in posted_payloads)
        forwarded_spans = [span for payload in posted_payloads for span in payload["spans"]]
        assert [span["span_id"] for span in forwarded_spans] == [str(index) for index in range(span_count)]
        assert all("lapdog_forwarded:true" in span["tags"] for span in forwarded_spans)
        assert all("lapdog_forwarded:true" not in span["tags"] for span in hooks._assembled_spans)
        if span_count <= 20:
            assert all("(chunk " not in description for description in descriptions)
        else:
            assert all(
                f"chunk {index + 1}/{len(expected_chunk_sizes)}" in description
                for index, description in enumerate(descriptions)
            )


async def test_session_tags_apply_to_existing_and_future_spans(agent):
    session_id = "sess-custom-tags"
    session_token = "launch-token"
    custom_tags = {
        "dd_auto_experiment_id": "c0817213-61d4-43d6-8261-050d7560011a",
        "iteration": "2",
    }

    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "lapdog_session_token": session_token,
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "tag this session",
        },
    )

    response = await agent.post(
        "/claude/hooks/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"tags": custom_tags},
    )
    assert response.status == 200, await response.text()

    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-after-tags",
            "tool_input": {"command": "pwd"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-after-tags",
            "tool_response": "/tmp",
        },
    )

    response = await agent.get("/claude/hooks/spans")
    spans = [span for span in (await response.json())["spans"] if span.get("session_id") == session_id]
    assert len(spans) >= 2
    for span in spans:
        assert "dd_auto_experiment_id:c0817213-61d4-43d6-8261-050d7560011a" in span["tags"]
        assert "iteration:2" in span["tags"]


async def test_session_tags_queue_until_hook_registers_launch_token(agent):
    session_id = "sess-queued-tags"
    session_token = "queued-launch-token"
    response = await agent.post(
        "/claude/hooks/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"tags": {"iteration": "2"}},
    )
    assert response.status == 200
    assert (await response.json())["session_ids"] == []

    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "lapdog_session_token": session_token,
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "use queued tags",
        },
    )

    response = await agent.get("/claude/hooks/spans")
    spans = [span for span in (await response.json())["spans"] if span.get("session_id") == session_id]
    assert spans
    assert all("iteration:2" in span["tags"] for span in spans)

    second_session_id = "sess-after-queued-tags"
    await _post_hook(
        agent,
        {
            "session_id": second_session_id,
            "hook_event_name": "SessionStart",
            "lapdog_session_token": session_token,
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": second_session_id,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "do not reuse consumed queued tags",
        },
    )
    response = await agent.get("/claude/hooks/spans")
    second_session_spans = [
        span for span in (await response.json())["spans"] if span.get("session_id") == second_session_id
    ]
    assert second_session_spans
    assert all("iteration:2" not in span["tags"] for span in second_session_spans)

    response = await agent.get("/claude/hooks/raw")
    raw_events = (await response.json())["events"]
    assert all("lapdog_session_token" not in event for event in raw_events)


async def test_session_tags_reject_ambiguous_launch_token(agent):
    session_token = "shared-launch-token"
    session_ids = ["shared-session-a", "shared-session-b"]
    for session_id in session_ids:
        await _post_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "SessionStart",
                "lapdog_session_token": session_token,
            },
        )
        await _post_hook(
            agent,
            {
                "session_id": session_id,
                "hook_event_name": "UserPromptSubmit",
                "prompt": session_id,
            },
        )

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"tags": {"iteration": "2"}},
    )
    assert response.status == 409
    assert (await response.json())["session_ids"] == session_ids

    response = await agent.get("/claude/hooks/spans")
    spans = [span for span in (await response.json())["spans"] if span.get("session_id") in session_ids]
    assert spans
    assert all("iteration:2" not in span["tags"] for span in spans)


async def test_session_tags_reject_session_registered_to_another_launch_token(agent):
    session_id = "session-owned-by-another-token"
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "lapdog_session_token": "owner-token",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "keep this session isolated",
        },
    )

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": "unrelated-token"},
        json={
            "session_id": session_id,
            "tags": {"iteration": "2"},
        },
    )
    assert response.status == 409

    response = await agent.get("/claude/hooks/spans")
    spans = [span for span in (await response.json())["spans"] if span.get("session_id") == session_id]
    assert spans
    assert all("iteration:2" not in span["tags"] for span in spans)


async def test_session_tags_reject_reserved_identity_keys(agent):
    session_id = "session-reserved-tags"
    session_token = "reserved-tags-token"
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "lapdog_session_token": session_token,
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "preserve identity tags",
        },
    )

    response = await agent.post(
        "/lapdog/session/tags",
        headers={"X-Lapdog-Session-Token": session_token},
        json={"tags": {"service": "wrong-service", "session_id": "wrong-session"}},
    )
    assert response.status == 400
    assert "reserved tag keys" in (await response.json())["error"]

    response = await agent.get("/claude/hooks/spans")
    spans = [span for span in (await response.json())["spans"] if span.get("session_id") == session_id]
    assert spans
    assert all("service:wrong-service" not in span["tags"] for span in spans)
    assert all("session_id:wrong-session" not in span["tags"] for span in spans)


async def test_session_tags_require_launch_token(agent):
    response = await agent.post(
        "/claude/hooks/session/tags",
        json={"tags": {"iteration": "2"}},
    )
    assert response.status == 404


async def test_hook_session_creates_agent_span(agent):
    session_id = "sess-agent-span"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    body = await resp.json()
    spans = body["spans"]

    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1

    root = root_spans[0]
    assert root["name"] == "claude-code-request"
    assert root["meta"]["span"]["kind"] == "agent"
    assert root["duration"] >= 0
    assert root["trace_id"]

    # Verify span appears in LLMObs query API
    resp = await agent.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"limit": 100, "search": {"query": ""}}},
    )
    assert resp.status == 200
    data = await resp.json()
    events = data["result"]["events"]
    trace_ids = {e["event"]["trace_id"] for e in events}
    assert root["trace_id"] in trace_ids


async def test_backfill_session_is_idempotent_for_same_session(agent):
    payload = {
        "session_id": "sess-backfill-once",
        "cwd": "/p",
        "entries": [
            {
                "type": "user",
                "timestamp": "2026-05-11T12:00:00.000Z",
                "message": {"role": "user", "content": "do thing"},
            },
            {
                "type": "assistant",
                "timestamp": "2026-05-11T12:00:01.000Z",
                "message": {
                    "role": "assistant",
                    "model": "claude-opus-4-7",
                    "content": [{"type": "text", "text": "ok"}],
                },
            },
        ],
    }

    first = await agent.post(
        "/claude/hooks/backfill_session",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
    )
    assert first.status == 200
    first_body = await first.json()
    assert first_body["status"] == "ok"
    assert first_body["spans_created"] == 3

    second = await agent.post(
        "/claude/hooks/backfill_session",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
    )
    assert second.status == 200
    second_body = await second.json()
    assert second_body["status"] == "skipped"
    assert second_body["reason"] == "already_backfilled"

    resp = await agent.get("/claude/hooks/spans")
    spans = (await resp.json())["spans"]
    assert len([s for s in spans if s.get("session_id") == "sess-backfill-once"]) == 3


async def test_hook_tool_use_creates_tool_span(agent):
    session_id = "sess-tool-span"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "ls"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-1",
            "tool_response": "file1.txt\nfile2.txt",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    assert len(tool_spans) == 1

    tool = tool_spans[0]
    assert tool["name"] == "Bash - ls"
    assert tool["duration"] >= 0
    assert "ls" in tool["meta"]["input"]["value"]
    assert "file1.txt" in tool["meta"]["output"]["value"]

    # Root agent span output comes from transcript (no transcript in tests, so empty)
    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1

    # Non-instrumented sessions (default) don't produce step spans — the tool
    # parents directly to the root agent.
    step_spans = [s for s in spans if s["meta"]["span"]["kind"] == "step"]
    assert step_spans == []
    assert tool["parent_id"] == root_spans[0]["span_id"]


async def test_claude_project_metadata_from_hook_cwd(agent, tmp_path, monkeypatch):
    from ddapm_test_agent.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/DataDog/claude-project.git"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    session_id = "sess-project-metadata"
    common = {"session_id": session_id, "cwd": str(tmp_path)}

    await _post_hook(agent, {**common, "hook_event_name": "SessionStart"})
    await _post_hook(agent, {**common, "hook_event_name": "UserPromptSubmit", "prompt": "list files"})
    await _post_hook(
        agent,
        {
            **common,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-project-1",
            "tool_input": {"command": "ls"},
        },
    )
    await _post_hook(
        agent,
        {
            **common,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-project-1",
            "tool_response": "README.md",
        },
    )
    await _post_hook(agent, {**common, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = [s for s in (await resp.json())["spans"] if s.get("session_id") == session_id]
    root = next(s for s in spans if s["parent_id"] == "undefined")
    tool = next(s for s in spans if s["meta"]["span"]["kind"] == "tool")

    for span in (root, tool):
        assert "project_name:claude-project" in span["tags"]
        assert "git.repository_url:github.com/DataDog/claude-project" in span["tags"]
        assert not any("commit" in tag for tag in span["tags"])
    assert root["meta"]["metadata"]["project_name"] == "claude-project"
    assert root["meta"]["metadata"]["git_repository_url"] == "github.com/DataDog/claude-project"


async def test_claude_spans_tagged_with_git_commit_sha(agent, tmp_path, monkeypatch):
    """Spans carry git.commit.sha for the same repo as the git.repository_url tag."""
    from ddapm_test_agent.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()

    def _git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True)

    _git("init")
    _git("config", "user.email", "qa@local")
    _git("config", "user.name", "QA")
    _git("remote", "add", "origin", "https://github.com/DataDog/claude-project.git")
    (tmp_path / "README.md").write_text("# repo\n")
    _git("add", "-A")
    _git("commit", "-m", "initial commit")
    sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=tmp_path, check=True, capture_output=True, text=True
    ).stdout.strip()

    session_id = "sess-commit-sha"
    common = {"session_id": session_id, "cwd": str(tmp_path)}

    await _post_hook(agent, {**common, "hook_event_name": "SessionStart"})
    await _post_hook(agent, {**common, "hook_event_name": "UserPromptSubmit", "prompt": "list files"})
    await _post_hook(
        agent,
        {
            **common,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-commit-1",
            "tool_input": {"command": "ls"},
        },
    )
    await _post_hook(
        agent,
        {
            **common,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-commit-1",
            "tool_response": "README.md",
        },
    )
    await _post_hook(agent, {**common, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = [s for s in (await resp.json())["spans"] if s.get("session_id") == session_id]
    root = next(s for s in spans if s["parent_id"] == "undefined")
    tool = next(s for s in spans if s["meta"]["span"]["kind"] == "tool")

    for span in (root, tool):
        assert f"git.commit.sha:{sha}" in span["tags"]
        assert "git.repository_url:github.com/DataDog/claude-project" in span["tags"]


async def test_claude_project_metadata_updates_when_cwd_changes(agent, tmp_path, monkeypatch):
    """A hook posted with a new cwd mid-session should re-resolve project metadata."""
    from ddapm_test_agent.coding_agent_metadata import _local_git_metadata

    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()

    repo_a = tmp_path / "repo-a"
    repo_b = tmp_path / "repo-b"
    repo_a.mkdir()
    repo_b.mkdir()
    for repo, remote in (
        (repo_a, "https://github.com/DataDog/repo-a.git"),
        (repo_b, "https://github.com/DataDog/repo-b.git"),
    ):
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", remote], cwd=repo, check=True, capture_output=True)

    session_id = "sess-cwd-change"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart", "cwd": str(repo_a)})
    await _post_hook(
        agent,
        {"session_id": session_id, "hook_event_name": "UserPromptSubmit", "cwd": str(repo_a), "prompt": "first"},
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop", "cwd": str(repo_a)})
    # Second turn — cwd switches to a different repo.
    await _post_hook(
        agent,
        {"session_id": session_id, "hook_event_name": "UserPromptSubmit", "cwd": str(repo_b), "prompt": "second"},
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop", "cwd": str(repo_b)})

    resp = await agent.get("/claude/hooks/spans")
    assert resp.status == 200
    spans = [s for s in (await resp.json())["spans"] if s.get("session_id") == session_id]
    roots = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(roots) == 2
    roots.sort(key=lambda s: s["start_ns"])
    assert "project_name:repo-a" in roots[0]["tags"]
    assert "git.repository_url:github.com/DataDog/repo-a" in roots[0]["tags"]
    assert "project_name:repo-b" in roots[1]["tags"]
    assert "git.repository_url:github.com/DataDog/repo-b" in roots[1]["tags"]


async def test_hook_subagent_creates_nested_agent(agent):
    session_id = "sess-subagent"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})

    # Start a subagent
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SubagentStart",
            "agent_type": "explore-agent",
        },
    )

    # Tool use inside subagent
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-sub-1",
            "tool_input": {"file_path": "/foo/bar.py"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-sub-1",
            "tool_response": "contents",
        },
    )

    # Stop subagent
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SubagentStop"})

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    # Should have: tool (Read), agent (explore-agent), root agent
    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    agent_spans = [s for s in spans if s["meta"]["span"]["kind"] == "agent"]

    assert len(tool_spans) == 1
    assert len(agent_spans) == 2  # subagent + root

    tool = tool_spans[0]
    subagent = [s for s in agent_spans if s["name"] == "explore-agent"][0]
    root = [s for s in agent_spans if s["parent_id"] == "undefined"][0]

    # Tool's parent should be the subagent, not the root
    assert tool["parent_id"] == subagent["span_id"]
    # Subagent's parent should be the root
    assert subagent["parent_id"] == root["span_id"]


async def test_hook_trace_endpoint(agent):
    session_id = "sess-trace-ep"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-t-1",
            "tool_input": {},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-t-1",
            "tool_response": "match",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    # Get sessions to find the trace_id
    resp = await agent.get("/claude/hooks/sessions")
    body = await resp.json()
    session_info = [s for s in body["sessions"] if s["session_id"] == session_id][0]
    trace_id = session_info["trace_id"]

    # Query the trace endpoint
    resp = await agent.get(f"/api/ui/llm-obs/v1/trace/{trace_id}")
    assert resp.status == 200
    data = await resp.json()

    assert "data" in data
    attrs = data["data"]["attributes"]
    assert attrs["root_id"] is not None
    assert len(attrs["spans"]) >= 2  # root + tool


async def test_hook_user_prompt_annotates_session(agent):
    session_id = "sess-prompt"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "user_prompt": "Fix the bug in auth.py",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    root_spans = [s for s in spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1

    root = root_spans[0]
    assert "Fix the bug in auth.py" in root["meta"]["input"]["value"]


async def test_hook_agent_manifest(agent):
    session_id = "sess-manifest"

    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SessionStart",
            "model": "claude-sonnet-4-5-20250929",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-m-1",
            "tool_input": {"command": "echo hi"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-m-1",
            "tool_response": "hi",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-m-2",
            "tool_input": {"file_path": "/tmp/x"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-m-2",
            "tool_response": "contents",
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    root = [s for s in spans if s["parent_id"] == "undefined"][0]
    manifest = root["meta"]["metadata"]["_dd"]["agent_manifest"]

    assert manifest["name"] == "claude-code"
    assert manifest["model"] == "claude-sonnet-4-5-20250929"
    assert manifest["model_provider"] == "anthropic"

    tool_names = [t["name"] for t in manifest["tools"]]
    assert "Bash" in tool_names
    assert "Read" in tool_names

    assert root["meta"]["model_name"] == "claude-sonnet-4-5-20250929"
    assert root["meta"]["model_provider"] == "anthropic"


async def test_hook_console_output_on_agent_span(agent):
    session_id = "sess-console"

    # Create a fake transcript with a previous turn and a current turn
    transcript = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    try:
        # Previous turn (should NOT appear in output)
        transcript.write(
            json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": "hello"}]}}) + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [{"type": "text", "text": "Hi there! How can I help?"}],
                    },
                }
            )
            + "\n"
        )
        # Tool result (type=user but NOT a prompt — should not reset the boundary)
        transcript.write(
            json.dumps(
                {
                    "type": "user",
                    "message": {
                        "content": [{"type": "tool_result", "tool_use_id": "x", "content": "ok"}],
                    },
                }
            )
            + "\n"
        )
        # Current turn — last user prompt
        transcript.write(
            json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": "fix the bug"}]}}) + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "Let me read that file for you."},
                            {"type": "tool_use", "name": "Read", "input": {}},
                        ],
                    },
                }
            )
            + "\n"
        )
        transcript.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [{"type": "text", "text": "Done! The bug is fixed."}],
                    },
                }
            )
            + "\n"
        )
        transcript.flush()
        transcript_path = transcript.name
        transcript.close()

        await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
        await _post_hook(
            agent, {"session_id": session_id, "hook_event_name": "Stop", "transcript_path": transcript_path}
        )

        resp = await agent.get("/claude/hooks/spans")
        body = await resp.json()
        spans = body["spans"]

        root = [s for s in spans if s["parent_id"] == "undefined" and s["trace_id"]][0]
        output = root["meta"]["output"]["value"]

        # Only output after the last prompt should appear
        assert "Let me read that file for you." in output
        assert "Done! The bug is fixed." in output
        # Previous turn's output should NOT appear
        assert "Hi there! How can I help?" not in output
    finally:
        os.unlink(transcript_path)


async def test_hook_tool_use_failure_creates_error_span(agent):
    session_id = "sess-tool-fail"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-fail-1",
            "tool_input": {"command": "rm -rf /nonexistent"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_use_id": "tool-fail-1",
            "error": "Command exited with non-zero status code 1",
            "is_interrupt": False,
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    assert len(tool_spans) == 1

    tool = tool_spans[0]
    assert tool["status"] == "error"
    assert tool["meta"]["error"]["message"] == "Command exited with non-zero status code 1"
    assert "rm -rf /nonexistent" in tool["meta"]["input"]["value"]
    assert "non-zero status" in tool["meta"]["output"]["value"]
    assert tool["duration"] >= 0


async def test_hook_tool_use_failure_interrupt(agent):
    session_id = "sess-tool-interrupt"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_use_id": "tool-int-1",
            "tool_input": {"command": "sleep 100"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_use_id": "tool-int-1",
            "error": "User interrupted",
            "is_interrupt": True,
        },
    )
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    tool_spans = [s for s in spans if s["meta"]["span"]["kind"] == "tool"]
    assert len(tool_spans) == 1

    tool = tool_spans[0]
    assert tool["status"] == "error"
    assert tool["meta"]["error"]["type"] == "interrupt"


async def test_hook_sessions_endpoint(agent):
    session_id = "sess-list-test"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})

    resp = await agent.get("/claude/hooks/sessions")
    assert resp.status == 200
    body = await resp.json()
    session_ids = [s["session_id"] for s in body["sessions"]]
    assert session_id in session_ids


async def test_concurrent_subagents_parent_correctly(agent):
    """Two Task tools spawn sibling subagents — both should be parented to root, not each other."""
    session_id = "sess-concurrent"

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SessionStart"})
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "UserPromptSubmit",
            "user_prompt": "Run two tasks concurrently",
        },
    )

    # Two PreToolUse(Task) fire before any SubagentStart — simulates concurrent dispatch
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_use_id": "task-A",
            "tool_input": {"description": "search code", "prompt": "Search the codebase for foo"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_use_id": "task-B",
            "tool_input": {"description": "read docs", "prompt": "Read the documentation for bar"},
        },
    )

    # SubagentStart for first agent (claims task-A)
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SubagentStart",
            "agent_type": "explore-agent",
        },
    )

    # SubagentStart for second agent (claims task-B)
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "SubagentStart",
            "agent_type": "explore-agent",
        },
    )

    # Tool inside agent1
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-in-A",
            "tool_input": {"pattern": "foo"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Grep",
            "tool_use_id": "tool-in-A",
            "tool_response": "found foo",
        },
    )

    # Tool inside agent2
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-in-B",
            "tool_input": {"file_path": "/docs/bar.md"},
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tool-in-B",
            "tool_response": "bar docs",
        },
    )

    # SubagentStop for agent2 (top of stack)
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SubagentStop"})
    # SubagentStop for agent1
    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "SubagentStop"})

    # PostToolUse for both Task tools
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Task",
            "tool_use_id": "task-A",
            "tool_response": "search results",
        },
    )
    await _post_hook(
        agent,
        {
            "session_id": session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "Task",
            "tool_use_id": "task-B",
            "tool_response": "docs content",
        },
    )

    await _post_hook(agent, {"session_id": session_id, "hook_event_name": "Stop"})

    resp = await agent.get("/claude/hooks/spans")
    body = await resp.json()
    spans = body["spans"]

    # Filter to just this session's spans
    session_spans = [s for s in spans if s.get("session_id") == session_id]

    root_spans = [s for s in session_spans if s["parent_id"] == "undefined"]
    assert len(root_spans) == 1
    root = root_spans[0]

    agent_spans = [s for s in session_spans if s["meta"]["span"]["kind"] == "agent" and s["parent_id"] != "undefined"]
    assert len(agent_spans) == 2, f"Expected 2 subagent spans, got {len(agent_spans)}"

    # Both subagents should be parented to root — not to each other
    for agent_span in agent_spans:
        assert agent_span["parent_id"] == root["span_id"], (
            f"Subagent {agent_span['name']} has parent_id={agent_span['parent_id']} "
            f"but expected root span_id={root['span_id']}"
        )


def test_instrumented_live_task_subagent_parents_to_spawning_step():
    link_tracker = ClaudeLinkTracker()
    hooks = ClaudeHooksAPI(link_tracker=link_tracker)
    proxy = ClaudeProxyAPI(hooks_api=hooks, link_tracker=link_tracker)
    session_id = "sess-live-step-subagent"

    hooks._dispatch_hook({"session_id": session_id, "hook_event_name": "SessionStart", "lapdog_instrumented": True})
    hooks._dispatch_hook({"session_id": session_id, "hook_event_name": "UserPromptSubmit", "user_prompt": "Run a task"})
    session = hooks._sessions[session_id]
    llm_span = proxy._create_llm_span(
        session,
        {"model": "claude-opus-4-7", "messages": [{"role": "user", "content": "Run a task"}]},
        {
            "model": "claude-opus-4-7",
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "content": [
                {"type": "text", "text": "Launching an Explore subagent."},
                {
                    "type": "tool_use",
                    "id": "task-1",
                    "name": "Task",
                    "input": {"description": "Explore", "prompt": "go look"},
                },
            ],
        },
        start_ns=1_000,
        duration_ns=500,
    )
    hooks._assembled_spans.append(llm_span)

    hooks._dispatch_hook(
        {
            "session_id": session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": "Task",
            "tool_use_id": "task-1",
            "tool_input": {"description": "Explore", "prompt": "go look"},
        }
    )
    hooks._dispatch_hook({"session_id": session_id, "hook_event_name": "SubagentStart", "agent_type": "Task"})

    spans = [s for s in hooks._assembled_spans if s.get("session_id") == session_id]
    by_id = {s["span_id"]: s for s in spans}
    step = next(s for s in spans if s["meta"]["span"]["kind"] == "step")
    subagent = next(s for s in spans if s["meta"]["span"]["kind"] == "agent" and s["parent_id"] != "undefined")

    assert llm_span["parent_id"] == step["span_id"]
    assert subagent["name"] == "Task - Explore"
    assert subagent["parent_id"] == step["span_id"]
    assert by_id[subagent["parent_id"]]["meta"]["span"]["kind"] == "step"


class _HookRequest:
    def __init__(self, body: Dict[str, Any]) -> None:
        self._body = body

    async def json(self) -> Dict[str, Any]:
        return dict(self._body)


async def test_post_tool_use_incrementally_forwards_completed_tool_before_stop(monkeypatch):
    hooks = ClaudeHooksAPI()
    hooks._link_tracker = ClaudeLinkTracker()
    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": False,
            "dd_site": "datadoghq.com",
            "dd_api_key": "test-key",
            "agent_url": "",
        }
    )
    calls = []
    backend = {}

    async def fake_post_spans(url: str, headers: Dict[str, str], spans: List[Dict[str, Any]], description: str) -> None:
        calls.append((description, spans))
        for span in spans:
            backend[(span["trace_id"], span["span_id"])] = span

    monkeypatch.setattr(hooks, "_post_spans_to_backend", fake_post_spans)
    session_id = "incremental-session"
    await hooks.handle_hook(
        _HookRequest(
            {"session_id": session_id, "hook_event_name": "SessionStart", "lapdog_instrumented": True}
        )
    )
    await hooks.handle_hook(
        _HookRequest(
            {
                "session_id": session_id,
                "hook_event_name": "UserPromptSubmit",
                "prompt": "run a tool",
            }
        )
    )
    session = hooks._sessions[session_id]
    hooks._start_step_for_llm(
        session=session,
        llm_span_id="llm-1",
        agent_parent_id=session.root_span_id,
        llm_start_ns=1,
        tool_use_ids=["tool-1"],
    )
    hooks._link_tracker.on_llm_tool_choice("tool-1", "Bash", "{}", "llm-1", session.trace_id)
    await hooks.handle_hook(
        _HookRequest(
            {
                "session_id": session_id,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "tool-1",
                "tool_input": {"command": "true"},
            }
        )
    )
    await hooks.handle_hook(
        _HookRequest(
            {
                "session_id": session_id,
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_use_id": "tool-1",
                "tool_response": "ok",
            }
        )
    )

    assert len(calls) == 1
    description, tool_spans = calls[0]
    assert description == "forward 1 span updates"
    assert any(span["span_id"] == tool_spans[0]["span_id"] for span in hooks._assembled_spans)
    assert tool_spans[0]["meta"]["span"]["kind"] == "tool"
    assert tool_spans[0]["meta"]["metadata"]["tool_id"] == "tool-1"

    await hooks.handle_hook(_HookRequest({"session_id": session_id, "hook_event_name": "Stop"}))
    assert len(calls) == 2
    assert len(backend) == len({(span["trace_id"], span["span_id"]) for span in hooks._assembled_spans})

    hooks._set_session_tags(hooks._sessions[session_id], {"post_close": "yes"})
    assert all("post_close:yes" in span["tags"] for span in hooks._assembled_spans)
    assert all("post_close:yes" not in span["tags"] for _, spans in calls for span in spans)


async def test_turn_root_parent_is_deferred_to_single_final_flush(monkeypatch):
    hooks = ClaudeHooksAPI()
    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": False,
            "dd_site": "datadoghq.com",
            "dd_api_key": "test-key",
            "agent_url": "",
        }
    )
    rows = []

    async def fake_post_spans(url: str, headers: Dict[str, str], spans: List[Dict[str, Any]], description: str) -> None:
        rows.extend(spans)

    monkeypatch.setattr(hooks, "_post_spans_to_backend", fake_post_spans)
    session_id = "turn-root-parent-session"
    await hooks.handle_hook(_HookRequest({"session_id": session_id, "hook_event_name": "SessionStart"}))
    await hooks.handle_hook(
        _HookRequest({"session_id": session_id, "hook_event_name": "UserPromptSubmit", "prompt": "run a tool"})
    )
    await hooks.handle_hook(
        _HookRequest(
            {"session_id": session_id, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "root-tool", "tool_input": {"command": "true"}}
        )
    )
    await hooks.handle_hook(
        _HookRequest(
            {"session_id": session_id, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "root-tool", "tool_response": "ok"}
        )
    )

    assert not [row for row in rows if row.get("meta", {}).get("metadata", {}).get("tool_id") == "root-tool"]
    await hooks.handle_hook(_HookRequest({"session_id": session_id, "hook_event_name": "Stop"}))

    tool_rows = [row for row in rows if row.get("meta", {}).get("metadata", {}).get("tool_id") == "root-tool"]
    assert len(tool_rows) == 1
    assert tool_rows[0]["parent_id"] == hooks._sessions[session_id].root_span_id


async def test_late_reparent_still_produces_one_final_row_under_step(monkeypatch):
    hooks = ClaudeHooksAPI()
    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": False,
            "dd_site": "datadoghq.com",
            "dd_api_key": "test-key",
            "agent_url": "",
        }
    )
    rows = []

    async def fake_post_spans(url: str, headers: Dict[str, str], spans: List[Dict[str, Any]], description: str) -> None:
        rows.extend(spans)

    monkeypatch.setattr(hooks, "_post_spans_to_backend", fake_post_spans)
    session_id = "late-reparent-session"
    await hooks.handle_hook(
        _HookRequest({"session_id": session_id, "hook_event_name": "SessionStart", "lapdog_instrumented": True})
    )
    await hooks.handle_hook(
        _HookRequest({"session_id": session_id, "hook_event_name": "UserPromptSubmit", "prompt": "run a tool"})
    )
    await hooks.handle_hook(
        _HookRequest({"session_id": session_id, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "late-tool", "tool_input": {"command": "true"}})
    )
    await hooks.handle_hook(
        _HookRequest({"session_id": session_id, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": "late-tool", "tool_response": "ok"})
    )
    assert rows == []

    session = hooks._sessions[session_id]
    active_step = hooks._start_step_for_llm(
        session=session,
        llm_span_id="late-llm",
        agent_parent_id=session.root_span_id,
        llm_start_ns=1,
        tool_use_ids=["late-tool"],
    )
    tool = next(span for span in hooks._assembled_spans if span.get("meta", {}).get("metadata", {}).get("tool_id") == "late-tool")
    assert tool["parent_id"] == active_step.span_id

    await hooks.handle_hook(_HookRequest({"session_id": session_id, "hook_event_name": "Stop"}))
    tool_rows = [row for row in rows if row.get("meta", {}).get("metadata", {}).get("tool_id") == "late-tool"]
    assert len(tool_rows) == 1
    assert tool_rows[0]["parent_id"] == active_step.span_id


async def test_forwarders_share_non_mutating_normalization(monkeypatch):
    hooks = ClaudeHooksAPI()
    session = hooks._get_or_create_session("normalization-session")
    source = {
        "span_id": "span-1",
        "trace_id": session.trace_id,
        "tags": ["session_id:normalization-session"],
        "metrics": {"input_tokens": 10, "estimated_total_cost": 3.5, "custom": 20},
    }
    hooks._assembled_spans = [source]
    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": False,
            "dd_site": "datadoghq.com",
            "dd_api_key": "test-key",
            "agent_url": "",
        }
    )
    sent = []

    async def fake_post_spans(url: str, headers: Dict[str, str], spans: List[Dict[str, Any]], description: str) -> None:
        sent.append(spans)

    monkeypatch.setattr(hooks, "_post_spans_to_backend", fake_post_spans)
    await hooks._forward_span_update([source])
    await hooks._forward_trace_to_backend(session.session_id)

    assert sent[0] == sent[1]
    assert sent[0][0]["metrics"] == {"input_tokens": 10, "custom": 20}
    assert sent[0][0]["tags"] == ["session_id:normalization-session", "lapdog_forwarded:true"]
    assert source == {
        "span_id": "span-1",
        "trace_id": session.trace_id,
        "tags": ["session_id:normalization-session"],
        "metrics": {"input_tokens": 10, "estimated_total_cost": 3.5, "custom": 20},
    }


async def test_incremental_forwarding_guards_and_failure_isolation(monkeypatch):
    hooks = ClaudeHooksAPI()
    span = {"span_id": "span-1", "trace_id": "trace-1", "metrics": {}, "tags": []}
    calls = []

    async def fake_post_spans(*args: Any) -> None:
        calls.append(args)

    monkeypatch.setattr(hooks, "_post_spans_to_backend", fake_post_spans)
    await hooks._forward_span_update([span])
    assert calls == []

    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": True,
            "dd_site": "datadoghq.com",
            "dd_api_key": "test-key",
            "agent_url": "",
        }
    )
    await hooks._forward_span_update([span])
    assert calls == []

    hooks._app["disable_llmobs_data_forwarding"] = False
    hooks._app["dd_api_key"] = None
    await hooks._forward_span_update([span])
    assert calls == []


async def test_incremental_timeout_cancels_held_open_sender_and_preserves_hook_result(monkeypatch, caplog):
    hooks = ClaudeHooksAPI()
    hooks._link_tracker = ClaudeLinkTracker()
    hooks.set_app(
        {
            "disable_llmobs_data_forwarding": False,
            "dd_site": "",
            "dd_api_key": None,
            "agent_url": "http://127.0.0.1:1",
        }
    )
    assert claude_hooks_module._INCREMENTAL_FORWARD_TIMEOUT_SECONDS == 1.0
    production_timeout = 0.05
    monkeypatch.setattr(claude_hooks_module, "_INCREMENTAL_FORWARD_TIMEOUT_SECONDS", production_timeout)
    sender_started = asyncio.Event()
    sender_cancelled = asyncio.Event()

    async def held_open_post(*args: Any) -> None:
        sender_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            sender_cancelled.set()
            raise

    monkeypatch.setattr(hooks, "_post_to_backend", held_open_post)
    session_id = "timeout-session"
    await hooks.handle_hook(
        _HookRequest(
            {"session_id": session_id, "hook_event_name": "SessionStart", "lapdog_instrumented": True}
        )
    )
    session = hooks._sessions[session_id]
    hooks._start_step_for_llm(
        session=session, llm_span_id="timeout-llm", agent_parent_id=session.root_span_id, llm_start_ns=1, tool_use_ids=["timeout-tool"]
    )
    hooks._link_tracker.on_llm_tool_choice("timeout-tool", "Bash", "{}", "timeout-llm", session.trace_id)
    await hooks.handle_hook(
        _HookRequest(
            {
                "session_id": session_id,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_use_id": "timeout-tool",
                "tool_input": {"command": "true"},
            }
        )
    )
    with caplog.at_level("WARNING", logger=claude_hooks_module.__name__):
        response = await asyncio.wait_for(
            hooks.handle_hook(
                _HookRequest(
                    {
                        "session_id": session_id,
                        "hook_event_name": "PostToolUse",
                        "tool_name": "Bash",
                        "tool_use_id": "timeout-tool",
                        "tool_response": "ok",
                    }
                )
            ),
            timeout=production_timeout * 10,
        )

    assert sender_started.is_set()
    assert any(
        record.getMessage() == "Error trying to forward completed tool span: TimeoutError()"
        for record in caplog.records
    )
    assert sender_cancelled.is_set()
    assert response.status == 200
    assert json.loads(response.body) == {"status": "ok"}
