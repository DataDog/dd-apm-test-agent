"""Claude Code Hooks → LLM Observability Spans.

Receives Claude Code lifecycle hook events via HTTP and assembles them
into LLMObs-format spans that can be queried through the Event Platform APIs.
"""

import gzip
import json
import logging
import os
import random
import socket
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from aiohttp import ClientSession
from aiohttp import web
from aiohttp.web import Request
import msgpack

from .claude_link_tracker import ClaudeLinkTracker
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)

_HOSTNAME = socket.gethostname()


class PendingToolSpan:
    """Tracks a tool invocation between PreToolUse and PostToolUse."""

    def __init__(self, span_id: str, tool_name: str, tool_input: Any, parent_id: str, start_ns: int) -> None:
        self.span_id = span_id
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.parent_id = parent_id
        self.start_ns = start_ns


class SessionState:
    """Tracks the state of a single Claude Code session."""

    def __init__(self, session_id: str, trace_id: str, root_span_id: str, start_ns: int) -> None:
        self.session_id = session_id
        self.trace_id = trace_id
        self.root_span_id = root_span_id
        self.start_ns = start_ns
        self.agent_span_stack: List[Dict[str, Any]] = []
        self.pending_tools: Dict[str, PendingToolSpan] = {}
        self.user_prompts: List[str] = []
        self.model: str = ""
        self.tools_used: Set[str] = set()
        self.root_span_emitted: bool = False
        # Deferred agent spans waiting for PostToolUse(Task) to provide their output.
        # Keyed by tool_use_id of the Task tool that spawned the subagent.
        self.deferred_agent_spans: Dict[str, Dict[str, Any]] = {}
        # Task tool_use_ids that have already been claimed by a SubagentStart,
        # so they are not matched again when a second SubagentStart fires.
        self.claimed_task_tools: Set[str] = set()


_MAX_UINT_64 = (1 << 64) - 1


def _rand64bits() -> int:
    """Generate a random 64-bit unsigned integer."""
    return random.getrandbits(64)


def _rand128bits() -> int:
    """Generate a 128-bit trace ID matching Datadog's format: <32-bit unix seconds><32 zero bits><64 random bits>."""
    return int(time.time()) << 96 | _rand64bits()


def _format_span_id() -> str:
    """Generate a span ID as a decimal string of a random 64-bit unsigned int."""
    return str(_rand64bits())


def _format_trace_id() -> str:
    """Generate a trace ID matching Datadog's format_trace_id: 32-char hex for 128-bit IDs."""
    trace_id = _rand128bits()
    if trace_id > _MAX_UINT_64:
        return "{:032x}".format(trace_id)
    return str(trace_id)


def _is_user_prompt_entry(entry: Dict[str, Any]) -> bool:
    """Check if a transcript entry is an actual user prompt (not a tool_result)."""
    if entry.get("type") != "user":
        return False
    content = entry.get("message", {}).get("content", [])
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "text" for b in content)
    return False


def _read_console_output(transcript_path: str) -> str:
    """Read assistant text responses after the last user prompt from a Claude Code transcript JSONL file."""
    if not transcript_path or not os.path.isfile(transcript_path):
        return ""
    try:
        entries: List[Dict[str, Any]] = []
        with open(transcript_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # Find the last actual user prompt (not tool_result entries)
        last_prompt_idx = -1
        for i, entry in enumerate(entries):
            if _is_user_prompt_entry(entry):
                last_prompt_idx = i

        # Collect assistant text after the last user prompt
        responses: List[str] = []
        start = last_prompt_idx + 1 if last_prompt_idx >= 0 else 0
        for entry in entries[start:]:
            if entry.get("type") == "assistant":
                for block in entry.get("message", {}).get("content", []):
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block["text"].strip()
                        if text:
                            responses.append(text)
        return "\n\n".join(responses)
    except Exception as e:
        log.debug("Failed to read transcript %s: %s", transcript_path, e)
        return ""


class ClaudeHooksAPI:
    """Handler for Claude Code hook events."""

    def __init__(self, link_tracker: Optional[ClaudeLinkTracker] = None) -> None:
        self._sessions: Dict[str, SessionState] = {}
        self._assembled_spans: List[Dict[str, Any]] = []
        self._raw_events: List[Dict[str, Any]] = []
        self._link_tracker = link_tracker
        self._app: Optional[web.Application] = None

    def set_app(self, app: web.Application) -> None:
        """Set the aiohttp app reference for backend forwarding."""
        self._app = app

    def _get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create a new one."""
        if session_id not in self._sessions:
            trace_id = _format_trace_id()
            root_span_id = _format_span_id()
            now_ns = int(time.time() * 1_000_000_000)
            self._sessions[session_id] = SessionState(
                session_id=session_id,
                trace_id=trace_id,
                root_span_id=root_span_id,
                start_ns=now_ns,
            )
        return self._sessions[session_id]

    def _current_parent_id(self, session: SessionState) -> str:
        """Return the span_id of the current active agent (top of stack), or root."""
        if session.agent_span_stack:
            return str(session.agent_span_stack[-1]["span_id"])
        return session.root_span_id

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SessionStart hook event."""
        session = self._get_or_create_session(session_id)
        model = body.get("model", "")
        if model:
            session.model = model
        log.info("Claude session started: %s (model=%s)", session_id, model)

    def _finalize_interrupted_turn(self, session: SessionState) -> None:
        """Finalize an in-progress turn that was interrupted (e.g. user Ctrl+C).

        Called when a new UserPromptSubmit or SessionEnd arrives but the previous
        turn's Stop hook never fired.  Updates all in-progress spans with their
        current duration so the trace is complete.
        """
        now_ns = int(time.time() * 1_000_000_000)
        duration = now_ns - session.start_ns

        # Finalize any in-progress subagent spans on the stack
        while session.agent_span_stack:
            agent_info = session.agent_span_stack.pop()
            span_ref = agent_info.get("_span_ref")
            if span_ref:
                span_ref["duration"] = now_ns - agent_info["start_ns"]
                span_ref["status"] = "error"
                span_ref["meta"]["error"] = {"message": "interrupted"}

        # Clear pending tools (they'll never get a PostToolUse)
        session.pending_tools.clear()
        session.deferred_agent_spans.clear()
        session.claimed_task_tools.clear()

        # Finalize the root span
        root_span: Optional[Dict[str, Any]] = getattr(session, "_root_span_ref", None)
        if not root_span:
            root_span = next(
                (s for s in self._assembled_spans if s.get("span_id") == session.root_span_id),
                None,
            )

        token_usage = self._compute_token_usage(session.trace_id)
        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""

        if root_span:
            root_span["duration"] = duration
            root_span["status"] = "error"
            root_span["meta"]["input"]["value"] = input_value
            root_span["meta"]["error"] = {"message": "interrupted by user"}
            root_span["meta"]["model_name"] = session.model
            root_span["meta"]["model_provider"] = "anthropic"
            root_span["metrics"] = token_usage

        session.root_span_emitted = True
        log.info("Finalized interrupted turn for session %s (trace %s)", session.session_id, session.trace_id)

    def _handle_user_prompt_submit(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle UserPromptSubmit hook event — starts a new trace for each user turn.

        Emits a preliminary root span eagerly so the execution graph can render
        before Stop fires.  The root span is updated in-place by _handle_stop.
        """
        session = self._get_or_create_session(session_id)

        # If the previous turn was never finalized (Stop never fired, e.g. Ctrl+C),
        # finalize it as interrupted before starting the new turn.
        if not session.root_span_emitted and getattr(session, "_root_span_ref", None) is not None:
            self._finalize_interrupted_turn(session)

        # If the previous turn's root span was emitted, start a fresh trace
        if session.root_span_emitted:
            now_ns = int(time.time() * 1_000_000_000)
            session.trace_id = _format_trace_id()
            session.root_span_id = _format_span_id()
            session.start_ns = now_ns
            session.user_prompts = []
            session.tools_used = set()
            session.agent_span_stack = []
            session.pending_tools = {}
            session.deferred_agent_spans = {}
            session.claimed_task_tools = set()
            session.root_span_emitted = False

        prompt = body.get("user_prompt", body.get("prompt", ""))
        if prompt:
            session.user_prompts.append(prompt)

        # Emit a preliminary root span so the trace has a root node immediately
        root_span: Dict[str, Any] = {
            "span_id": session.root_span_id,
            "trace_id": session.trace_id,
            "parent_id": "undefined",
            "name": "claude-code-request",
            "status": "ok",
            "start_ns": session.start_ns,
            "duration": 0,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                "ml_app:claude-code",
                f"session_id:{session.session_id}",
                "service:claude-code",
                "env:local",
                "source:claude-code-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
            ],
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt},
                "output": {"value": ""},
            },
            "metrics": {},
        }
        self._assembled_spans.append(root_span)
        session._root_span_ref = root_span  # type: ignore[attr-defined]

    def _handle_pre_tool_use(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle PreToolUse hook event — creates a pending tool span."""
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_input = body.get("tool_input", {})
        tool_use_id = body.get("tool_use_id", tool_name)
        session.tools_used.add(tool_name)

        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)

        session.pending_tools[tool_use_id] = PendingToolSpan(
            span_id=span_id,
            tool_name=tool_name,
            tool_input=tool_input,
            parent_id=parent_id,
            start_ns=now_ns,
        )

    def _handle_post_tool_use(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle PostToolUse hook event.

        If this is PostToolUse for a "Task" tool with a deferred agent span,
        emits the agent span (with Task I/O and span links) instead of a tool span.
        Otherwise emits a normal tool span.
        """
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_use_id = body.get("tool_use_id", tool_name)
        tool_output = body.get("tool_response", body.get("tool_output", ""))

        now_ns = int(time.time() * 1_000_000_000)

        pending = session.pending_tools.pop(tool_use_id, None)
        # Clean up claimed_task_tools so the set doesn't grow unbounded
        session.claimed_task_tools.discard(tool_use_id)
        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = self._current_parent_id(session)
            start_ns = now_ns
            input_value = ""
            actual_tool_name = tool_name

        output_str = str(tool_output)[:4096] if tool_output else ""

        # Check if this Task tool has a deferred agent span to update instead
        deferred = session.deferred_agent_spans.pop(tool_use_id, None)
        if deferred:
            # Update the eagerly-emitted AGENT span with the Task tool's I/O and span links.
            agent_span_id = deferred["span_id"]

            span_links = []
            if self._link_tracker:
                links = self._link_tracker.on_tool_call(
                    tool_use_id, agent_span_id, session.trace_id, deferred["parent_id"]
                )
                span_links = [link.to_dict() for link in links]

            span_ref = deferred.get("_span_ref")
            if span_ref:
                # Update the preliminary span in-place
                span_ref["duration"] = deferred["duration"]
                span_ref["meta"]["input"] = {"value": input_value}
                span_ref["meta"]["output"] = {"value": output_str}
                span_ref["span_links"] = span_links
            else:
                # Fallback: no preliminary span — append a new one
                span = {
                    "span_id": agent_span_id,
                    "trace_id": deferred["trace_id"],
                    "parent_id": deferred["parent_id"],
                    "name": deferred["name"],
                    "status": "ok",
                    "start_ns": deferred["start_ns"],
                    "duration": deferred["duration"],
                    "ml_app": "claude-code",
                    "service": "claude-code",
                    "env": "local",
                    "session_id": session.session_id,
                    "tags": [
                        "ml_app:claude-code",
                        f"session_id:{session.session_id}",
                        "service:claude-code",
                        "env:local",
                        "source:claude-code-hooks",
                        "language:python",
                        f"hostname:{_HOSTNAME}",
                    ],
                    "meta": {
                        "span": {"kind": "agent"},
                        "input": {"value": input_value},
                        "output": {"value": output_str},
                    },
                    "metrics": {},
                    "span_links": span_links,
                }
                self._assembled_spans.append(span)
            return

        # Normal tool span
        duration = now_ns - start_ns

        span_links = []
        if self._link_tracker:
            links = self._link_tracker.on_tool_call(tool_use_id, span_id, session.trace_id, parent_id)
            span_links = [link.to_dict() for link in links]

        span = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": actual_tool_name,
            "status": "ok",
            "start_ns": start_ns,
            "duration": duration,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                "ml_app:claude-code",
                f"session_id:{session.session_id}",
                "service:claude-code",
                "env:local",
                "source:claude-code-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
            ],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": input_value},
                "output": {"value": output_str},
            },
            "metrics": {},
            "span_links": span_links,
        }
        self._assembled_spans.append(span)

    def _handle_subagent_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SubagentStart hook event — pushes a new agent onto the stack.

        Emits a preliminary agent span immediately so the UI can show the
        in-progress subagent.  The span is updated in-place by _handle_subagent_stop
        (or _handle_post_tool_use for Task-spawned subagents).

        If a pending "Task" tool exists, captures its tool_use_id and input so the
        agent span can absorb the Task tool's I/O and span links.
        """
        session = self._get_or_create_session(session_id)
        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)

        agent_name = body.get("agent_type", body.get("agent_name", "subagent"))

        # Find the pending "Task" tool that spawned this subagent.
        # Skip Task tools already claimed by a previous SubagentStart so that
        # when multiple Task tools are pending, each subagent gets its own.
        task_tool_use_id = ""
        task_tool_input: Any = None
        for tid, pending in session.pending_tools.items():
            if pending.tool_name == "Task" and tid not in session.claimed_task_tools:
                task_tool_use_id = tid
                task_tool_input = pending.tool_input
                session.claimed_task_tools.add(tid)
                break

        # Emit a preliminary agent span so the trace shows the subagent immediately
        preliminary_span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": agent_name,
            "status": "ok",
            "start_ns": now_ns,
            "duration": 0,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                "ml_app:claude-code",
                f"session_id:{session.session_id}",
                "service:claude-code",
                "env:local",
                "source:claude-code-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
            ],
            "meta": {
                "span": {"kind": "agent"},
                "input": {},
                "output": {},
            },
            "metrics": {},
        }
        self._assembled_spans.append(preliminary_span)

        session.agent_span_stack.append(
            {
                "span_id": span_id,
                "parent_id": parent_id,
                "name": agent_name,
                "start_ns": now_ns,
                "task_tool_use_id": task_tool_use_id,
                "task_tool_input": task_tool_input,
                "_span_ref": preliminary_span,
            }
        )

    def _handle_subagent_stop(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SubagentStop hook event — pops the agent stack.

        Updates the eagerly-emitted agent span in-place with final duration.
        If the agent was spawned by a Task tool, defers the final update until
        PostToolUse(Task) fires so the agent span can include the Task's output.
        """
        session = self._get_or_create_session(session_id)
        now_ns = int(time.time() * 1_000_000_000)

        if not session.agent_span_stack:
            log.warning("SubagentStop with empty agent stack for session %s", session_id)
            return

        agent_info = session.agent_span_stack.pop()
        duration = now_ns - agent_info["start_ns"]

        task_tool_use_id = agent_info.get("task_tool_use_id", "")
        task_tool_input = agent_info.get("task_tool_input")
        span_ref = agent_info.get("_span_ref")

        if task_tool_use_id:
            # Defer final update — PostToolUse(Task) will set I/O and span links.
            # Update duration on the preliminary span so the UI shows progress.
            if span_ref:
                span_ref["duration"] = duration
            session.deferred_agent_spans[task_tool_use_id] = {
                "span_id": agent_info["span_id"],
                "trace_id": session.trace_id,
                "parent_id": agent_info["parent_id"],
                "name": agent_info["name"],
                "start_ns": agent_info["start_ns"],
                "duration": duration,
                "input": str(task_tool_input) if task_tool_input else "",
                "_span_ref": span_ref,
            }
        else:
            # Update the eagerly-emitted span in-place
            if span_ref:
                span_ref["duration"] = duration
            else:
                # Fallback: no preliminary span (shouldn't happen)
                span = {
                    "span_id": agent_info["span_id"],
                    "trace_id": session.trace_id,
                    "parent_id": agent_info["parent_id"],
                    "name": agent_info["name"],
                    "status": "ok",
                    "start_ns": agent_info["start_ns"],
                    "duration": duration,
                    "ml_app": "claude-code",
                    "service": "claude-code",
                    "env": "local",
                    "session_id": session.session_id,
                    "tags": [
                        "ml_app:claude-code",
                        f"session_id:{session.session_id}",
                        "service:claude-code",
                        "env:local",
                        "source:claude-code-hooks",
                        "language:python",
                        f"hostname:{_HOSTNAME}",
                    ],
                    "meta": {
                        "span": {"kind": "agent"},
                        "input": {},
                        "output": {},
                    },
                    "metrics": {},
                }
                self._assembled_spans.append(span)

    def _compute_token_usage(self, trace_id: str) -> Dict[str, int]:
        """Sum token metrics from all LLM spans in the given trace."""
        total_input = 0
        total_output = 0
        for span in self._assembled_spans:
            if span.get("trace_id") != trace_id:
                continue
            if span.get("meta", {}).get("span", {}).get("kind") != "llm":
                continue
            metrics = span.get("metrics", {})
            total_input += metrics.get("input_tokens", 0)
            total_output += metrics.get("output_tokens", 0)
        return {
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
        }

    def _handle_stop(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle Stop / SessionEnd hook event — updates the eagerly-emitted root span with final data."""
        session = self._sessions.get(session_id)
        if not session:
            log.warning("Stop event for unknown session %s", session_id)
            return

        now_ns = int(time.time() * 1_000_000_000)
        duration = now_ns - session.start_ns

        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""
        transcript_path = body.get("transcript_path", "")
        output_value = _read_console_output(transcript_path)

        agent_manifest = {
            "name": "claude-code",
            "instructions": "",
            "handoff_description": "",
            "model": session.model,
            "model_provider": "anthropic",
            "model_settings": {},
            "tools": [{"name": name} for name in sorted(session.tools_used)],
            "handoffs": [],
            "guardrails": [],
        }

        # Find the eagerly-emitted root span and update it in-place
        root_span: Optional[Dict[str, Any]] = getattr(session, "_root_span_ref", None)
        if not root_span:
            # Fallback: search _assembled_spans
            root_span = next(
                (s for s in self._assembled_spans if s.get("span_id") == session.root_span_id),
                None,
            )
        # Compute aggregate token usage from LLM spans in this trace
        token_usage = self._compute_token_usage(session.trace_id)

        if root_span:
            root_span["duration"] = duration
            root_span["meta"]["input"]["value"] = input_value
            root_span["meta"]["output"]["value"] = output_value
            root_span["meta"]["model_name"] = session.model
            root_span["meta"]["model_provider"] = "anthropic"
            root_span["meta"]["metadata"] = {
                "agent_manifest": agent_manifest,
                "model_name": session.model,
                "model_provider": "anthropic",
            }
            root_span["metrics"] = token_usage
        else:
            # No eagerly-emitted root span found — create one as fallback
            root_span = {
                "span_id": session.root_span_id,
                "trace_id": session.trace_id,
                "parent_id": "undefined",
                "name": "claude-code-request",
                "status": "ok",
                "start_ns": session.start_ns,
                "duration": duration,
                "ml_app": "claude-code",
                "service": "claude-code",
                "env": "local",
                "session_id": session.session_id,
                "tags": [
                    "ml_app:claude-code",
                    f"session_id:{session.session_id}",
                    "service:claude-code",
                    "env:local",
                    "source:claude-code-hooks",
                    "language:python",
                    f"hostname:{_HOSTNAME}",
                ],
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {"value": input_value},
                    "output": {"value": output_value},
                    "model_name": session.model,
                    "model_provider": "anthropic",
                    "metadata": {
                        "agent_manifest": agent_manifest,
                        "model_name": session.model,
                        "model_provider": "anthropic",
                    },
                },
                "metrics": token_usage,
            }
            self._assembled_spans.append(root_span)

        session.root_span_emitted = True

    def _handle_session_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SessionEnd hook event.

        If the current turn was already finalized by Stop, this is a no-op.
        If Stop never fired (e.g. user Ctrl+C), finalize the turn as interrupted.
        """
        session = self._sessions.get(session_id)
        if not session:
            return

        if not session.root_span_emitted:
            self._finalize_interrupted_turn(session)

    def _handle_notification(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle Notification hook event — logged but no span emitted."""
        log.info("Claude notification for session %s: %s", session_id, body.get("message", ""))

    def _dispatch_hook(self, body: Dict[str, Any]) -> None:
        """Dispatch a hook event to the appropriate handler."""
        session_id = body.get("session_id", "")
        hook_event_name = body.get("hook_event_name", "")

        handlers: Dict[str, Any] = {
            "SessionStart": self._handle_session_start,
            "UserPromptSubmit": self._handle_user_prompt_submit,
            "PreToolUse": self._handle_pre_tool_use,
            "PostToolUse": self._handle_post_tool_use,
            "SubagentStart": self._handle_subagent_start,
            "SubagentStop": self._handle_subagent_stop,
            "Stop": self._handle_stop,
            "SessionEnd": self._handle_session_end,
            "Notification": self._handle_notification,
        }

        handler = handlers.get(hook_event_name)
        if handler:
            handler(session_id, body)
        else:
            log.debug("Unhandled hook event: %s", hook_event_name)

    async def _forward_span_update(self, spans: List[Dict[str, Any]]) -> None:
        """Forward span updates to the DD backend via the update endpoint."""
        app = self._app
        if not app:
            return

        if not spans:
            return

        dd_site = app.get("dd_site", "")
        dd_api_key = app.get("dd_api_key")
        agent_url = app.get("agent_url", "")
        disable_forwarding = app.get("disable_llmobs_data_forwarding", False)

        if disable_forwarding:
            return

        if agent_url:
            url = f"{agent_url}/evp_proxy/v2/api/v2/llmobs"
            headers: Dict[str, str] = {"Content-Type": "application/msgpack", "Content-Encoding": "gzip"}
        elif dd_api_key and dd_site:
            url = f"https://llmobs-intake.{dd_site}/api/v2/llmobs"
            headers = {
                "Content-Type": "application/msgpack",
                "Content-Encoding": "gzip",
                "DD-API-KEY": dd_api_key,
            }
        else:
            log.debug("No DD_API_KEY/DD_SITE or agent URL configured — skipping LLMObs update forwarding")
            return

        payload = {
            "_dd.stage": "raw",
            "event_type": "span",
            "spans": spans,
        }
        data = gzip.compress(msgpack.packb(payload))

        try:
            async with ClientSession() as http_session:
                async with http_session.post(url, headers=headers, data=data) as resp:
                    if not resp.ok:
                        log.warning("Failed to forward span update: %s %s", resp.status, await resp.text())
                    else:
                        log.info("Forwarded %d span updates", len(spans))
        except Exception as e:
            log.warning("Error forwarding span update: %s", e)

    async def _forward_trace_to_backend(self, session_id: str) -> None:
        """Forward all assembled spans for a session's trace to the backend via the EVP proxy path."""
        app = self._app
        if not app:
            return

        session = self._sessions.get(session_id)
        if not session:
            return

        trace_id = session.trace_id
        spans = [s for s in self._assembled_spans if s.get("trace_id") == trace_id]
        if not spans:
            return

        dd_site = app.get("dd_site", "")
        dd_api_key = app.get("dd_api_key")
        agent_url = app.get("agent_url", "")
        disable_forwarding = app.get("disable_llmobs_data_forwarding", False)

        if disable_forwarding:
            return

        if agent_url:
            url = f"{agent_url}/evp_proxy/v2/api/v2/llmobs"
            headers: Dict[str, str] = {"Content-Type": "application/msgpack", "Content-Encoding": "gzip"}
        elif dd_api_key and dd_site:
            url = f"https://llmobs-intake.{dd_site}/api/v2/llmobs"
            headers = {
                "Content-Type": "application/msgpack",
                "Content-Encoding": "gzip",
                "DD-API-KEY": dd_api_key,
            }
        else:
            log.debug("No DD_API_KEY/DD_SITE or agent URL configured — skipping LLMObs forwarding for Claude hooks")
            return

        payload = {
            "_dd.stage": "raw",
            "event_type": "span",
            "spans": spans,
        }
        data = gzip.compress(msgpack.packb(payload))

        try:
            async with ClientSession() as http_session:
                async with http_session.post(url, headers=headers, data=data) as resp:
                    if not resp.ok:
                        log.warning("Failed to forward Claude hooks spans: %s %s", resp.status, await resp.text())
                    else:
                        log.info("Forwarded %d Claude hooks spans for trace %s", len(spans), trace_id)
        except Exception as e:
            log.warning("Error forwarding Claude hooks spans: %s", e)

    async def handle_hook(self, request: Request) -> web.Response:
        """Handle POST /claude/hooks — receives hook JSON and dispatches by event name."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        session_id = body.get("session_id", "")
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        self._raw_events.append(body)
        self._dispatch_hook(body)

        hook_event_name = body.get("hook_event_name", "")

        # Forward completed traces to the backend (includes the now-updated root span).
        # The eager root span is only used locally so the test agent UI has a root node
        # immediately; we don't forward it on UserPromptSubmit because the DD backend
        # doesn't deduplicate by span_id and would create a duplicate entry.
        if hook_event_name in ("Stop", "SessionEnd"):
            await self._forward_trace_to_backend(session_id)

        return web.json_response({"status": "ok"})

    async def handle_sessions(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/sessions — list tracked sessions."""
        sessions = []
        for sid, state in self._sessions.items():
            sessions.append(
                {
                    "session_id": sid,
                    "trace_id": state.trace_id,
                    "root_span_id": state.root_span_id,
                    "num_prompts": len(state.user_prompts),
                    "agent_stack_depth": len(state.agent_span_stack),
                    "pending_tools": len(state.pending_tools),
                }
            )
        return web.json_response({"sessions": sessions})

    async def handle_spans(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/spans — return all assembled spans."""
        return web.json_response({"spans": self._assembled_spans})

    async def handle_raw_events(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/raw — return all raw received events for debugging."""
        return web.json_response({"events": self._raw_events})

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        return [
            web.post("/claude/hooks", with_cors(self.handle_hook)),
            web.route("*", "/claude/hooks/sessions", with_cors(self.handle_sessions)),
            web.route("*", "/claude/hooks/spans", with_cors(self.handle_spans)),
            web.route("*", "/claude/hooks/raw", with_cors(self.handle_raw_events)),
        ]
