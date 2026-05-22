"""Server-side conversion: claude transcript JSONL entries → LLMObs spans.

This is the backfill counterpart to the live ``claude_hooks`` + ``claude_proxy``
pipeline. The live pipeline gets *lifecycle* events from Claude Code hooks and
*LLM call* data from the proxy intercept. For backfill we have neither of
those streams — only the on-disk transcript at
``~/.claude/projects/<encoded-cwd>/<session-id>.jsonl`` which already contains
the full conversation (user prompts, assistant content blocks, tool_use /
tool_result pairs, ``message.usage`` with token counts, and per-entry
timestamps).

This module reads those entries and emits the same span shape the live
pipeline does, so backfilled sessions are indistinguishable in the UI:

  * One root ``claude-code-request`` agent span **per user prompt** (so a
    file with N user turns becomes N traces, matching live behavior where
    each UserPromptSubmit opens a new trace).
  * One LLM span per ``type=assistant`` entry, with model + token usage +
    cost computed via ``claude_cost_tracker.compute_cost_metrics``.
  * One tool span per tool_use / tool_result pair, parented to the LLM span
    that requested it. Claude Code ``Task`` tool uses become child agent
    spans so backfilled subagents are visible as agents rather than generic
    tools.

Timestamps come from the entries' ``timestamp`` field (ISO-8601). Durations
between adjacent entries are used as best-effort span durations.
"""

from datetime import datetime
import getpass
import os
import socket
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from ddapm_test_agent.backfill_utils import backfill_metadata
from ddapm_test_agent.backfill_utils import format_span_id
from ddapm_test_agent.backfill_utils import format_trace_id
from ddapm_test_agent.backfill_utils import to_text
from ddapm_test_agent.claude_cost_tracker import compute_cost_metrics
from ddapm_test_agent.lapdog_app_names import CLAUDE_CODE_ML_APP as _ML_APP

_HOSTNAME = socket.gethostname()
_USERNAME = os.environ.get("HOST_USER") or getpass.getuser()


def _format_trace_id() -> str:
    return format_trace_id()


def _format_span_id() -> str:
    return format_span_id()


def _parse_iso_ns(ts: Optional[str]) -> Optional[int]:
    """Parse an ISO-8601 ``timestamp`` into nanoseconds since epoch.

    Returns None for missing or malformed values.
    """
    if not ts:
        return None
    try:
        # Python 3.10 fromisoformat doesn't accept the trailing 'Z' (only +00:00).
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return int(datetime.fromisoformat(ts).timestamp() * 1_000_000_000)
    except (TypeError, ValueError):
        return None


def _format_output_messages(content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Render assistant content blocks as LLMObs output messages.

    Mirrors ``claude_proxy._format_output_messages`` so the rendering
    matches what the live proxy emits.
    """
    messages: List[Dict[str, Any]] = []
    for block in content_blocks:
        if not isinstance(block, dict):
            continue
        btype = block.get("type", "")
        if btype == "text":
            messages.append({"role": "assistant", "content": block.get("text", "")})
        elif btype == "tool_use":
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "name": block.get("name", ""),
                            "arguments": block.get("input", {}),
                            "tool_id": block.get("id", ""),
                            "type": "tool_use",
                        }
                    ],
                }
            )
    return messages


def _common_tags(session_id: str, source: str = "claude-code-backfill") -> List[str]:
    return [
        f"ml_app:{_ML_APP}",
        f"service:{_ML_APP}",
        "env:local",
        f"source:{source}",
        "language:python",
        f"hostname:{_HOSTNAME}",
        f"user_name:{_USERNAME}",
        f"session_id:{session_id}",
        "backfilled:true",
    ]


def _new_turn(session_id: str, cwd: str, model: str, start_ns: int, prompt: str) -> Dict[str, Any]:
    """Open a new turn — generate trace + root agent span."""
    trace_id = _format_trace_id()
    root_span_id = _format_span_id()
    root_span: Dict[str, Any] = {
        "span_id": root_span_id,
        "trace_id": trace_id,
        "parent_id": "undefined",
        "name": "claude-code-request",
        "start_ns": start_ns,
        "duration": 0,
        "status": "ok",
        "error": 0,
        "ml_app": _ML_APP,
        "service": _ML_APP,
        "env": "local",
        "session_id": session_id,
        "tags": _common_tags(session_id) + ([f"cwd:{cwd}"] if cwd else []),
        "meta": {
            "span": {"kind": "agent"},
            "kind": "agent",
            "input": {"value": prompt},
            "output": {"value": ""},
            "model_name": model,
            "model_provider": "anthropic",
            "metadata": {
                "_dd": {
                    **backfill_metadata(),
                    "agent_manifest": {
                        "name": _ML_APP,
                        "model": model,
                        "model_provider": "anthropic",
                    },
                },
            },
        },
        "metrics": {},
        "span_links": [],
    }
    return {
        "trace_id": trace_id,
        "root_span_id": root_span_id,
        "root_span": root_span,
        "start_ns": start_ns,
        "end_ns": start_ns,
        "pending_tools": {},  # tool_use_id → {start_ns, llm_span_id, name, input}
        "user_prompts": [prompt],
        "assistant_text_chunks": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "total_cost": 0.0,
        "tools_used": set(),
        "model_set": bool(model),
    }


def _build_llm_span(
    session_id: str,
    msg: Dict[str, Any],
    content: List[Dict[str, Any]],
    model: str,
    start_ns: int,
    duration_ns: int,
    parent_span_id: str,
    trace_id: str,
) -> Dict[str, Any]:
    usage = msg.get("usage") or {}
    raw_input = int(usage.get("input_tokens", 0) or 0)
    cache_read = int(usage.get("cache_read_input_tokens", 0) or 0)
    cache_creation = int(usage.get("cache_creation_input_tokens", 0) or 0)
    output = int(usage.get("output_tokens", 0) or 0)
    total_input = raw_input + cache_read + cache_creation

    cost_metrics = (
        compute_cost_metrics(
            model_id=model,
            non_cached_input_tokens=raw_input,
            cache_write_tokens=cache_creation,
            cache_read_tokens=cache_read,
            output_tokens=output,
        )
        or {}
    )

    return {
        "span_id": _format_span_id(),
        "trace_id": trace_id,
        "parent_id": parent_span_id,
        "name": model or "llm-call",
        "start_ns": start_ns,
        "duration": duration_ns,
        "status": "ok",
        "error": 0,
        "ml_app": _ML_APP,
        "service": _ML_APP,
        "env": "local",
        "session_id": session_id,
        "tags": _common_tags(session_id, source="claude-code-backfill-llm"),
        "meta": {
            "span": {"kind": "llm"},
            "kind": "llm",
            "model_name": model,
            "model_provider": "anthropic",
            # Input messages aren't recoverable from the on-disk transcript
            # (it only stores the assistant response, not the request payload
            # the SDK sent upstream). Leaving empty is honest.
            "input": {"messages": []},
            "output": {"messages": _format_output_messages(content)},
            "metadata": {
                "stop_reason": msg.get("stop_reason", ""),
                "_dd": backfill_metadata(input_messages_unavailable=True),
            },
        },
        "metrics": {
            "input_tokens": total_input,
            "output_tokens": output,
            "total_tokens": total_input + output,
            "cache_read_input_tokens": cache_read,
            "cache_write_input_tokens": cache_creation,
            "non_cached_input_tokens": raw_input,
            **cost_metrics,
        },
        "span_links": [],
    }


def _build_tool_span(
    session_id: str,
    trace_id: str,
    pending: Dict[str, Any],
    tool_result_block: Dict[str, Any],
    end_ns: int,
) -> Dict[str, Any]:
    tool_name = pending.get("name", "unknown_tool")
    tool_input = pending.get("input", {}) or {}
    start_ns = pending["start_ns"]
    duration = max(0, end_ns - start_ns)
    is_error = bool(tool_result_block.get("is_error", False))
    output_value = tool_result_block.get("content", "")
    if isinstance(output_value, list):
        output_value = " ".join((b.get("text", "") if isinstance(b, dict) else str(b)) for b in output_value)
    elif not isinstance(output_value, str):
        output_value = to_text(output_value)
    if tool_name == "Task":
        tool_description = ""
        if isinstance(tool_input, dict):
            tool_description = str(tool_input.get("description") or "")
        span_name = f"Task - {tool_description}" if tool_description else "Task"
        return {
            "span_id": _format_span_id(),
            "trace_id": trace_id,
            "parent_id": pending["llm_span_id"],
            "name": span_name,
            "start_ns": start_ns,
            "duration": duration,
            "status": "error" if is_error else "ok",
            "error": 1 if is_error else 0,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session_id,
            "tags": _common_tags(session_id, source="claude-code-backfill-subagent"),
            "meta": {
                "span": {"kind": "agent"},
                "kind": "agent",
                "input": {"value": to_text(tool_input)},
                "output": {"value": output_value},
                "metadata": {
                    "subagent": {
                        "tool_use_id": pending.get("id", ""),
                        "description": tool_description,
                        "prompt": tool_input.get("prompt", "") if isinstance(tool_input, dict) else "",
                    },
                    "_dd": backfill_metadata(),
                },
                **({"error": {"message": output_value}} if is_error else {}),
            },
            "metrics": {},
            "span_links": [],
        }
    return {
        "span_id": _format_span_id(),
        "trace_id": trace_id,
        "parent_id": pending["llm_span_id"],
        "name": f"{tool_name}",
        "start_ns": start_ns,
        "duration": duration,
        "status": "error" if is_error else "ok",
        "error": 1 if is_error else 0,
        "ml_app": _ML_APP,
        "service": _ML_APP,
        "env": "local",
        "session_id": session_id,
        "tags": _common_tags(session_id, source="claude-code-backfill-tool"),
        "meta": {
            "span": {"kind": "tool"},
            "kind": "tool",
            "input": {"value": to_text(tool_input)},
            "output": {"value": output_value},
            "metadata": {
                "tool_name": tool_name,
                "tool_use_id": pending.get("id", ""),
                "_dd": backfill_metadata(),
            },
            **({"error": {"message": output_value}} if is_error else {}),
        },
        "metrics": {},
        "span_links": [],
    }


def _set_turn_model(turn: Dict[str, Any], model: str) -> None:
    if not model or turn.get("model_set"):
        return
    root = turn["root_span"]
    root["meta"]["model_name"] = model
    root["meta"]["metadata"]["_dd"]["agent_manifest"]["model"] = model
    turn["model_set"] = True


def _finalize_turn(turn: Dict[str, Any]) -> None:
    """Update root span aggregates after all child spans are built."""
    root = turn["root_span"]
    root["duration"] = max(0, turn["end_ns"] - turn["start_ns"])
    root["meta"]["output"]["value"] = "\n".join(turn["assistant_text_chunks"]).strip()
    if turn["total_tokens"]:
        root["metrics"]["input_tokens"] = turn["input_tokens"]
        root["metrics"]["output_tokens"] = turn["output_tokens"]
        root["metrics"]["total_tokens"] = turn["total_tokens"]
        if turn["total_cost"]:
            root["metrics"]["estimated_total_cost"] = turn["total_cost"]
    if turn["tools_used"]:
        root["meta"]["metadata"]["_dd"]["agent_manifest"]["tools"] = [
            {"name": name} for name in sorted(turn["tools_used"])
        ]


def session_to_spans(session_id: str, cwd: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert a session's transcript entries into a flat list of LLMObs spans.

    A new turn (and a new trace_id) is started for every user prompt — so a
    file with N user prompts produces N traces, matching the live behavior of
    ``claude_hooks._handle_user_prompt_submit``.

    Entries without a parseable ``timestamp`` are skipped.
    """
    spans: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    # Track the previous entry's timestamp so the LLM span can have a non-zero
    # duration (best-effort: end-to-start of consecutive entries).
    previous_ts_ns: Optional[int] = None

    for entry in entries:
        etype = entry.get("type")
        if etype not in ("user", "assistant"):
            continue
        msg = entry.get("message") or {}
        content = msg.get("content")
        ts_ns = _parse_iso_ns(entry.get("timestamp"))
        if ts_ns is None:
            continue

        if etype == "user":
            if isinstance(content, str) and content:
                # New user prompt → finalize prior turn, open a new one.
                if current is not None:
                    _finalize_turn(current)
                current = _new_turn(session_id, cwd, "", ts_ns, content)
                spans.append(current["root_span"])
            elif isinstance(content, list) and current is not None:
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "tool_result":
                        tu_id = block.get("tool_use_id") or ""
                        pending = current["pending_tools"].pop(tu_id, None)
                        if pending is None:
                            continue
                        tool_span = _build_tool_span(session_id, current["trace_id"], pending, block, ts_ns)
                        spans.append(tool_span)
                        current["end_ns"] = max(current["end_ns"], ts_ns)
                        current["tools_used"].add(pending.get("name", ""))
        elif etype == "assistant" and isinstance(content, list) and current is not None:
            raw_model = msg.get("model")
            model = (
                raw_model
                if isinstance(raw_model, str) and raw_model
                else current["root_span"]["meta"].get("model_name", "")
            )
            _set_turn_model(current, model)
            # Best-effort duration: time since previous entry's timestamp.
            duration_ns = max(0, ts_ns - (previous_ts_ns or ts_ns))
            llm_span = _build_llm_span(
                session_id=session_id,
                msg=msg,
                content=content,
                model=model,
                start_ns=ts_ns,
                duration_ns=duration_ns,
                parent_span_id=current["root_span_id"],
                trace_id=current["trace_id"],
            )
            spans.append(llm_span)
            metrics = llm_span["metrics"]
            current["input_tokens"] += metrics.get("input_tokens", 0)
            current["output_tokens"] += metrics.get("output_tokens", 0)
            current["total_tokens"] += metrics.get("total_tokens", 0)
            current["total_cost"] += float(metrics.get("estimated_total_cost", 0) or 0)
            current["end_ns"] = max(current["end_ns"], ts_ns)

            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    txt = block.get("text") or ""
                    if txt:
                        current["assistant_text_chunks"].append(txt)
                elif btype == "tool_use":
                    tu_id = block.get("id") or ""
                    if tu_id:
                        current["pending_tools"][tu_id] = {
                            "id": tu_id,
                            "name": block.get("name", "unknown_tool"),
                            "input": block.get("input", {}),
                            "start_ns": ts_ns,
                            "llm_span_id": llm_span["span_id"],
                        }

        previous_ts_ns = ts_ns

    if current is not None:
        _finalize_turn(current)

    return spans
