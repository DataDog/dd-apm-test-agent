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
  * One tool span per tool_use / tool_result pair, parented to the step span
    for that inference cycle. Claude Code ``Task`` tool uses become child
    agent spans parented to the same step span, so backfilled subagents are
    visible as agents rather than generic tools while matching live traces.
  * Subagent (e.g. ``Explore``) conversations — which Claude writes to
    separate ``<session-id>/subagents/agent-*.jsonl`` files and the client
    bundles into the ``subagents`` payload — are nested *under* the ``Task``
    agent span that launched them (matched by launch prompt), in the same
    trace and session, instead of being backfilled as standalone sessions.

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


def _closed_duration_ns(start_ns: int, end_ns: int) -> int:
    """Completed backfill spans must not use duration=0.

    The static LLM Observability app treats a root span with zero duration as
    still running. Historical backfill payloads are complete by definition, so
    use a 1ns floor when adjacent transcript entries share a timestamp.
    """
    return max(1, end_ns - start_ns)


def _assistant_text(content_blocks: List[Dict[str, Any]]) -> str:
    chunks: List[str] = []
    for block in content_blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            txt = block.get("text") or ""
            if txt:
                chunks.append(txt)
    return "\n\n".join(chunks)


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
    trace_id = format_trace_id()
    root_span_id = format_span_id()
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
        "step_count": 0,
    }


def _build_step_span(
    session_id: str,
    trace_id: str,
    parent_span_id: str,
    index: int,
    start_ns: int,
    end_ns: int,
    content: List[Dict[str, Any]],
    stop_reason: str,
) -> Dict[str, Any]:
    tool_use_ids = [
        str(block.get("id"))
        for block in content
        if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("id")
    ]
    metadata: Dict[str, Any] = {
        "message_index": index,
        "_dd": backfill_metadata(),
    }
    if stop_reason:
        metadata["stop_reason"] = stop_reason
    if tool_use_ids:
        metadata["tool_use_ids"] = tool_use_ids
    if any(isinstance(block, dict) and block.get("type") == "thinking" for block in content):
        metadata["has_thinking"] = True

    return {
        "span_id": format_span_id(),
        "trace_id": trace_id,
        "parent_id": parent_span_id,
        "name": f"inference-{index}",
        "start_ns": start_ns,
        "duration": _closed_duration_ns(start_ns, end_ns),
        "status": "ok",
        "error": 0,
        "ml_app": _ML_APP,
        "service": _ML_APP,
        "env": "local",
        "session_id": session_id,
        "tags": _common_tags(session_id, source="claude-code-backfill-step")
        + ["trajectory.semantic_type:agent_message"],
        "meta": {
            "span": {"kind": "step"},
            "kind": "step",
            "input": {},
            "output": {"value": _assistant_text(content)},
            "metadata": metadata,
        },
        "metrics": {},
        "span_links": [],
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
        "span_id": format_span_id(),
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


def _tool_result_text(tool_result_block: Dict[str, Any]) -> str:
    """Render a ``tool_result`` block's content as a plain string."""
    output_value = tool_result_block.get("content", "")
    if isinstance(output_value, list):
        return " ".join((b.get("text", "") if isinstance(b, dict) else str(b)) for b in output_value)
    if not isinstance(output_value, str):
        return to_text(output_value)
    return output_value


def _build_subagent_span(
    session_id: str,
    trace_id: str,
    pending: Dict[str, Any],
    tool_result_block: Dict[str, Any],
    end_ns: int,
    agent_id: str = "",
) -> Dict[str, Any]:
    """Build the ``agent`` span for a subagent-spawning tool call (``Task``).

    The subagent's own conversation lives in a separate transcript that
    ``_subagent_to_spans`` attaches *under* this span, so a backfilled subagent
    shows up as a nested agent in the same trace — matching the live pipeline —
    rather than leaking into a separate session.
    """
    tool_name = pending.get("name", "Task")
    tool_input = pending.get("input", {}) or {}
    start_ns = pending["start_ns"]
    duration = _closed_duration_ns(start_ns, end_ns)
    is_error = bool(tool_result_block.get("is_error", False))
    output_value = _tool_result_text(tool_result_block)

    description = subagent_type = prompt = ""
    if isinstance(tool_input, dict):
        description = str(tool_input.get("description") or "")
        subagent_type = str(tool_input.get("subagent_type") or "")
        prompt = str(tool_input.get("prompt") or "")
    label = description or subagent_type
    span_name = f"{tool_name} - {label}" if label else tool_name

    subagent_meta: Dict[str, Any] = {
        "tool_use_id": pending.get("id", ""),
        "description": description,
        "prompt": prompt,
    }
    if subagent_type:
        subagent_meta["agent_type"] = subagent_type
    if agent_id:
        subagent_meta["agent_id"] = agent_id

    return {
        "span_id": format_span_id(),
        "trace_id": trace_id,
        "parent_id": pending.get("parent_span_id", pending["llm_span_id"]),
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
                "subagent": subagent_meta,
                "_dd": backfill_metadata(),
            },
            **({"error": {"message": output_value}} if is_error else {}),
        },
        "metrics": {},
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
    duration = _closed_duration_ns(start_ns, end_ns)
    is_error = bool(tool_result_block.get("is_error", False))
    output_value = _tool_result_text(tool_result_block)
    return {
        "span_id": format_span_id(),
        "trace_id": trace_id,
        "parent_id": pending.get("parent_span_id", pending["llm_span_id"]),
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
    root["duration"] = _closed_duration_ns(turn["start_ns"], turn["end_ns"])
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


def _norm_prompt(prompt: Any) -> str:
    return prompt.strip() if isinstance(prompt, str) else ""


def _subagent_prompt(entries: List[Dict[str, Any]]) -> str:
    """Return the prompt a subagent was launched with.

    It is the first ``user`` message in the subagent's transcript, which Claude
    stores as a plain string; that same string is the parent ``Task`` tool_use's
    ``input.prompt``, which is how the two are re-linked across files.
    """
    for entry in entries:
        if entry.get("type") != "user":
            continue
        content = (entry.get("message") or {}).get("content")
        if isinstance(content, str) and content:
            return content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                    return str(block["text"])
        return ""
    return ""


def _first_ts_ns(entries: List[Dict[str, Any]]) -> Optional[int]:
    for entry in entries:
        if entry.get("type") in ("user", "assistant"):
            ts_ns = _parse_iso_ns(entry.get("timestamp"))
            if ts_ns is not None:
                return ts_ns
    return None


def _build_subagent_index(
    subagents: Optional[List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Index subagent transcripts by their normalized launch prompt.

    Several subagents can share a prompt, so each key maps to a list consumed
    in order as matching ``Task`` calls are encountered.
    """
    index: Dict[str, List[Dict[str, Any]]] = {}
    for sub in subagents or []:
        sub_entries = sub.get("entries") or []
        prompt = _norm_prompt(_subagent_prompt(sub_entries))
        if not prompt or not sub_entries:
            continue
        index.setdefault(prompt, []).append({"agent_id": sub.get("agent_id") or "", "entries": sub_entries})
    return index


def _claim_subagent(
    index: Dict[str, List[Dict[str, Any]]],
    prompt: Any,
) -> Optional[Dict[str, Any]]:
    """Pop (consume) the next subagent transcript launched with ``prompt``."""
    key = _norm_prompt(prompt)
    if not key:
        return None
    bucket = index.get(key)
    if not bucket:
        return None
    return bucket.pop(0)


def _finish_pending_tool_result(
    session_id: str,
    trace_id: str,
    pending: Dict[str, Any],
    tool_result_block: Dict[str, Any],
    end_ns: int,
    subagent_index: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Convert a completed tool_result into either a tool span or subagent tree."""
    tool_input = pending.get("input") or {}
    prompt = tool_input.get("prompt") if isinstance(tool_input, dict) else None
    claim = _claim_subagent(subagent_index, prompt)

    if pending.get("name") == "Task" or claim is not None:
        agent_span = _build_subagent_span(
            session_id,
            trace_id,
            pending,
            tool_result_block,
            end_ns,
            agent_id=(claim or {}).get("agent_id", ""),
        )
        spans = [agent_span]
        if claim is not None:
            spans.extend(_subagent_to_spans(session_id, agent_span, trace_id, claim["entries"], subagent_index))
    else:
        spans = [_build_tool_span(session_id, trace_id, pending, tool_result_block, end_ns)]

    step_span = pending.get("step_span")
    if isinstance(step_span, dict):
        step_span["duration"] = _closed_duration_ns(step_span["start_ns"], end_ns)
    return spans


def _subagent_to_spans(
    session_id: str,
    agent_span: Dict[str, Any],
    trace_id: str,
    entries: List[Dict[str, Any]],
    subagent_index: Dict[str, List[Dict[str, Any]]],
    *,
    standalone: bool = False,
) -> List[Dict[str, Any]]:
    """Convert a subagent's transcript into spans nested under ``agent_span``.

    Mirrors the per-turn logic in ``session_to_spans`` but uses ``agent_span``
    as the root: the subagent's first ``user`` message is its launch prompt —
    already captured as the agent span's input — so it does not open a new
    turn. Subagents the transcript itself spawned are nested recursively. The
    aggregated token usage / cost is rolled up onto ``agent_span``.

    When ``standalone`` is True the agent span is a freshly-minted root (used as
    a fallback when a transcript couldn't be matched to a parent ``Task`` call),
    so its start/duration/output are derived from the transcript here.
    """
    spans: List[Dict[str, Any]] = []
    parent_span_id = str(agent_span["span_id"])
    pending_tools: Dict[str, Dict[str, Any]] = {}
    previous_ts_ns: Optional[int] = None
    start_ns: Optional[int] = None
    end_ns: Optional[int] = None
    input_tokens = output_tokens = total_tokens = 0
    total_cost = 0.0
    text_chunks: List[str] = []
    model_name = ""
    step_count = 0

    for entry in entries:
        etype = entry.get("type")
        if etype not in ("user", "assistant"):
            continue
        msg = entry.get("message") or {}
        content = msg.get("content")
        ts_ns = _parse_iso_ns(entry.get("timestamp"))
        if ts_ns is None:
            continue
        if start_ns is None:
            start_ns = ts_ns

        if etype == "user":
            # A string user message is the launch prompt (already the agent
            # span's input) — never open a new turn inside a subagent.
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    tu_id = block.get("tool_use_id") or ""
                    pending = pending_tools.pop(tu_id, None)
                    if pending is None:
                        continue
                    spans.extend(
                        _finish_pending_tool_result(session_id, trace_id, pending, block, ts_ns, subagent_index)
                    )
                    end_ns = ts_ns if end_ns is None else max(end_ns, ts_ns)
        elif etype == "assistant" and isinstance(content, list):
            raw_model = msg.get("model")
            model = raw_model if isinstance(raw_model, str) and raw_model else model_name
            if not model_name and model:
                model_name = model
            llm_start_ns = previous_ts_ns or end_ns or start_ns or ts_ns
            step_span = _build_step_span(
                session_id=session_id,
                trace_id=trace_id,
                parent_span_id=parent_span_id,
                index=step_count,
                start_ns=llm_start_ns,
                end_ns=ts_ns,
                content=content,
                stop_reason=str(msg.get("stop_reason") or ""),
            )
            step_count += 1
            spans.append(step_span)
            llm_span = _build_llm_span(
                session_id=session_id,
                msg=msg,
                content=content,
                model=model,
                start_ns=llm_start_ns,
                duration_ns=_closed_duration_ns(llm_start_ns, ts_ns),
                parent_span_id=step_span["span_id"],
                trace_id=trace_id,
            )
            spans.append(llm_span)
            metrics = llm_span["metrics"]
            input_tokens += metrics.get("input_tokens", 0)
            output_tokens += metrics.get("output_tokens", 0)
            total_tokens += metrics.get("total_tokens", 0)
            total_cost += float(metrics.get("estimated_total_cost", 0) or 0)
            end_ns = ts_ns if end_ns is None else max(end_ns, ts_ns)
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    txt = block.get("text") or ""
                    if txt:
                        text_chunks.append(txt)
                elif btype == "tool_use":
                    tu_id = block.get("id") or ""
                    if tu_id:
                        pending_tools[tu_id] = {
                            "id": tu_id,
                            "name": block.get("name", "unknown_tool"),
                            "input": block.get("input", {}),
                            "start_ns": ts_ns,
                            "llm_span_id": llm_span["span_id"],
                            "parent_span_id": step_span["span_id"],
                            "step_span": step_span,
                        }
        previous_ts_ns = ts_ns

    if total_tokens:
        agent_span["metrics"]["input_tokens"] = input_tokens
        agent_span["metrics"]["output_tokens"] = output_tokens
        agent_span["metrics"]["total_tokens"] = total_tokens
        if total_cost:
            agent_span["metrics"]["estimated_total_cost"] = total_cost
    if model_name:
        agent_span["meta"]["model_name"] = model_name
        agent_span["meta"].setdefault("model_provider", "anthropic")
    if standalone and start_ns is not None:
        agent_span["start_ns"] = start_ns
        agent_span["duration"] = _closed_duration_ns(start_ns, end_ns or start_ns)
        agent_span["meta"]["output"]["value"] = "\n".join(text_chunks).strip()
    return spans


def session_to_spans(
    session_id: str,
    cwd: str,
    entries: List[Dict[str, Any]],
    subagents: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Convert a session's transcript entries into a flat list of LLMObs spans.

    A new turn (and a new trace_id) is started for every user prompt — so a
    file with N user prompts produces N traces, matching the live behavior of
    ``claude_hooks._handle_user_prompt_submit``.

    ``subagents`` carries the transcripts Claude wrote for any subagents this
    session spawned (``Task`` / ``Explore`` etc.), which live in separate files
    on disk. Each is nested under the ``Task`` agent span that launched it,
    sharing the parent turn's trace, so subagents no longer split off into
    their own sessions.

    Entries without a parseable ``timestamp`` are skipped.
    """
    subagent_index = _build_subagent_index(subagents)
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
                        spans.extend(
                            _finish_pending_tool_result(
                                session_id,
                                current["trace_id"],
                                pending,
                                block,
                                ts_ns,
                                subagent_index,
                            )
                        )
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
            # Best-effort: an assistant transcript timestamp represents the
            # completed response, so start the inference at the prior
            # transcript event and end it at this assistant event.
            llm_start_ns = previous_ts_ns or current["end_ns"] or ts_ns
            step_index = int(current["step_count"])
            current["step_count"] = step_index + 1
            step_span = _build_step_span(
                session_id=session_id,
                trace_id=current["trace_id"],
                parent_span_id=current["root_span_id"],
                index=step_index,
                start_ns=llm_start_ns,
                end_ns=ts_ns,
                content=content,
                stop_reason=str(msg.get("stop_reason") or ""),
            )
            spans.append(step_span)
            duration_ns = _closed_duration_ns(llm_start_ns, ts_ns)
            llm_span = _build_llm_span(
                session_id=session_id,
                msg=msg,
                content=content,
                model=model,
                start_ns=llm_start_ns,
                duration_ns=duration_ns,
                parent_span_id=step_span["span_id"],
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
                            "parent_span_id": step_span["span_id"],
                            "step_span": step_span,
                        }

        previous_ts_ns = ts_ns

    if current is not None:
        _finalize_turn(current)

    # Any subagent transcript that never matched a Task call still belongs to
    # this session — emit it as its own trace under the SAME session_id rather
    # than letting it leak into a separate session (the original bug). Draining
    # by popping handles nested subagents claimed during recursion.
    while True:
        orphan = next((bucket.pop(0) for bucket in subagent_index.values() if bucket), None)
        if orphan is None:
            break
        orphan_entries = orphan["entries"]
        start_ns = _first_ts_ns(orphan_entries)
        if start_ns is None:
            continue
        root = _new_turn(session_id, cwd, "", start_ns, _subagent_prompt(orphan_entries))["root_span"]
        agent_id = orphan.get("agent_id") or ""
        if agent_id:
            root["meta"]["metadata"]["_dd"]["agent_id"] = agent_id
        spans.append(root)
        spans.extend(
            _subagent_to_spans(session_id, root, root["trace_id"], orphan_entries, subagent_index, standalone=True)
        )

    return spans
