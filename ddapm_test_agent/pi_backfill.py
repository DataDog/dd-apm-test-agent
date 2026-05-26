"""Server-side conversion: pi/omp session JSONL entries → LLMObs spans.

Pi's on-disk transcript already carries everything we need to recreate a
trace: per-message timestamps (in milliseconds), model + provider, content
blocks (text / toolCall / thinking), and a ``message.usage`` dict with token
counts AND a pre-computed ``cost`` object in dollars. Tool results arrive as
separate ``role=toolResult`` messages referencing the ``toolCallId`` of the
originating tool_use.

This module mirrors ``claude_backfill`` but adapted to pi's format. One
agent root span is opened per user message; LLM spans hang off the root;
tool spans hang off their owning LLM span and are sized by the gap between
the toolCall and the matching toolResult.
"""

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
from ddapm_test_agent.lapdog_app_names import PI_CODING_AGENT_ML_APP as _ML_APP

_HOSTNAME = socket.gethostname()
_USERNAME = os.environ.get("HOST_USER") or getpass.getuser()


def _format_trace_id() -> str:
    return format_trace_id()


def _format_span_id() -> str:
    return format_span_id()


def _parse_ts_ns(ts: Any) -> Optional[int]:
    """Pi timestamps are milliseconds-since-epoch (numeric)."""
    if ts is None:
        return None
    try:
        return int(ts) * 1_000_000
    except (TypeError, ValueError):
        return None


def _closed_duration_ns(start_ns: int, end_ns: int) -> int:
    """Completed backfill spans must not use duration=0.

    The static LLM Observability app treats a root span with zero duration as
    still running. Historical backfill payloads are complete by definition, so
    use a 1ns floor when adjacent transcript entries share a timestamp.
    """
    return max(1, end_ns - start_ns)


def _common_tags(session_id: str, source: str = "pi-backfill") -> List[str]:
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


def _format_output_messages(content: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pi assistant content blocks → LLMObs output messages."""
    out: List[Dict[str, Any]] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type", "")
        if btype == "text":
            out.append({"role": "assistant", "content": block.get("text", "")})
        elif btype == "toolCall":
            out.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "name": block.get("name", ""),
                            "arguments": block.get("arguments", {}) or {},
                            "tool_id": block.get("id", ""),
                            "type": "tool_use",
                        }
                    ],
                }
            )
    return out


def _assistant_text(content: List[Dict[str, Any]]) -> str:
    chunks: List[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text") or ""
            if text:
                chunks.append(text)
    return "\n\n".join(chunks)


def _user_text(message: Dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: List[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                t = block.get("text") or ""
                if t:
                    chunks.append(t)
        return "\n".join(chunks)
    return ""


def _new_turn(session_id: str, cwd: str, model: str, start_ns: int, prompt: str) -> Dict[str, Any]:
    trace_id = _format_trace_id()
    root_span_id = _format_span_id()
    root_span: Dict[str, Any] = {
        "span_id": root_span_id,
        "trace_id": trace_id,
        "parent_id": "undefined",
        "name": "pi-agent-turn",
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
            "metadata": {"_dd": backfill_metadata()},
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
        "pending_tools": {},
        "assistant_text_chunks": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
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
        if isinstance(block, dict) and block.get("type") == "toolCall" and block.get("id")
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
        "span_id": _format_span_id(),
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
        "tags": _common_tags(session_id, source="pi-backfill-step") + ["trajectory.semantic_type:agent_message"],
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
    trace_id: str,
    parent_span_id: str,
    msg: Dict[str, Any],
    model: str,
    start_ns: int,
    duration_ns: int,
) -> Dict[str, Any]:
    usage = msg.get("usage") or {}
    input_tokens = int(usage.get("input", 0) or 0)
    output_tokens = int(usage.get("output", 0) or 0)
    cache_read = int(usage.get("cacheRead", 0) or 0)
    cache_write = int(usage.get("cacheWrite", 0) or 0)
    total = int(usage.get("totalTokens", input_tokens + output_tokens + cache_read + cache_write) or 0)
    cost = usage.get("cost") or {}
    total_cost_usd = float(cost.get("total", 0) or 0)
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
        "tags": _common_tags(session_id, source="pi-backfill-llm"),
        "meta": {
            "span": {"kind": "llm"},
            "kind": "llm",
            "model_name": model,
            "model_provider": str(msg.get("provider") or "anthropic"),
            "input": {"messages": []},
            "output": {"messages": _format_output_messages(msg.get("content") or [])},
            "metadata": {
                "stop_reason": msg.get("stopReason", ""),
                "_dd": backfill_metadata(input_messages_unavailable=True),
            },
        },
        "metrics": {
            "input_tokens": input_tokens + cache_read + cache_write,
            "output_tokens": output_tokens,
            "total_tokens": total,
            "cache_read_input_tokens": cache_read,
            "cache_write_input_tokens": cache_write,
            "non_cached_input_tokens": input_tokens,
            # pi's cost is in dollars; convert to nanodollars to match the
            # convention used by ``claude_cost_tracker.compute_cost_metrics``
            # so dashboards summing across sources don't need source-specific
            # unit handling.
            "estimated_total_cost": int(round(total_cost_usd * 1_000_000_000)),
        },
        "span_links": [],
    }


def _tool_result_text(message: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for block in message.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            t = block.get("text") or ""
            if t:
                chunks.append(t)
    return "\n".join(chunks)


def _build_tool_span(
    session_id: str,
    trace_id: str,
    pending: Dict[str, Any],
    tool_result_msg: Dict[str, Any],
    end_ns: int,
) -> Dict[str, Any]:
    tool_name = pending.get("name", "unknown_tool")
    start_ns = pending["start_ns"]
    duration = _closed_duration_ns(start_ns, end_ns)
    is_error = bool(tool_result_msg.get("isError", False))
    output_value = _tool_result_text(tool_result_msg)
    return {
        "span_id": _format_span_id(),
        "trace_id": trace_id,
        "parent_id": pending.get("parent_span_id", pending["llm_span_id"]),
        "name": tool_name,
        "start_ns": start_ns,
        "duration": duration,
        "status": "error" if is_error else "ok",
        "error": 1 if is_error else 0,
        "ml_app": _ML_APP,
        "service": _ML_APP,
        "env": "local",
        "session_id": session_id,
        "tags": _common_tags(session_id, source="pi-backfill-tool"),
        "meta": {
            "span": {"kind": "tool"},
            "kind": "tool",
            "input": {"value": to_text(pending.get("input") or {})},
            "output": {"value": output_value},
            "metadata": {
                "tool_name": tool_name,
                "tool_call_id": pending.get("id", ""),
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
    turn["root_span"]["meta"]["model_name"] = model
    turn["model_set"] = True


def _finalize_turn(turn: Dict[str, Any]) -> None:
    root = turn["root_span"]
    root["duration"] = _closed_duration_ns(turn["start_ns"], turn["end_ns"])
    root["meta"]["output"]["value"] = "\n".join(turn["assistant_text_chunks"]).strip()
    if turn["total_tokens"]:
        root["metrics"]["input_tokens"] = turn["input_tokens"]
        root["metrics"]["output_tokens"] = turn["output_tokens"]
        root["metrics"]["total_tokens"] = turn["total_tokens"]
        if turn["total_cost_usd"]:
            root["metrics"]["estimated_total_cost"] = int(round(turn["total_cost_usd"] * 1_000_000_000))


def session_to_spans(session_id: str, cwd: str, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert pi/omp transcript entries into LLMObs spans.

    Same trace-per-user-turn convention as ``claude_backfill.session_to_spans``.
    """
    spans: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    previous_ts_ns: Optional[int] = None

    for entry in entries:
        if entry.get("type") != "message":
            continue
        msg = entry.get("message") or {}
        role = msg.get("role")
        ts_ns = _parse_ts_ns(msg.get("timestamp"))
        if ts_ns is None:
            continue

        if role == "user":
            text = _user_text(msg)
            if not text:
                continue
            if current is not None:
                _finalize_turn(current)
            current = _new_turn(session_id, cwd, "", ts_ns, text)
            spans.append(current["root_span"])
        elif role == "assistant" and current is not None:
            content = msg.get("content") or []
            model = str(msg.get("model") or current["root_span"]["meta"].get("model_name", ""))
            _set_turn_model(current, model)
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
                stop_reason=str(msg.get("stopReason") or ""),
            )
            spans.append(step_span)
            duration_ns = _closed_duration_ns(llm_start_ns, ts_ns)
            llm_span = _build_llm_span(
                session_id=session_id,
                trace_id=current["trace_id"],
                parent_span_id=step_span["span_id"],
                msg=msg,
                model=model,
                start_ns=llm_start_ns,
                duration_ns=duration_ns,
            )
            spans.append(llm_span)
            metrics = llm_span["metrics"]
            current["input_tokens"] += metrics.get("input_tokens", 0)
            current["output_tokens"] += metrics.get("output_tokens", 0)
            current["total_tokens"] += metrics.get("total_tokens", 0)
            current["total_cost_usd"] += float((msg.get("usage") or {}).get("cost", {}).get("total", 0) or 0)
            current["end_ns"] = max(current["end_ns"], ts_ns)
            for block in content:
                if not isinstance(block, dict):
                    continue
                btype = block.get("type")
                if btype == "text":
                    t = block.get("text") or ""
                    if t:
                        current["assistant_text_chunks"].append(t)
                elif btype == "toolCall":
                    tc_id = block.get("id") or ""
                    if tc_id:
                        current["pending_tools"][tc_id] = {
                            "id": tc_id,
                            "name": block.get("name", "unknown_tool"),
                            "input": block.get("arguments", {}),
                            "start_ns": ts_ns,
                            "llm_span_id": llm_span["span_id"],
                            "parent_span_id": step_span["span_id"],
                            "step_span": step_span,
                        }
                        current["tools_used"].add(block.get("name", "unknown_tool"))
        elif role == "toolResult" and current is not None:
            tc_id = msg.get("toolCallId") or ""
            pending = current["pending_tools"].pop(tc_id, None)
            if pending is None:
                continue
            tool_span = _build_tool_span(session_id, current["trace_id"], pending, msg, ts_ns)
            spans.append(tool_span)
            step_span = pending.get("step_span")
            if isinstance(step_span, dict):
                step_span["duration"] = _closed_duration_ns(step_span["start_ns"], ts_ns)
            current["end_ns"] = max(current["end_ns"], ts_ns)

        previous_ts_ns = ts_ns

    if current is not None:
        _finalize_turn(current)

    return spans
