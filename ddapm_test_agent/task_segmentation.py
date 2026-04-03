"""Task segmentation for LLM Observability sessions.

Takes session spans from the test agent, compresses them into a transcript,
and calls Claude Haiku to identify task boundaries and outcomes.

Adapted from mrlee-plugins trajectory/src/analysis/task-segmentation/segment.py.
"""

import json
import logging
import os
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import aiohttp
from aiohttp import web
from aiohttp.web import Request

from .llmobs_event_platform import LLMObsEventPlatformAPI
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)

ANTHROPIC_API_BASE = "https://api.anthropic.com"
MODEL = "claude-haiku-4-5-20251001"
MAX_PROMPT_CHARS = 12000

# ---------------------------------------------------------------------------
# Span compression (mirrors segment.py from mrlee-plugins)
# ---------------------------------------------------------------------------


def _get_input_preview(meta: Dict[str, Any]) -> str:
    """Extract a short input preview from span meta."""
    inp = meta.get("input", {})
    if not inp:
        return ""
    messages = inp.get("messages", [])
    if messages:
        last = messages[-1] if isinstance(messages[-1], dict) else {}
        return str(last.get("content", ""))[:300]
    return str(inp.get("value", ""))[:300]


def _get_output_preview(meta: Dict[str, Any]) -> str:
    """Extract a short output preview from span meta."""
    out = meta.get("output", {})
    if not out:
        return ""
    messages = out.get("messages", [])
    if messages:
        last = messages[-1] if isinstance(messages[-1], dict) else {}
        return str(last.get("content", ""))[:200]
    return str(out.get("value", ""))[:200]


def compress_span_to_turn(span: Dict[str, Any], turn_idx: int) -> Dict[str, Any]:
    """Compress a root-level span into a turn-like structure for the LLM."""
    meta = span.get("meta", {})
    name = span.get("name", "")
    status = span.get("status", "ok")
    duration_ns = span.get("duration", 0)
    span_kind = meta.get("span", {}).get("kind", "llm")

    turn: Dict[str, Any] = {"turn": turn_idx}

    # User input
    user_input = _get_input_preview(meta)
    if user_input:
        turn["user"] = user_input

    # Agent response
    output = _get_output_preview(meta)
    if output:
        turn["response"] = output

    # Metadata
    turn["name"] = name
    turn["kind"] = span_kind
    turn["status"] = status
    turn["duration_ms"] = round(duration_ns / 1_000_000, 1) if duration_ns else 0

    return turn


def compress_session_spans(spans: List[Dict[str, Any]], session_id: str) -> Dict[str, Any]:
    """Compress session spans into an LLM-friendly transcript."""
    # Sort by start time ascending
    sorted_spans = sorted(spans, key=lambda s: s.get("start_ns", 0))

    # Only include root spans (agent/workflow level, not child LLM calls)
    root_spans = [s for s in sorted_spans if not s.get("parent_id") or s.get("parent_id") in ("0", "", "undefined")]

    # If no root spans, fall back to all spans
    if not root_spans:
        root_spans = sorted_spans

    turns = []
    for i, span in enumerate(root_spans):
        turns.append(compress_span_to_turn(span, i))

    return {
        "session_id": session_id,
        "total_turns": len(turns),
        "turns": turns,
    }


# ---------------------------------------------------------------------------
# Segmentation prompt (adapted from segment.py)
# ---------------------------------------------------------------------------

SEGMENTATION_PROMPT = """\
You are a task segmentation system. Given a compressed agent session transcript,
identify the distinct tasks the user worked on and their outcomes.

## What is a task?

A **task** is a coherent unit of user intent. It has a goal (what the user wants),
boundaries (which turns), and an outcome (did it work?).

## Rules

1. **Don't over-segment.** A multi-turn conversation about one topic is ONE task.
   Only create a new task when the user's goal clearly changes.

2. **Don't under-segment.** Sessions with 6+ turns almost always have 3+ tasks.

3. **Turn boundaries must not overlap and must not have gaps.** Every turn should
   belong to exactly one task.

4. **Short sessions (1-2 turns) are usually 1 task.**

## Outcome labels

- **success**: Goal fully achieved.
- **mostly**: Goal substantially achieved with minor gaps (~80%+ done).
- **partial**: Some progress but significant work remains.
- **failure**: Attempted but did not achieve goal.
- **interrupted**: Task did not complete because session ended or user pivoted.

## Session Transcript

```json
{transcript}
```
"""

TASK_SCHEMA = {
    "type": "object",
    "properties": {
        "tasks": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "integer",
                        "description": "Sequential task number starting at 1",
                    },
                    "goal": {
                        "type": "string",
                        "description": "Short description of what the user wanted accomplished",
                    },
                    "start_turn": {
                        "type": "integer",
                        "description": "First turn index (0-based)",
                    },
                    "end_turn": {
                        "type": "integer",
                        "description": "Last turn index (0-based)",
                    },
                    "outcome": {
                        "type": "string",
                        "enum": ["success", "mostly", "partial", "failure", "interrupted"],
                    },
                    "outcome_score": {
                        "type": "number",
                        "description": "0.0 to 1.0 quality score",
                    },
                },
                "required": ["task_id", "goal", "start_turn", "end_turn", "outcome", "outcome_score"],
            },
        }
    },
    "required": ["tasks"],
}


def build_prompt(session_data: Dict[str, Any]) -> str:
    """Build the segmentation prompt from compressed session data."""
    transcript_json = json.dumps(session_data, indent=2)

    # Truncate if too long
    if len(transcript_json) > MAX_PROMPT_CHARS:
        for turn in session_data.get("turns", []):
            if "response" in turn:
                turn["response"] = turn["response"][:100]
            if "user" in turn:
                turn["user"] = turn["user"][:150]
        transcript_json = json.dumps(session_data, indent=2)

    return SEGMENTATION_PROMPT.replace("{transcript}", transcript_json)


# ---------------------------------------------------------------------------
# Anthropic API call
# ---------------------------------------------------------------------------


async def call_anthropic(prompt: str, api_key: str) -> Tuple[Dict[str, Any], float]:
    """Call the Anthropic API with structured JSON output.

    Returns (result_dict, cost_usd).
    """
    headers = {
        "x-api-key": api_key,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    body = {
        "model": MODEL,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
        "tools": [
            {
                "name": "output_tasks",
                "description": "Output the task segmentation result",
                "input_schema": TASK_SCHEMA,
            }
        ],
        "tool_choice": {"type": "tool", "name": "output_tasks"},
    }

    t0 = time.time()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{ANTHROPIC_API_BASE}/v1/messages",
            headers=headers,
            json=body,
        ) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                log.error(f"Anthropic API error {resp.status}: {error_text}")
                return {"tasks": []}, 0.0

            data = await resp.json()

    duration_ms = int((time.time() - t0) * 1000)
    log.info(f"[task_segmentation] Anthropic call took {duration_ms}ms")

    # Extract tool use result
    for block in data.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "output_tasks":
            result = block.get("input", {})
            # Estimate cost from usage
            usage = data.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)
            output_tokens = usage.get("output_tokens", 0)
            # Haiku pricing: $0.80/MTok input, $4/MTok output
            cost = (input_tokens * 0.80 + output_tokens * 4.0) / 1_000_000
            return result, cost

    return {"tasks": []}, 0.0


# ---------------------------------------------------------------------------
# API handler
# ---------------------------------------------------------------------------


class TaskSegmentationAPI:
    """Handler for task segmentation endpoints."""

    def __init__(self, llmobs_api: LLMObsEventPlatformAPI) -> None:
        self.llmobs_api = llmobs_api
        self._cache: Dict[str, Dict[str, Any]] = {}  # session_id -> cached result

    async def handle_session_tasks(self, request: Request) -> web.Response:
        """Handle GET /api/ui/llm-obs/v1/session/{session_id}/tasks endpoint."""
        try:
            session_id = request.match_info.get("session_id", "")
            if not session_id:
                return web.json_response({"error": "session_id required"}, status=400)

            # Check for force refresh
            force = request.query.get("force", "false").lower() == "true"

            # Get all spans and filter by session_id
            all_spans = self.llmobs_api.get_llmobs_spans()
            session_spans = [s for s in all_spans if s.get("session_id") == session_id]

            if not session_spans:
                return web.json_response({"tasks": [], "session_id": session_id, "span_count": 0})

            # Check cache (invalidate if span count changed)
            cache_key = session_id
            cached = self._cache.get(cache_key)
            if cached and not force and cached.get("span_count") == len(session_spans):
                return web.json_response(cached)

            # Get API key from env or app config
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return web.json_response(
                    {"error": "ANTHROPIC_API_KEY not set. Set it to enable task segmentation."},
                    status=503,
                )

            # Compress spans into transcript
            session_data = compress_session_spans(session_spans, session_id)

            # Build prompt and call LLM
            prompt = build_prompt(session_data)
            result, cost = await call_anthropic(prompt, api_key)

            response_data = {
                "tasks": result.get("tasks", []),
                "session_id": session_id,
                "span_count": len(session_spans),
                "total_turns": session_data["total_turns"],
                "cost_usd": cost,
            }

            # Cache result
            self._cache[cache_key] = response_data

            return web.json_response(response_data)

        except Exception as e:
            log.error(f"Error handling session tasks: {e}")
            return web.json_response({"error": str(e)}, status=500)

    def get_routes(self) -> List[web.RouteDef]:
        """Return routes for this API."""
        return [
            web.route(
                "*",
                "/api/ui/llm-obs/v1/session/{session_id}/tasks",
                with_cors(self.handle_session_tasks),
            ),
        ]
