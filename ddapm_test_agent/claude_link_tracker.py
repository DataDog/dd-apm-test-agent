"""Span link tracking for connecting LLM and tool spans in Claude Code traces.

Follows the same linking pattern as dd-trace-py's LinkTracker:
- LLM.output -> Tool.input (when LLM generates tool_use, link to the tool span)
- Tool.output -> LLM.input (when tool_result is sent to next LLM call)
"""

import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

log = logging.getLogger(__name__)


class SpanLink:
    """A directional link between two spans in the agentic graph."""

    def __init__(self, span_id: str, trace_id: str, from_io: str, to_io: str) -> None:
        self.span_id = span_id
        self.trace_id = trace_id
        self.from_io = from_io
        self.to_io = to_io

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "attributes": {"from": self.from_io, "to": self.to_io},
        }


class TrackedToolCall:
    """Tracks a tool call between LLM response and tool execution for linking."""

    def __init__(
        self,
        tool_use_id: str,
        tool_name: str,
        arguments: str,
        llm_span_id: str,
        llm_trace_id: str,
    ) -> None:
        self.tool_use_id = tool_use_id
        self.tool_name = tool_name
        self.arguments = arguments
        self.llm_span_id = llm_span_id
        self.llm_trace_id = llm_trace_id
        self.tool_span_id: Optional[str] = None
        self.tool_trace_id: Optional[str] = None
        self.tool_parent_id: Optional[str] = None


class ClaudeLinkTracker:
    """Tracks tool_use_id correlations between LLM and tool spans.

    The linking flow:
    1. Proxy sees LLM response with tool_use blocks -> on_llm_tool_choice()
       Stores {tool_use_id -> llm_span context}

    2. Hook fires PostToolUse with tool_use_id -> on_tool_call()
       Creates LLM.output -> Tool.input link on the tool span
       Stores {tool_use_id -> tool_span context}

    3. Proxy sees next LLM request with tool_result blocks -> on_tool_call_output_used()
       Creates Tool.output -> LLM.input link on the LLM span
       Consumes the tracked tool call
    """

    def __init__(self) -> None:
        self._tool_calls: Dict[str, TrackedToolCall] = {}

    def on_llm_tool_choice(
        self,
        tool_use_id: str,
        tool_name: str,
        arguments: str,
        llm_span_id: str,
        llm_trace_id: str,
    ) -> None:
        """Called when an LLM response contains a tool_use block."""
        self._tool_calls[tool_use_id] = TrackedToolCall(
            tool_use_id=tool_use_id,
            tool_name=tool_name,
            arguments=arguments,
            llm_span_id=llm_span_id,
            llm_trace_id=llm_trace_id,
        )
        log.debug("Tracking tool choice: %s (%s)", tool_use_id, tool_name)

    def on_tool_call(
        self, tool_use_id: str, tool_span_id: str, tool_trace_id: str, tool_parent_id: str
    ) -> List[SpanLink]:
        """Called when a tool span finishes (from PostToolUse hook).

        Returns span links to add to the tool span (LLM.output -> Tool.input).
        Also stores the tool span's parent_id so the proxy can use it to determine
        the correct parent for subsequent LLM spans (handles concurrent subagents).
        """
        tc = self._tool_calls.get(tool_use_id)
        if not tc:
            return []

        tc.tool_span_id = tool_span_id
        tc.tool_trace_id = tool_trace_id
        tc.tool_parent_id = tool_parent_id

        log.debug("Linking LLM(%s).output -> Tool(%s).input via %s", tc.llm_span_id, tool_span_id, tool_use_id)
        return [
            SpanLink(
                span_id=tc.llm_span_id,
                trace_id=tc.llm_trace_id,
                from_io="output",
                to_io="input",
            )
        ]

    def on_tool_call_output_used(self, tool_use_id: str) -> Tuple[List[SpanLink], Optional[str]]:
        """Called when an LLM request contains a tool_result block.

        Returns (span_links, parent_id_hint):
        - span_links: Tool.output -> LLM.input links for the LLM span
        - parent_id_hint: the parent of the tool span that produced this result,
          allowing the proxy to assign the correct parent even with concurrent subagents

        Consumes the tracked tool call.
        """
        tc = self._tool_calls.pop(tool_use_id, None)
        if not tc or not tc.tool_span_id:
            return [], None

        log.debug("Linking Tool(%s).output -> LLM.input via %s (parent hint: %s)",
                  tc.tool_span_id, tool_use_id, tc.tool_parent_id)
        links = [
            SpanLink(
                span_id=tc.tool_span_id,
                trace_id=tc.tool_trace_id,
                from_io="output",
                to_io="input",
            )
        ]
        return links, tc.tool_parent_id
