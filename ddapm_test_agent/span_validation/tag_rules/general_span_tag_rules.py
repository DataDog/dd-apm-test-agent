from typing import Dict

from ..span_tag_rules import SpanTagRules


general_tag_rules = SpanTagRules(
    name="General",
    required_tags=["component", "error"],
    optional_tags=["language", "error.msg", "error.type", "error.stack"],
)

first_span_in_chunk_tag_rules = SpanTagRules(
    name="1st Span in Chunk",
    required_tags=["runtime-id", "process_id"],  # add language later
)

internal_tag_rules = SpanTagRules(
    name="Internal",
    optional_tags=[
        "_dd.p.dm",
        "_dd.agent_psr",
        "_dd.measured",
        "_dd.top_level",
        "_sampling_priority_v1",
        "_dd.tracer_kr",
    ],
)

error_tag_rules = SpanTagRules(
    name="Error",
    optional_tags=["error.message", "error.type", "error.stack"],
)

general_span_tag_rules_map: Dict[str, SpanTagRules] = dict(
    {
        "error": error_tag_rules,
        "general": general_tag_rules,
        "internal": internal_tag_rules,
        "chunk": first_span_in_chunk_tag_rules,
    }
)
