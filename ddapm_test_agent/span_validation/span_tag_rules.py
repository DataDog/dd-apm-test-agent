import logging


log = logging.getLogger(__name__)


class SpanTagRules:
    def __init__(
        self,
        name=None,
        span_type=None,
        required_tags=None,
        optional_tags=None,
        matches=None,
        additional_type_assertions=None,
        base_integration_tag_rules=None,
        first_span_in_chunk_tags=None,
    ):
        self.name = name  # can be name or list
        self.type = span_type  # can be string or None
        self._required_tags = required_tags
        self._optional_tags = optional_tags
        self._tag_comparisons = matches
        self._additional_type_assertions = additional_type_assertions
        self._base_integration_tag_rules = base_integration_tag_rules
        self._first_span_in_chunk_tags = first_span_in_chunk_tags
