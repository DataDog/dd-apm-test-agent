class SpanTagRules:
    def __init__(
        self,
        name=None,
        span_type=None,
        required_tags=None,
        optional_tags=None,
        matches=None,
    ):
        self.name = name  # can be name or list
        self.span_type = span_type
        self._required_tags = required_tags
        self._optional_tags = optional_tags
        self._tag_comparisons = matches

    def validate(self, span_validator):
        span_validator.span_matching_tag_validator(self)
        span_validator.span_required_tag_validator(self)
        span_validator.span_optional_tag_validator(self)
