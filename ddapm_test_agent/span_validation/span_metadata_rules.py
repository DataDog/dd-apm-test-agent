import logging

log = logging.getLogger(__name__)

class SpanMetadataRules:
    def __init__(self, name, type=None, required_tags=[], optional_tags=[], matches={}, additional_type_assertions=None):
        self.name = name # can be name or list
        self.type = type # can be string or None
        self._required_tags = required_tags
        self._optional_tags = optional_tags
        self._tag_comparisons = {}
        for k, v in matches.items():
            self._tag_comparisons[k] = v
        self._additional_type_assertions = additional_type_assertions