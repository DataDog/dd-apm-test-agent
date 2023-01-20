import logging

from ddapm_test_agent.span_validation import console_output

from .tag_rules.general_span_tag_rules import general_span_tag_rules_map
from .tag_rules.type_span_tag_rules import span_type_tag_rules_map


log = logging.getLogger(__name__)

# Ignore the below tags
IGNORED_TAGS = set(
    [
        "span_id",
        "trace_id",
        "duration",
        "start",
        "resource",
        "parent_id",
        "env",
        "version",
        "service",
        "name",
    ]
)

GENERAL_SPAN_RULES = general_span_tag_rules_map["general"]
ERROR_SPAN_RULES = general_span_tag_rules_map["error"]
INTERNAL_SPAN_RULES = general_span_tag_rules_map["internal"]

SPAN_TYPES = set(
    [
        "cache",
        "cassandra",
        "elasticsearch",
        "grpc",
        "graphql",
        "http",
        "mongodb",
        "redis",
        "sql",
        "template",
        "test",
        "web",
        "worker",
    ]
)


class SpanTagValidator:
    def __init__(
        self,
        span,
        type_span_rules=None,
        integration_base_span_rules=None,
        integration_root_span_rules=None,
        first_in_chunk_span_rules=None,
    ):
        self.console_out = console_output.OutputPrinter(log)
        self.span = span

        self.integration_base_span_rules = integration_base_span_rules

        # Set some basic attributes
        self.validate_all_tags = False
        self.main_tag_rules = GENERAL_SPAN_RULES
        self.failed_tag_rules = None
        self.span_tag_rules_list = [GENERAL_SPAN_RULES, INTERNAL_SPAN_RULES]

        if first_in_chunk_span_rules:
            self.span_tag_rules_list.append(first_in_chunk_span_rules)

        span_error = self.span.get("error", None)
        if span_error and span_error == "1":
            self.span_tag_rules_list.insert(1, ERROR_SPAN_RULES)

        if type_span_rules:
            self.main_tag_rules = type_span_rules
            self.span_tag_rules_list.append(type_span_rules)

        if integration_base_span_rules:
            self.main_tag_rules = integration_base_span_rules
            self.span_tag_rules_list.append(integration_base_span_rules)

        if integration_root_span_rules:
            self.main_tag_rules = integration_root_span_rules
            self.span_tag_rules_list.append(integration_root_span_rules)

        # Validate all tags if we have all rules.
        if integration_base_span_rules and integration_root_span_rules:

            span_type = self.span.get("type", None)
            # If a span doesn't have a type, validate all. If span has a type, check the type if valid and if yes, check we have rules for type.
            # If we type rules, validate all span tags, if we do not, do not validate all tags.
            if span_type:
                if span_type == "" or (span_type in SPAN_TYPES and span_type in span_type_tag_rules_map.keys()):
                    self.validate_all_tags = True

        self.tag_rules = self.span_tag_rules_list[0]
        self._tags = self.extract_tags({})

    def validate(self):
        self.console_out.print_intro_message(self)

        for tag_rules in self.span_tag_rules_list:
            self.tag_rules = tag_rules
            self.failed_tag_rules = None
            try:
                tag_rules.validate(self)
            except AssertionError as e:
                self.failed_tag_rules = tag_rules
                self.console_out.print_result(self)
                raise AssertionError(e)

        self.tag_rules = self.main_tag_rules
        self.console_out.print_result(self)

    def span_matching_tag_validator(self):
        tag_rules = self.tag_rules
        if tag_rules._tag_comparisons:
            self.console_out.print_asserting_on(self, matching_tags=True)
            for e_k, e_v in tag_rules._tag_comparisons.items():
                assert e_k in self._tags.keys(), console_output.tag_missing_assertion(
                    self.span, tag_rules.name.upper(), e_k, self._tags.keys()
                )
                assert e_v == self._tags[e_k], console_output.tag_mismatch_assertion(
                    self.span, tag_rules.name.upper(), e_k, e_v, self._tags
                )
                del self._tags[e_k]
                log.info(f"                       Validated presence of {e_k} tag with value {e_v}")

        else:
            self.console_out.print_asserting_on(self, matching_tags=True, error=True)
            return

    def span_required_tag_validator(self):
        tag_rules = self.tag_rules
        if tag_rules._required_tags:
            required_tags = tag_rules._required_tags
            self.console_out.print_asserting_on(self, required_tags=True)
            for tag_name in required_tags:
                assert tag_name in self._tags.keys(), console_output.tag_missing_assertion(
                    self.span, tag_rules.name.upper(), tag_name, self._tags.keys()
                )
                log.info(f"                        Required Tag {tag_name} validated.")

                # We can delete tag unless the tag is component and we need it to assert with the integration name later
                if tag_name == "component" and tag_rules.name.lower() == "general" and self.integration_base_span_rules:
                    continue
                else:
                    del self._tags[tag_name]

        else:
            self.console_out.print_asserting_on(self, required_tags=True, error=True)
            return

    def span_optional_tag_validator(self):
        tag_rules = self.tag_rules
        if tag_rules._optional_tags:
            self.console_out.print_asserting_on(self, optional_tags=True)
            for tag_name in tag_rules._optional_tags:
                if tag_name in self._tags.keys():
                    log.info(f"                        Optional Tag {tag_name} validated.")
                    del self._tags[tag_name]
        else:
            self.console_out.print_asserting_on(self, optional_tags=True, error=True)
            return

    def extract_tags(self, extracted_tags):
        for k, v in self.span.items():
            if isinstance(v, dict):
                extracted_tags = self.extract_tags(extracted_tags)
            elif k in IGNORED_TAGS:
                continue
            else:
                extracted_tags[k] = v
        return extracted_tags
