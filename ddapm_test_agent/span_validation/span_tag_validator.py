import logging

from ddapm_test_agent.span_validation.console_output import OutputPrinter

from .tag_rules.general_span_tag_rules import general_span_tag_rules_map


log = logging.getLogger(__name__)

type_missing_assertion = (
    lambda span, tag_rules: f"TYPE-ASSERTION-ERROR: Expected span: {span['name']} have 'type' tag with value: {tag_rules.type}"
)
type_mismatch_assertion = (
    lambda span, tag_rules: f"TYPE-ASSERTION-ERROR: Expected span: {span['name']} actual 'type' tag: {span['type']} to equal expected 'type' tag: {tag_rules.type}"
)
tag_missing_assertion = (
    lambda span, tag_rules_name, e_k, tags: f"{tag_rules_name}-ASSERTION-ERROR: Expected span: {span['name']} to have tag: '{e_k}' within meta: {tags}"
)
tag_mismatch_assertion = (
    lambda span, tag_rules_name, e_k, e_v, tags: f"{tag_rules_name}-ASSERTION-ERROR: Expected span: {span['name']} with tag: '{e_k}' with value: {tags[e_k]} to equal expected value: {e_v}"
)

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


class SpanTagValidator:
    def __init__(
        self,
        type_span_rules=None,
        integration_base_span_rules=None,
        integration_root_span_rules=None,
        first_in_chunk_span_rules=None,
    ):
        self.console_out = OutputPrinter(log)
        self.type_span_rules_exist = False
        self.keep_component_tag_for_later_match = False
        self.span_tag_rules_list = [GENERAL_SPAN_RULES, INTERNAL_SPAN_RULES]

        if first_in_chunk_span_rules:
            self.span_tag_rules_list.append(first_in_chunk_span_rules)

        if type_span_rules:
            self.type_span_rules_exist = True
            self.span_tag_rules_list.append(type_span_rules)

        if integration_base_span_rules:
            self.keep_component_tag_for_later_match = True
            self.span_tag_rules_list.append(integration_base_span_rules)

        if integration_root_span_rules:
            self.span_tag_rules_list.append(integration_root_span_rules)

    def validate(self, span):
        self._span = span
        main_tag_rules = self.span_tag_rules_list[-1]

        if span["error"]:
            self.span_tag_rules_list.insert(1, ERROR_SPAN_RULES)

        self.console_out.print_intro_message(span, main_tag_rules)

        self._tags = self.extract_tags(span, {})

        for tag_rules in self.span_tag_rules_list:
            try:
                tag_rules.validate(self)

            except AssertionError as e:
                self.console_out.print_result(span, tag_rules, self._tags)
                raise AssertionError(e)

        self.console_out.print_result(span, main_tag_rules, self._tags)

    def span_matching_tag_validator(self, tag_rules):
        if tag_rules._tag_comparisons:
            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} tags matching ---------------------------------"
            )
            for e_k, e_v in tag_rules._tag_comparisons.items():
                assert e_k in self._tags.keys(), tag_missing_assertion(
                    self._span, tag_rules.name.upper(), e_k, self._tags.keys()
                )
                assert e_v == self._tags[e_k], tag_mismatch_assertion(
                    self._span, tag_rules.name.upper(), e_k, e_v, self._tags
                )
                del self._tags[e_k]
                log.info(f"                       Validated presence of {e_k} tag with value {e_v}")

        else:
            log.info(
                f"     ------------------ No tag comparisons to assert on for tag rules {tag_rules.name} -------------------"
            )
            return

    def span_required_tag_validator(self, tag_rules):
        if tag_rules._required_tags:
            required_tags = tag_rules._required_tags

            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} required tags ---------------------------------"
            )
            for tag_name in required_tags:
                assert tag_name in self._tags.keys(), tag_missing_assertion(
                    self._span, tag_rules.name.upper(), tag_name, self._tags.keys()
                )
                log.info(f"                             Required Tag {tag_name} validated.")

                # We can delete tag if not component or if it is component, only if we no dont need for later assertions
                if tag_name != "component" or not self.keep_component_tag_for_later_match:
                    del self._tags[tag_name]
        else:
            log.info(
                f"     ------------------ No required tags to assert on for tag rules {tag_rules.name} ---------------------"
            )
            return

    def span_optional_tag_validator(self, tag_rules):
        if tag_rules._optional_tags:
            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} optional tags ---------------------------------"
            )
            for tag_name in tag_rules._optional_tags:
                if tag_name in self._tags.keys():
                    log.info(f"                             Optional Tag {tag_name} validated.")
                    del self._tags[tag_name]
        else:
            log.info(
                f"     ------------------ No optional tags to assert on for tag rules {tag_rules.name} ---------------------"
            )
            return

    def extract_tags(self, span, extracted_tags):
        for k, v in span.items():
            if isinstance(v, dict):
                extracted_tags = self.extract_tags(span[k], extracted_tags)
            elif k in IGNORED_TAGS:
                continue
            elif (
                k == "type" and self.type_span_rules_exist
            ):  # if key == type and we have type rules, delete type since it is already verified
                continue
            else:
                extracted_tags[k] = v
        return extracted_tags
