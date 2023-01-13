import logging
from typing import Dict

from .tag_rules.general_span_tag_rules import general_span_tag_rules_map
from .tag_rules.span_type_tag_rules import span_type_tag_rules_map


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


class SpanTagValidator:
    _tags: Dict[str, str] = {}

    def __init__(
        self,
        span,
        tag_rules,
        validate_base_tags=True,
        validate_internal_tags=True,
        final_validation=True,  # check for remaining tags and return true if no tags left to verify remain
        tags=None,
        validate_first_span_in_chunk_tags=False,
    ):
        log.info("\n")
        log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        log.info(
            f" -----------  Asserting on span {span['name']} with rules {tag_rules.name} within the validator!  --------------------"
        )
        log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        log.info("\n")

        self._span = span

        # Ignore the below tags
        ignored_tags = set(
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

        # Extract tags to dictionary acting as validation queue.
        def extract_tags(span, extracted_tags):
            for k, v in span.items():
                if isinstance(v, dict):
                    extracted_tags = extract_tags(span[k], extracted_tags)
                elif k in ignored_tags:
                    continue
                else:
                    extracted_tags[k] = v
            return extracted_tags

        self._tags = tags
        if not self._tags:
            self._tags = extract_tags(span, {})

        # Validate exact tag matches
        if tag_rules._tag_comparisons:
            self.spanMatchingTagValidator(tag_rules)

        # Validate required tags exist
        if tag_rules._required_tags:
            self.spanRequiredTagValidator(tag_rules)

        # Validate optional tags existing
        if tag_rules._optional_tags:
            self.spanOptionalTagValidator(tag_rules)

        # Validate internal tags
        if validate_internal_tags:
            self.spanOptionalTagValidator(general_span_tag_rules_map["internal"])

        # Validate general and internal tags
        if validate_base_tags:
            self.spanRequiredTagValidator(general_span_tag_rules_map["general"])
            self.spanOptionalTagValidator(general_span_tag_rules_map["general"])
            # Validate first span in chunk General tags
            if validate_first_span_in_chunk_tags:
                self.spanRequiredTagValidator(
                    tags_list=general_span_tag_rules_map[
                        "general"
                    ]._first_span_in_chunk_tags
                )

        # Validate first span in chunk tags
        if validate_first_span_in_chunk_tags and tag_rules._first_span_in_chunk_tags:
            self.spanRequiredTagValidator(tags_list=tag_rules._first_span_in_chunk_tags)

            # Validate span error
            if "error" in span.keys() and span["error"] == 1:
                error_tag_rules = general_span_tag_rules_map["error"]
                self.spanOptionalTagValidator(error_tag_rules)
                self._tags.pop("error", None)

        # Validate span type if we have an assertion for it
        if tag_rules.type:
            assert "type" in self._tags.keys(), type_missing_assertion(span, tag_rules)
            assert span["type"] == tag_rules.type, type_mismatch_assertion(
                span, tag_rules
            )
            if tag_rules.type in span_type_tag_rules_map.keys():
                type_tag_rules = span_type_tag_rules_map[tag_rules.type]
                self.spanRequiredTagValidator(type_tag_rules)
                self.spanOptionalTagValidator(type_tag_rules)
            self._tags.pop("type", None)

        # Else we are validating general tags. In that case, only validate type tags if a type field is present
        elif (
            "type" in self._tags.keys()
            and span["type"] in span_type_tag_rules_map.keys()
        ):
            type_tag_rules = span_type_tag_rules_map[span["type"]]
            self.spanRequiredTagValidator(type_tag_rules)
            self.spanOptionalTagValidator(type_tag_rules)
            self._tags.pop("type", None)

        # Validate base integration tags if the rules exist, ie: validate redis base span tags
        if tag_rules._base_integration_tag_rules:
            self._tags = SpanTagValidator(
                span,
                tag_rules._base_integration_tag_rules,
                validate_base_tags=False,
                validate_internal_tags=False,
                final_validation=False,
                tags=self._tags,
                validate_first_span_in_chunk_tags=validate_first_span_in_chunk_tags,
            )._tags

        if final_validation:
            # Validation was successful if no tags are left to validate.
            # self.success = self._tags == {}
            self.success = len(self._tags.keys()) == 1
            if not self.success:
                log.info("\n")
                log.info(
                    f'     ************** Unverified span tags below for span {span["name"]} and rules {tag_rules.name} *************** '
                )
                for tag, value in self._tags.items():
                    if tag != "component":
                        log.info(
                            " " * 5
                            + "*" * 14
                            + " " * 15
                            + f"{tag} : {value}"
                            + " " * 15
                            + "*" * 14
                            + " " * 5
                        )
            log.info("\n")
            log.info(
                "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            )
            log.info(
                f"----------------------- Returning that {tag_rules.name} span validation returned: {self.success}. --------------------"
            )
            log.info(
                "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            )

    def spanMatchingTagValidator(self, tag_rules):
        if tag_rules._tag_comparisons:
            tag_rules_name = tag_rules.name.upper()
            tag_rules_matching_tags = tag_rules._tag_comparisons.items()
            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} tags matching ---------------------"
            )
            for expected_k, expected_v in tag_rules_matching_tags:
                assert expected_k in self._tags.keys(), tag_missing_assertion(
                    self._span, tag_rules_name, expected_k, self._tags.keys()
                )
                assert expected_v == self._tags[expected_k], tag_mismatch_assertion(
                    self._span, tag_rules_name, expected_k, expected_v, self._tags
                )
                log.info(
                    f"                       Validated presence of {expected_k} tag with value {expected_v}"
                )
        else:
            log.info(
                f"     ------------------ No tag comparisons to assert on for tag rules {tag_rules.name} ---------------------"
            )
            return

    def spanRequiredTagValidator(self, tag_rules=None, tags_list=None):
        tag_rules_name = None
        if not tag_rules and tags_list:
            required_tags = tags_list
            log.info(
                "     ------------------ Asserting on first span in chunk required tags ---------------------"
            )
        else:
            tag_rules_name = tag_rules.name.upper()
            if tag_rules._required_tags:
                required_tags = tag_rules._required_tags
            else:
                log.info(
                    f"     ------------------ No required tags to assert on for tag rules {tag_rules.name} ---------------------"
                )
                return
            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} required tags ---------------------"
            )
        for tag_name in required_tags:
            if not tag_rules_name:
                tag_rules_name = tag_name
            assert tag_name in self._tags.keys(), tag_missing_assertion(
                self._span, tag_rules_name, tag_name, self._tags.keys()
            )
            log.info(f"                             Required Tag {tag_name} validated.")
            if tag_name != "component":
                self._tags.pop(tag_name, None)

    def spanOptionalTagValidator(self, tag_rules):
        if tag_rules._optional_tags:
            optional_tags = tag_rules._optional_tags
            log.info(
                f"     ------------------ Asserting on span {tag_rules.name} optional tags ---------------------"
            )
            for tag_name in optional_tags:
                if tag_name in self._tags.keys():
                    log.info(
                        f"                             Optional Tag {tag_name} validated."
                    )
                    del self._tags[tag_name]
        else:
            log.info(
                f"     ------------------ No optional tags to assert on for tag rules {tag_rules.name} ---------------------"
            )
            return
