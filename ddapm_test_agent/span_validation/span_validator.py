import logging


log = logging.getLogger(__name__)

from .rules import type_tag_rules_map


class SpanMetadataValidator:
    _tags = {}

    def __init__(self, span, tag_rules, validate_base_tags=True, tags=None, validate_first_span_in_chunk_tags=False):
        log.info("\n")
        log.info(f" ----------------  Asserting on span {span['name']} with rules {tag_rules.name} within the validator!  --------------------")

        self._span = span

        # Ignore the below tags
        ignored_tags = set(["span_id", "trace_id", "duration", "start", "resource", "parent_id", "env", "version", "service", "name"])

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

        # Validate general and internal tags
        if validate_base_tags:
            self.spanRequiredTagValidator(type_tag_rules_map["general"])
            self.spanOptionalTagValidator(type_tag_rules_map["general"])
            self.spanOptionalTagValidator(type_tag_rules_map["internal"])
            # Validate first span in chunk General tags
            if validate_first_span_in_chunk_tags:
                self.spanRequiredTagValidator(tags_list=type_tag_rules_map["general"]._first_span_in_chunk_tags)

        
        # Validate first span in chunk tags
        if validate_first_span_in_chunk_tags and tag_rules._first_span_in_chunk_tags:
            self.spanRequiredTagValidator(tags_list=tag_rules._first_span_in_chunk_tags)


            # Validate span error
            if "error" in span.keys() and span["error"] == 1:
                error_tag_rules = type_tag_rules_map["error"]
                self.spanOptionalTagValidator(error_tag_rules)
                self._tags.pop('error', None)

        # Validate span type
        if tag_rules.type:
            assert 'type' in span.keys(), f"TYPE-ASSERTION-ERROR: Expected span: {self._span['name']} have 'type' tag with value: {tag_rules.type}"
            assert span["type"] == tag_rules.type, f"TYPE-ASSERTION-ERROR: Expected span: {self._span['name']} actual 'type' tag: {span['type']} to equal expected 'type' tag: {tag_rules.type}"
            if tag_rules.type in type_tag_rules_map.keys():
                type_tag_rules = type_tag_rules_map[tag_rules.type]
                self.spanRequiredTagValidator(type_tag_rules)
                self.spanOptionalTagValidator(type_tag_rules)
            self._tags.pop('type', None)

        # Validate base integration tags if the rules exist, ie: validate redis base span tags
        if tag_rules._base_integration_tag_rules:
            self._tags = SpanMetadataValidator(
                span, 
                tag_rules._base_integration_tag_rules, 
                validate_base_tags=False, 
                tags=self._tags, 
                validate_first_span_in_chunk_tags=validate_first_span_in_chunk_tags
            )._tags

        # Validation was successful if no tags are left to validate.
        # self.success = self._tags == {}
        log.info(f' - - - - - - Unverified span tags below for span {span["name"]} and rules {tag_rules.name} - - - - ')
        log.info(self._tags)
        self.success = True
        log.info(
            f"--------- Returning that {tag_rules.name} span validation returned: {self.success}. ---------------"
        )
        log.info("\n")

    # def spanNameValidator(self, span, tag_rules):
    #     log.info(f"Asserting on span name: {tag_rules.name}")
    #     if isinstance(tag_rules.name, str):
    #         assert span["name"] == tag_rules.name
    #     elif isinstance(tag_rules.name, list):
    #         assert span["name"] in tag_rules.name
    #     self._tags.pop('name', None)

    def spanMatchingTagValidator(self, tag_rules):
        tag_rules_name = tag_rules.name.upper()
        tag_rules_matching_tags = tag_rules._tag_comparisons.items()
        log.info(f"------------------- Asserting on span {tag_rules.name} tags matching ---------------------")
        for expected_k, expected_v in tag_rules_matching_tags:
            assert expected_k in self._tags.keys(), f"{tag_rules_name}-ASSERTION-ERROR: Expected span: {self._span['name']} to have tag: '{expected_k}' within meta: {self._tags.keys()}"
            assert expected_v == self._tags[expected_k], f"ASSERTION-ERROR: Expected span: {self._span['name']} with tag: '{expected_k}' with value: {self._tags[expected_k]} to equal expected value: {expected_v}"
            log.info(f"             Validated presence of {expected_k} tag with value {expected_v}")
            self._tags.pop(expected_k, None)

    def spanRequiredTagValidator(self, tag_rules=[], tags_list=[]):
        tag_rules_name = None
        tag_rules_name = tag_rules_name.upper()
        if not tag_rules:
            required_tags = tags_list
            log.info(f"------------------- Asserting on first span in chunk required tags ---------------------")
        else:
            tag_rules_name = tag_rules.name.upper()
            required_tags = tag_rules._required_tags
            log.info(f"------------------- Asserting on span {tag_rules.name} required tags ---------------------")
        for tag_name in required_tags:
            if not tag_rules_name:
                tag_rules_name = tag_name
            assert tag_name in self._tags.keys(), f"{tag_rules_name}-ASSERTION-ERROR: Expected span {self._span['name']} to have tag '{tag_name}' within meta: {self._tags.keys()}"
            log.info(f"             Required Tag {tag_name} validated.")
            self._tags.pop(tag_name, None)

    def spanOptionalTagValidator(self, tag_rules):
        optional_tags = tag_rules._optional_tags
        log.info(f"------------------- Asserting on span {tag_rules.name} optional tags ---------------------")
        for tag_name in optional_tags:
            if tag_name in self._tags.keys():
                log.info(f"             Optional Tag {tag_name} validated.")
                del self._tags[tag_name]
