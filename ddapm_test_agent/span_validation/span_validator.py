import logging

log = logging.getLogger(__name__)

from .rules import type_metadata_rules_map

class SpanMetadataValidator:
    _tags = {}

    def __init__(self, span, metadata_rules, validate_base_tags=True):
        log.info("asserting on span within the validator!")

        self._span = span
        
        # Extract tags to dictionary acting as validation queue.
        def extract_tags(span, extracted_tags):
            logging.info(span)
            for k, v in span.items():
                if isinstance(v, dict):
                    extracted_tags = extract_tags(span[k], extracted_tags)
                else:
                    extracted_tags[k] = v
            return extracted_tags

        self._tags = extract_tags(span, {})

        # Validate name
        self.spanNameValidator(span, metadata_rules)

        # Validate integration specific tags
        self.spanMatchingTagValidator(metadata_rules)
        self.spanRequiredTagValidator(metadata_rules)
        self.spanOptionalTagValidator(metadata_rules)

        # Validate general and internal tags
        self.spanRequiredTagValidator(type_metadata_rules_map["general"])
        self.spanOptionalTagValidator(type_metadata_rules_map["general"])
        self.spanOptionalTagValidator(type_metadata_rules_map["internal"])

        # Validate span type
        if metadata_rules.type is not None:
            assert span["type"] == metadata_rules.type
            if metadata_rules.type in type_metadata_rules_map.keys():
                type_metadata_rules = type_metadata_rules_map[metadata_rules.type]
                self.spanRequiredTagValidator(type_metadata_rules)
                self.spanOptionalTagValidator(type_metadata_rules)
            del self._tags["type"]

        # Validate span error
        if "error" in span.keys():
            error_metadata_rules = type_metadata_rules_map["error"]
            self.spanRequiredTagValidator(error_metadata_rules)
            self.spanOptionalTagValidator(error_metadata_rules)
            del self._tags["error"]

        # Validation was successful if no tags are left to validate.
        self.success = self._tags == {}
        log.info(self._tags)
        log.info(f"--------- Returning that {metadata_rules.name} span validation returned: {self.success}. ---------------")
        

    def spanNameValidator(self, span, metadata_rules):
        log.info(f"Asserting on span name: {metadata_rules.name}")
        if isinstance(metadata_rules.name, str):
            assert span["name"] == metadata_rules.name
        elif isinstance(metadata_rules.name, list):
            assert span["name"] in metadata_rules.name
        del self._tags["name"]

    def spanMatchingTagValidator(self, metadata_rules):
        metadata_rules_matching_tags = metadata_rules._tag_comparisons.items()
        log.info(f"------------------- Asserting on span {metadata_rules.name} tags matching ---------------------")
        for expected_k, expected_v in metadata_rules_matching_tags:
            assert expected_k in self._tags.keys()
            assert expected_v == self._tags[expected_k]
            log.info(f"             Validated presenence of {expected_k} tag with value {expected_v}")
            del self._tags[expected_k]

    def spanRequiredTagValidator(self, metadata_rules):
        required_tags = metadata_rules._required_tags
        log.info(f"------------------- Asserting on span {metadata_rules.name} required tags ---------------------")
        for tag_name in required_tags:
            assert tag_name in self._tags.keys()
            log.info(f"             Required Tag {tag_name} validated.")
            del self._tags[tag_name]

    def spanOptionalTagValidator(self, metadata_rules):
        optional_tags = metadata_rules._optional_tags
        log.info(f"------------------- Asserting on span {metadata_rules.name} optional tags ---------------------")
        for tag_name in optional_tags:
            if tag_name in self._tags.keys():
                log.info(f"             Optional Tag {tag_name} validated.")
                del self._tags[tag_name]
