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


class OutputPrinter:
    def __init__(self, log):
        self._log = log

    def print_intro_message(self, span_validator):
        span = span_validator.span
        tag_rules = span_validator.tag_rules
        self._log.info("\n")
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info(
            f" -----------  Asserting on span {span['name']} with rules {tag_rules.name} within the validator!  --------------------"
        )
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info("\n")

    def print_result(self, span_validator):
        main_tag_rules = span_validator.tag_rules

        tags = span_validator._tags
        span = span_validator.span
        success = True

        # log unverified tags to console
        if len(tags) > 0:
            if span_validator.failed_tag_rules:
                success = False
            elif span_validator.validate_all_tags:
                success = len(tags) == 0
            else:
                self._log.info("\n")
                self._log.info(
                    f"************************ Did not validate all tags for {main_tag_rules.name} rules for span {span['name']}. ************************"
                )
                self._log.info(" " * 5 + "*" * 14)
            self._log.info(
                f'     ************** Unverified span tags below for span {span["name"]} and rules {main_tag_rules.name} *************** '
            )
            for tag, value in tags.items():
                self._log.info(" " * 5 + "*" * 14 + " " * 15 + f"{tag} : {value}")

        self._log.info("\n")
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info(
            f"------------------------ Returning that {main_tag_rules.name} span validation returned: {success}. -----------------------------------"
        )
        for rule in span_validator.span_tag_rules_list:
            if span_validator.failed_tag_rules and rule == span_validator.failed_tag_rules:
                self._log.info(
                    " " * 5 + "X" * 14 + " " * 15 + f"{rule.name} " + "-" * (30 - len(rule.name)) + "> FAILED"
                )
            else:
                self._log.info(
                    " " * 5 + "*" * 14 + " " * 15 + f"{rule.name} " + "-" * (30 - len(rule.name)) + "> SUCCESS"
                )
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info("\n")

    def print_asserting_on(
        self, span_validator, matching_tags=False, required_tags=False, optional_tags=False, error=False
    ):
        phrase = ""
        if matching_tags:
            phrase = "tag comparisons"
        if required_tags:
            phrase = "required tags"
        if optional_tags:
            phrase = "optional tags"

        if error:
            self._log.info(
                " " * 5
                + "-" * 18
                + f"No {phrase} to assert on with tag rules {span_validator.tag_rules.name} "
                + "-" * (52 - len(phrase))
            )
        else:
            self._log.info(
                " " * 5
                + "-" * 18
                + f"Asserting on span with {span_validator.tag_rules.name} {phrase} "
                + " "
                + "-" * (60 - len(phrase))
            )
