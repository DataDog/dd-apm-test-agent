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
        tag_rules = span_validator.tag_rules
        tags = span_validator._tags
        span = span_validator.span
        success = True

        # log unverified tags to console
        if len(tags) > 0:
            if span_validator.validate_all_tags:
                success = len(tags) == 0
            else:
                self._log.info("\n")
                self._log.info(
                    f"************************ Not validating all tags for {tag_rules.name} rules for span {span['name']}. ************************"
                )

            self._log.info("\n")
            self._log.info(
                f'     ************** Unverified span tags below for span {span["name"]} and rules {tag_rules.name} *************** '
            )
            for tag, value in tags.items():
                self._log.info(" " * 5 + "*" * 14 + " " * 15 + f"{tag} : {value}")
            self._log.info("\n")

        self._log.info("\n")
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info(
            f"------------------------ Returning that {tag_rules.name} span validation returned: {success}. ------------------------"
        )
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info("\n")
