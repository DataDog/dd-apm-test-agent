class OutputPrinter:
    def __init__(self, log):
        self._log = log

    def print_intro_message(self, span, tag_rules):
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

    def print_result(self, span, tag_rules, span_tags_left):
        success = len(span_tags_left) == 0
        self._log.info("\n")

        if not success:
            self._log.info(
                f'     ************** Unverified span tags below for span {span["name"]} and rules {tag_rules.name} *************** '
            )
            for tag, value in span_tags_left.items():
                self._log.info(" " * 5 + "*" * 14 + " " * 15 + f"{tag} : {value}" + " " * 15 + "*" * 14 + " " * 5)
            self._log.info("\n")
            self._log.info("\n")

        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
        self._log.info(
            f"------------------------ Returning that {tag_rules.name} span validation returned: {success}. -------------------------"
        )
        self._log.info(
            "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        )
