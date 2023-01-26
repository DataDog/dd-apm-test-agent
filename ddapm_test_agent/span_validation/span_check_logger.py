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


class ConsoleSpanCheckLogger:
    def __init__(self, log):
        self._log = log
        self.length = 120

    def print_intro_message(self, span_validation_check):
        self._log.info("\n")
        self._log.info("~" * self.length)
        message = f" Asserting on span {span_validation_check.span['name']} with rules {span_validation_check.main_tags_check.name} within the validator! "
        indent = "~" * 20
        self.log_message(message, indent, "~")
        self._log.info("~" * self.length)
        self._log.info("\n")

    def warn_tags_not_asserted_on(self, span_validation_check):
        self._log.info("\n")
        message = f" Did not validate all tags for {span_validation_check.main_tags_check.name} rules for span {span_validation_check.span['name']} "
        indent = " " * 5 + "*" * 30
        self.log_message(message, indent, "*")

        message = f" Unverified span tags below for span {span_validation_check.span['name']} and rules {span_validation_check.main_tags_check.name} "
        indent = " " * 5 + "*" * 30
        self.log_message(message, indent, "*")

        for tag, value in span_validation_check._tags.items():
            indent = " " * 5 + "*" * 14 + " " * 15
            tag_k_v = f"{tag} : {str(value)[0:40]} "
            self._log.info(indent + tag_k_v)
        self._log.info("\n")

    def print_validation_success(self, span_validation_check):
        self._log.info("\n")
        main_tag_rules = span_validation_check.main_tags_check
        span = span_validation_check.span
        message = f" Returning that Span Validation Check: {main_tag_rules.name} returned: SUCCESSFUL for Span: {span['name']} "
        indent = "-" * 20
        self.log_message(message, indent, "-")

        for check in span_validation_check.span_tags_checks:
            # if span_validator.failed_tag_rules and rule == span_validator.failed_tag_rules:
            #     self._log.error(
            #         " " * 5 + "X" * 14 + " " * 15 + f"{rule.name} " + "-" * (30 - len(rule.name)) + "> FAILED"
            #     )

            message = f" {check.name} " + "-" * (30 - len(check.name)) + "> SUCCESS "
            indent = " " * 30
            self.log_message(message, indent, " ")

    def log_message(self, message, indent, char=" "):
        self._log.info(indent + message + (self.length - len(indent) - len(message)) * char)
