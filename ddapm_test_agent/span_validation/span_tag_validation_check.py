import logging

from ..checks import Check
from .tag_checks import SpanTagChecks
from .tag_checks import SpanTagChecksLoader


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

GENERAL_SPAN_CHECK = SpanTagChecksLoader.load_span_tag_check("./specifications/ddtrace/general-spec.json")
ERROR_SPAN_CHECK = SpanTagChecksLoader.load_span_tag_check("./specifications/ddtrace/error-spec.json")
INTERNAL_SPAN_CHECK = SpanTagChecksLoader.load_span_tag_check("./specifications/ddtrace/internal-spec.json")


class SpanTagValidationCheck(Check):
    def __init__(
        self,
        span,
        type_span_check=None,
        integration_span_check=None,
        first_in_chunk_span_check=None,
    ):
        self.span = span

        # Set some basic attributes
        self.validate_all_tags = False
        self.main_tags_check = GENERAL_SPAN_CHECK
        self.span_tags_checks: list[SpanTagChecks] = [GENERAL_SPAN_CHECK, INTERNAL_SPAN_CHECK]

        if first_in_chunk_span_check:
            self.span_tags_checks.append(first_in_chunk_span_check)

        span_error = self.span.get("error", None)
        if span_error and span_error == 1:
            self.span_tags_checks.insert(1, ERROR_SPAN_CHECK)

        if type_span_check:
            self.main_tags_check = type_span_check
            self.span_tags_checks.append(type_span_check)

        if integration_span_check:
            self.main_tags_check = integration_span_check
            self.span_tags_checks.append(integration_span_check)

            span_type = self.span.get("type", None)

            # If a span doesn't have a type, validate all. If span has a type, check the type is valid and if yes, check we have check for type.
            # If we type check, validate all span tags, if we do not, do not validate all tags.
            if span_type:
                if span_type == "" or span_type in SPAN_TYPES:
                    self.validate_all_tags = True

        self.tag_check = self.span_tags_checks[0]
        self._tags = self.extract_tags(span, {})

    def check(self):
        for span_tags_check in self.span_tags_checks:
            span_tags_check.check(self)

        if self.validate_all_tags:
            if len(self._tags) > 0:
                self.fail(
                    f"Span validation failed for span: {self.span['name']} with rules: {self.main_tags_check.name}."
                )
        else:
            # warn about not asserting on all tags
            return

            # except AssertionError as e:
            #     self.console_out.print_result(self)
        #         raise AssertionError(e)
        # self.console_out.print_result(self)

    def extract_tags(self, span, extracted_tags):
        for k, v in span.items():
            if isinstance(v, dict):
                extracted_tags = self.extract_tags(v, extracted_tags)
            elif k in IGNORED_TAGS:
                continue
            else:
                extracted_tags[k] = v
        return extracted_tags
