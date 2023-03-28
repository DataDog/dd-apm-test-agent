import logging
import os
from pathlib import Path
import pprint

from ..checks import Check
from ..checks import CheckTrace
from .span_tag_validation_check import SpanTagValidationCheck
from .tag_checks import SpanTagChecks
from .tag_checks import SpanTagChecksLoader
from .whitelist import span_whitelist


log = logging.getLogger(__name__)

LANGUAGE = os.environ.get("TRACE_LANGUAGE", "default")

FIRST_SPAN_IN_CHUNK_CHECK = SpanTagChecksLoader().load_span_tag_check(
    path=Path(f"./specifications/ddtrace/{LANGUAGE}/root-span-in-chunk-spec.json")
)


def span_failure_message(check, i):
    return f"Span Validation Failure for span '{check.span['name']}' at position {i} in trace for Check: '{check.main_tags_check.name}'"


def span_whitelisted_message(span):
    return f"Skipping Span Validation for Whitelisted Span: {span['name']}"


class TraceTagValidationCheck(Check):
    name = "trace_tag_validation"
    description = """
Perform tag validation on traces to ensure span tagging is in compliance with Datadog Unified Naming Convention work.
""".strip()
    default_enabled = False

    def check(self, trace):
        for i, span in enumerate(trace):

            if i == 0:
                first_in_chunk_span_rules = FIRST_SPAN_IN_CHUNK_CHECK
            else:
                first_in_chunk_span_rules = None

            if span["name"] in span_whitelist:
                with CheckTrace.add_frame(span_whitelisted_message(span)) as frame:
                    frame.add_item(f"Skipped Span:\n{pprint.pformat(span)}")
                continue

            # returns empty dictionary if no specific checks found, type_check and/or integration specific span check
            span_checks: list[SpanTagChecks] = SpanTagChecksLoader().find_span_tag_check(span=span)
            check = SpanTagValidationCheck(
                span=span,
                type_span_check=span_checks.get("type_span_check", None),
                integration_span_check=span_checks.get("integration_span_check", None),
                first_in_chunk_span_check=first_in_chunk_span_rules,
            )

            with CheckTrace.add_frame(span_failure_message(check, i)):
                check.check()
                # log to file??


def log_span_tag_validation_error_to_file(message):
    lines = set([])
    writepath = Path("./validation_failures.txt")
    if writepath.is_file():
        with open(writepath, "r") as f:
            data = f.readlines()
            lines = set([line.rstrip() for line in data])
            lines.discard("")

    lines.add(str(message))
    with open(writepath, "w") as f:
        for line in lines:
            if line != "":
                f.write(line + "\n")
