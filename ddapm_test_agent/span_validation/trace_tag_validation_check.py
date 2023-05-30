import logging
import os
from pathlib import Path
import pprint
from typing import Dict

from ..checks import Check
from ..checks import CheckTrace
from .span_tag_validation_check import SpanTagValidationCheck
from .tag_check import merge_span_tag_checks
from .tag_check import SpanTagChecks
from .tag_check import SpanTagChecksLoader
from .whitelist import SPAN_WHITELIST


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
    default_enabled = True
    

    def __init__(self, documentation: Dict[str, Dict[str, SpanTagChecks]] = {}):
        self._span_tag_check_loader = SpanTagChecksLoader()
        self.documentation = documentation
        self._failed: bool = False
        self._msg: str = ""
        
    def check(self, trace):
        for i, span in enumerate(trace):

            if i == 0:
                first_in_chunk_span_rules = FIRST_SPAN_IN_CHUNK_CHECK
            else:
                first_in_chunk_span_rules = None

            if span["name"] in SPAN_WHITELIST:
                with CheckTrace.add_frame(span_whitelisted_message(span)) as frame:
                    frame.add_item(f"Skipped Span:\n{pprint.pformat(span)}")
                continue

            # returns empty dictionary if no specific checks found, type_check and/or integration specific span check
            span_checks: list[SpanTagChecks] = self._span_tag_check_loader.find_span_tag_check(span=span)

            check = SpanTagValidationCheck(
                span=span,
                type_span_check=span_checks.get("type_span_check", None),
                integration_span_check=span_checks.get("integration_span_check", None),
                first_in_chunk_span_check=first_in_chunk_span_rules,
            )

            with CheckTrace.add_frame(span_failure_message(check, i)):
                unvalidated_tags = check.check()
                integration_span_check: SpanTagChecks = span_checks.get("integration_span_check") if span_checks.get("integration_span_check", None) else span_checks.get("blank_integration_span_check", None)
                type_span_check: SpanTagChecks = span_checks.get("type_span_check", None)
                if integration_span_check:
                    if len(unvalidated_tags.keys()) > 0:
                        for tag_name in unvalidated_tags.keys():
                            integration_span_check.add_tag_check(tag_name, val_type=None, required=False, value=None)

                    if type_span_check:
                        integration_span_check = merge_span_tag_checks(integration_span_check, type_span_check)
                    self.update_documentation(span, integration_span_check)
        return self._span_tag_check_loader.type_specs, self.documentation
                    
    
    def update_documentation(self, span, integration_span_spec: SpanTagChecks):
        # span should be guaranteed to have component
        component = span.get("meta", {}).get("component", "")
        if component != "":
            if component not in self.documentation.keys():
                self.documentation[component] = {span["name"]: integration_span_spec}
            else:
                if span["name"] not in self.documentation[component].keys():
                    self.documentation[component][span["name"]] = integration_span_spec
                else:
                    # else we have a span with the same name, lets merge the specs
                    self.documentation[component][span["name"]] = merge_span_tag_checks(integration_span_spec, self.documentation[component][span["name"]])


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
