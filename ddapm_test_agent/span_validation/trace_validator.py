import logging
from pathlib import Path
import pprint

from ..checks import CheckTrace
from .span_validator import SpanTagValidator
from .tag_rules.default_span_tag_rules_by_integration import default_span_tag_rules_by_integration_map
from .tag_rules.general_span_tag_rules import general_span_tag_rules_map
from .tag_rules.root_span_tag_rules_by_integration import root_span_tag_rules_by_integration_map
from .tag_rules.whitelist import span_whitelist


log = logging.getLogger(__name__)

header = "~" * 108
space_indent = "~" * 20


def span_failure_message(span, i):
    return f"Snapshot compare of span '{span['name']}' at position {i} in trace"


def log_error(message):
    n = 80
    if type(message) != str:
        message = str(message)
    msg_chunks = [message[i : i + n] for i in range(0, len(message), n)]
    log.info("\n")
    log.info(space_indent + header)
    for chunk in msg_chunks:
        log.info(space_indent * 2 + "    " + chunk + "    " + space_indent * 2)
    log.info(space_indent + header)
    log.info("\n")


class TraceValidator:
    def __init__(self, agent):
        self.agent = agent

    def validate_trace(self, trace):
        for i, span in enumerate(trace):
            component: str = span["meta"].get("component", "")

            if span["name"] in span_whitelist:
                log.info("\n")
                log.info("~" * 160)
                log.info(
                    "#" * 40
                    + f" WHITELISTED: Skipping validating integration {component} span: {span['name']} "
                    + "#" * 40
                )
                log.info("~" * 160)
                log.info("\n")
            # check if span name has an associated tag rules test, ie: web.request has a specific test case
            elif span["name"] in root_span_tag_rules_by_integration_map.keys():
                try:
                    # component should always be defined
                    if component == "":
                        raise AttributeError(
                            f"COMPONENT-ASSERTION-ERROR: Span with name {span['name']} should have a component tag!"
                        )
                    span_name: str = span["name"]
                    # if type == dict, multiple integrations produce this span name. Makes sure to get the right test case by component
                    if type(root_span_tag_rules_by_integration_map[span_name]) == dict:
                        span_rules = root_span_tag_rules_by_integration_map[span_name][component]
                    else:
                        span_rules = root_span_tag_rules_by_integration_map[span_name]
                    log.info("\n")
                    log.info("~" * 160)
                    log.info(
                        space_indent * 2
                        + f" Validating integration {component} specific span: {span_name}."
                        + space_indent * 2
                    )
                    log.info("~" * 160)
                    SpanTagValidator(
                        span,
                        span_rules,
                        validate_first_span_in_chunk_tags=i == 0,
                    )
                except Exception as msg:
                    log_error(msg)
                    with CheckTrace.add_frame(span_failure_message(span, i)) as frame:
                        frame.add_item("Received span:\n")
                        pprint.pprint(span, indent=2)
                    self.log_span_tag_validation_error_to_file(span, msg)

            # check for an integration-level span tag test using component tag within span.
            # IE: All Django spans must abide by these tag rules.
            elif component != "" and component in default_span_tag_rules_by_integration_map.keys():
                span_name = span["name"]
                log.info("\n")
                log.info("~" * 160)
                log.info(
                    space_indent * 2
                    + f" Validating integration {component} general span: {span_name}."
                    + space_indent * 2
                )
                log.info("~" * 160)
                try:
                    span_rules = default_span_tag_rules_by_integration_map[span_name]
                    SpanTagValidator(
                        span,
                        span_rules,
                        validate_first_span_in_chunk_tags=i == 0,
                    )
                except Exception as msg:
                    log_error(msg)
                    with CheckTrace.add_frame(span_failure_message(span, i)) as frame:
                        frame.add_item("Received span:\n")
                        pprint.pprint(span, indent=2)
                    self.log_span_tag_validation_error_to_file(span, msg)

            # Else no specific test for the span / integration. Default to basic span test
            else:
                log.info("\n")
                log.info("~" * 160)
                log.info(
                    space_indent * 2
                    + f" No specific rules, validating general rules for {span['name']} with component {component} "
                    + space_indent * 2
                )
                log.info("~" * 160)
                try:
                    span_rules = general_span_tag_rules_map["general"]
                    SpanTagValidator(
                        span,
                        span_rules,
                        validate_base_tags=False,
                        validate_first_span_in_chunk_tags=i == 0,
                    )
                except Exception as msg:
                    log_error(msg)
                    with CheckTrace.add_frame(span_failure_message(span, i)) as frame:
                        frame.add_item("Received span:\n")
                        pprint.pprint(span, indent=2)
                    self.log_span_tag_validation_error_to_file(span, msg)

    def log_span_tag_validation_error_to_file(self, span, message):
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
