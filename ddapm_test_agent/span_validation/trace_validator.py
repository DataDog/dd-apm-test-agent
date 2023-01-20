import logging
from pathlib import Path
import pprint

from ..checks import CheckTrace
from .span_tag_validator import SpanTagValidator
from .tag_rules.general_span_tag_rules import general_span_tag_rules_map
from .tag_rules.integration_default_span_tag_rules import default_span_tag_rules_by_integration_map
from .tag_rules.integration_root_span_tag_rules import root_span_tag_rules_by_integration_map
from .tag_rules.type_span_tag_rules import span_type_tag_rules_map
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
        log.info(space_indent * 2 + "    " + chunk)
    log.info(space_indent + header)
    log.info("\n")


class TraceValidator:
    def __init__(self, agent):
        self.agent = agent

    def validate_trace(self, trace):
        for i, span in enumerate(trace):
            component: str = span["meta"].get("component", "")

            integration_base_span_rules = None
            integration_root_span_rules = None
            type_span_rules = None
            span_type = span.get("type", None)

            if i == 0:
                first_in_chunk_span_rules = general_span_tag_rules_map["chunk"]
            else:
                first_in_chunk_span_rules = None

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
                    # component tag should always be defined
                    if component == "":
                        raise AttributeError(
                            f"COMPONENT-ASSERTION-ERROR: Span with name {span['name']} should have a component tag!"
                        )
                    span_name = span["name"]

                    # if type == dict, multiple integrations produce this span name. Get correct integration root span rules.
                    if type(root_span_tag_rules_by_integration_map[span_name]) == dict:
                        integration_root_span_rules = root_span_tag_rules_by_integration_map[span_name][component]
                    else:
                        integration_root_span_rules = root_span_tag_rules_by_integration_map[span_name]

                    # get integration base span rules:
                    if component in default_span_tag_rules_by_integration_map.keys():
                        integration_base_span_rules = default_span_tag_rules_by_integration_map.get(component, None)

                    # get span type rules if this span has a type
                    if span_type:
                        # validate actual and expected span types equal
                        if integration_root_span_rules.span_type:
                            if span_type != integration_root_span_rules.span_type:
                                raise AssertionError(
                                    "TYPE-ASSERTION-ERROR: "
                                    + f"Integration {component} specific span: {span_name} should have span_type {integration_root_span_rules.span_type}"
                                )
                        if integration_base_span_rules and integration_base_span_rules.span_type:
                            if span_type != integration_base_span_rules.span_type:
                                raise AssertionError(
                                    "TYPE-ASSERTION-ERROR: "
                                    + f"Integration {component} specific span: {span_name} should have span_type {integration_base_span_rules.span_type}"
                                )
                        type_span_rules = span_type_tag_rules_map.get(span_type, None)

                    # else if there are rules with expected span types, raise an error if actual span does not have type
                    else:
                        if integration_root_span_rules.span_type:
                            raise AssertionError(
                                "TYPE-ASSERTION-ERROR: "
                                + f"Integration {component} specific span: {span_name} should have span_type {integration_root_span_rules.span_type}"
                            )

                        if integration_base_span_rules and integration_base_span_rules.span_type:
                            raise AssertionError(
                                "TYPE-ASSERTION-ERROR: "
                                + f"Integration {component} specific span: {span_name} should have span_type {integration_base_span_rules.span_type}"
                            )

                    log.info("\n")
                    log.info("~" * 160)
                    log.info(
                        space_indent * 2
                        + f" Validating integration {component} specific span: {span_name}."
                        + space_indent * 2
                    )
                    log.info("~" * 160)

                    # Validate span!
                    SpanTagValidator(
                        span=span,
                        type_span_rules=type_span_rules,
                        integration_base_span_rules=integration_base_span_rules,
                        integration_root_span_rules=integration_root_span_rules,
                        first_in_chunk_span_rules=first_in_chunk_span_rules,
                    ).validate()

                except Exception as msg:
                    log_error(msg)
                    with CheckTrace.add_frame(span_failure_message(span, i)) as frame:
                        frame.add_item("Received span:\n")
                        pprint.pprint(span, indent=2)
                    self.log_span_tag_validation_error_to_file(span, msg)

            # check for an integration-level span tag test using component tag within span.
            # IE: All Django spans must abide by these tag rules.
            elif component != "" and component in default_span_tag_rules_by_integration_map.keys():

                log.info("\n")
                log.info("~" * 160)
                log.info(
                    space_indent * 2
                    + f" Validating integration {component} general span: {span_name}."
                    + space_indent * 2
                )
                log.info("~" * 160)

                span_name = span["name"]

                try:
                    integration_base_span_rules = default_span_tag_rules_by_integration_map[component]

                    # get span type rules if this span has a type
                    if span_type:
                        # validate actual and expected span types equal
                        if integration_base_span_rules and integration_base_span_rules.span_type:
                            if span_type != integration_base_span_rules.span_type:
                                raise AssertionError(
                                    "TYPE-ASSERTION-ERROR: "
                                    + f"Integration {component} specific span: {span_name} should have span_type {integration_base_span_rules.span_type}"
                                )
                        type_span_rules = span_type_tag_rules_map.get(span_type, None)
                    else:
                        # else if there are rules with expected span type, raise an error if actual span does not have type
                        if integration_base_span_rules and integration_base_span_rules.span_type:
                            raise AssertionError(
                                "TYPE-ASSERTION-ERROR: "
                                + f"Integration {component} specific span: {span_name} should have span_type {integration_base_span_rules.span_type}"
                            )

                    # Validate Span!
                    SpanTagValidator(
                        span=span,
                        type_span_rules=type_span_rules,
                        integration_base_span_rules=integration_base_span_rules,
                        first_in_chunk_span_rules=first_in_chunk_span_rules,
                    ).validate()

                except Exception as msg:
                    log_error(msg)
                    with CheckTrace.add_frame(span_failure_message(span, i)) as frame:
                        frame.add_item("Received span:\n")
                        pprint.pprint(span, indent=2)
                    self.log_span_tag_validation_error_to_file(span, msg)

            # Else no specific test for the span / integration. Default to basic span test, do a type test if the span has a type as well
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
                    # if span_type and span_type not in span_type_tag_rules_map.keys():
                    #     raise AttributeError(
                    #         f"TYPE-ASSERTION-ERROR: Span with name {span['name']} with span_type {span['type']}" +
                    #         f"not in officially supported list of types: {str(span_type_tag_rules_map.keys())}"
                    #     )
                    type_span_rules = span_type_tag_rules_map.get(span_type, None)

                    # Validate Span!
                    SpanTagValidator(
                        span=span,
                        type_span_rules=type_span_rules,
                        first_in_chunk_span_rules=first_in_chunk_span_rules,
                    ).validate()

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
