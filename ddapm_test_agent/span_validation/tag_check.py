import json
import logging
import os
from pathlib import Path
from typing import Any
from typing import Dict

from ddapm_test_agent.trace import Span

from ..checks import Check
from ..checks import CheckTrace
from .span_check_logger import ConsoleSpanCheckLogger


log = logging.getLogger(__name__)

logger: ConsoleSpanCheckLogger = ConsoleSpanCheckLogger(log)

indent1 = "-" * 20
indent2 = " " * 30

LANGUAGE = os.environ.get("TRACE_LANGUAGE", "default")

TESTED_SPAN_TYPES = ["http"]  # remove later once all are added


def unpack(data, initial={}):
    for k, v in data.items():
        if isinstance(v, dict):
            initial = unpack(v, initial)
        else:
            initial[k] = v
    return initial


string_to_type_map = {
    "string": str,
    "integer": int,
    "bool": bool,
    "float": float,
    "str": str,
    "int": int,
}



class TagCheck(Check):
    def __init__(self, name: str, val_type: Any, required: bool, value: Any = None):
        self.name = name
        self.val_type = val_type if isinstance(val_type, str) else None
        self.val_types = val_type if isinstance(val_type, list) else None
        self.required: bool = required
        self.value: Any = value
        self._failed: bool = False
        self._verified: bool = False


    def check(self, span: Span, span_check_name: str) -> None:
        flattened_span = unpack(span)
        if self.required and self.value:
            logger.log_message(
                f" Asserting on span '{span['name']}' having matching expected tag '{self.name}' with value: '{self.value}' ",
                indent2,
            )
            if self.name not in flattened_span.keys():
                message = f"REQUIRED-TAG-ERROR: Expected tag '{self.name}' to be found within span: '{span['name']}' during Check: '{span_check_name}'"
                logger.log_failure_message_to_file(message)
                self.fail(message)

            if flattened_span[self.name] != self.value:
                message = f"MATCHING-TAG-ERROR: Expected tag '{self.name}' to be have value: '{self.value}' for span: '{span['name']}' during Check: '{span_check_name}'"
                logger.log_failure_message_to_file(message)
                self.fail(message)
            self._verified = True
        elif self.required:
            logger.log_message(f" Asserting on span: '{span['name']}' having required tag: '{self.name}' ", indent2)
            if self.name not in flattened_span.keys():
                message = f"REQUIRED-TAG-ERROR: Expected tag '{self.name}' to be found within span: '{span['name']}' during Check: '{span_check_name}'"
                logger.log_failure_message_to_file(message)
                self.fail(message)

            if self.val_type:
                actual_val_type = type(
                    flattened_span.get(self.name, None)
                )  # if None, will be a <class> NoneType object
                if actual_val_type != string_to_type_map[self.val_type]:
                    message = f"TAG-VALUE-TYPE-ERROR: Expected tag '{self.name}' to have expected type '{self.val_type}', got: '{actual_val_type}'"
                    logger.log_failure_message_to_file(message)
                    self.fail(message)
            elif self.val_types:
                actual_val_type = type(
                    flattened_span.get(self.name, None)
                )  # if None, will be a <class> NoneType object
                expected_val_types = []
                for type_str in self.val_types:
                    expected_val_types.append(string_to_type_map[type_str])
                if actual_val_type not in expected_val_types:
                    message = f"TAG-VALUE-TYPE-ERROR: Expected tag '{self.name}' to have expected type of one of '{self.val_types}', got: '{actual_val_type}'"
                    logger.log_failure_message_to_file(message)
                    self.fail(message)
            self._verified = True
        else:
            if self.name not in flattened_span.keys():
                logger.log_message(
                    f" Assertion on span: '{span['name']}' having optional tag: '{self.name}' --------> FALSE ", indent2
                )
            else:
                if self.val_type:
                    actual_val_type = type(flattened_span.get(self.name, None))
                    if actual_val_type != string_to_type_map[self.val_type]:
                        message = f"TAG-VALUE-TYPE-ERROR: Expected tag '{self.name}' to have expected type '{self.val_type}', got: '{actual_val_type}'"
                        logger.log_failure_message_to_file(message)
                        self.fail(message)
                elif self.val_types:
                    actual_val_type = type(
                        flattened_span.get(self.name, None)
                    )  # if None, will be a <class> NoneType object
                    expected_val_types = []
                    for type_str in self.val_types:
                        expected_val_types.append(string_to_type_map[type_str])
                    if actual_val_type not in expected_val_types:
                        message = f"TAG-VALUE-TYPE-ERROR: Expected tag '{self.name}' to have expected type of one of '{self.val_types}', got: '{actual_val_type}'"
                        logger.log_failure_message_to_file(message)
                        self.fail(message)
                logger.log_message(
                    f" Assertion on span: '{span['name']}' having optional tag: '{self.name}' --------> TRUE ", indent2
                )
                self._verified = True


def merge_tag_checks(first: TagCheck, other: TagCheck):
    val_type = first.val_type if string_to_type_map.get(first.val_type, "") == string_to_type_map.get(other.val_type, "empty") else None
    value = first.value if first.value == other.value else None
    return TagCheck(name=first.name, val_type=val_type, required=(first.required and other.required), value=value)


class SpanTagChecks(Check):

    @classmethod
    def build(self, name: str, tags: dict, span_type: str=None):
        name = name
        span_type: str = span_type
        tag_checks: Dict[str, TagCheck] = {}
        for tag_name in tags.keys():
            tag_spec = tags[tag_name]
            tag_check = TagCheck(
                name=tag_name,
                required=tag_spec.get("required", None),
                val_type=tag_spec.get("type", None),
                value=tag_spec.get("value", None),
            )
            tag_checks[tag_name] = tag_check
        return SpanTagChecks(name=name, span_type=span_type, tag_checks=tag_checks)

    def __init__(self, name: str, tag_checks: Dict[str, TagCheck], span_type: str=None):
        self.name = name
        self.span_type: str = span_type
        self.tag_checks: Dict[str, TagCheck] = tag_checks
        self._failed: bool = False

    def add_tag_check(self, tag_name: str, val_type: Any, required: bool, value: Any = None):
        self.tag_checks[tag_name] = TagCheck(name=tag_name, val_type=val_type, required=required, value=value)

    def check(self, span_validator_check):
        logger.log_message(
            f" Asserting on span: {span_validator_check.span['name']} with Span Tag Checks: {self.name} ", indent1, "-"
        )

        with CheckTrace.add_frame(f"SpanTagChecks: {self.name}") as f:
            for tag_name, tag_check in self.tag_checks.items():
                f.add_check(tag_check)
                tag_check.check(span_validator_check.span, self.name)

                # if f.has_fails():
                #     self.fail(f"Span Tag Checks: {self.name} has failed for span: {span_validator_check.span['name']}.")

                if tag_check.name in span_validator_check._tags.keys():
                    del span_validator_check._tags[tag_check.name]


def merge_span_tag_checks(first: SpanTagChecks, other: SpanTagChecks):
    tag_checks = {}
    for tag_name, tag_check in first.tag_checks.items():
        if tag_check._verified and not tag_check._failed:
            if tag_name in other.tag_checks.keys():
                if other.tag_checks[tag_name]._verified and not other.tag_checks[tag_name]._failed:
                    tag_checks[tag_name] = merge_tag_checks(tag_check, other.tag_checks[tag_name])
            else:
                tag_checks[tag_name] = tag_check
    for tag_name, tag_check in other.tag_checks.items():
        if tag_check._verified and not tag_check._failed:
            # dont do anything with tag names in it since first case will add those checks
            if tag_name not in tag_checks.keys():
                tag_checks[tag_name] = tag_check
    return SpanTagChecks(name=first.name, tag_checks=tag_checks, span_type=first.span_type)


class SpanTagChecksLoader:
    def __init__(self):
        self.integration_spec_path: Path = Path("./specifications/integration/")
        self.general_spec_path: Path = Path(f"./specifications/ddtrace/{LANGUAGE}/")
        self.type_spec_path: Path = Path(f"./specifications/ddtrace/default/")
        self.integration_specs: Dict[
            str, Dict[str, SpanTagChecks]
        ] = {}  # { <INTEGRATION_NAME>: { <SPEC_NAME> : <SpanTagCheck> } }
        self.type_specs: Dict[str, SpanTagChecks] = {}

        if not self.integration_spec_path.is_dir():
            raise FileNotFoundError(
                f"Integration Path {self.integration_spec_path} not found! Ensure you mounted specification directory."
            )

        for spec_file in self.type_spec_path.iterdir():
            if spec_file.is_file():
                f = open(Path(spec_file))
                data = json.load(f)

                name = data.get("name")
                span_type = data.get("type", None)
                tag_checks_json = data.get("specification", {}).get("tags", {})

                if name in TESTED_SPAN_TYPES:
                    self.type_specs[name] = SpanTagChecks.build(name=name, tags=tag_checks_json, span_type=span_type)

        for spec_file in self.integration_spec_path.iterdir():
            if spec_file.is_file():
                f = open(Path(spec_file))
                data = json.load(f)

                integration_specs = {}

                if type(data) == list:
                    for span_spec in data:
                        name = span_spec.get("name")
                        span_type = span_spec.get("type", None)
                        tag_checks_json = span_spec.get("specification", {}).get("tags", {})
                        integration_specs[name] = SpanTagChecks.build(name=name, tags=tag_checks_json, span_type=span_type)

                self.integration_specs[str(spec_file.name)[:-10]] = integration_specs

    def load_span_tag_check(self, path: Path, spec_index: int = None) -> SpanTagChecks:
        if path.is_file():
            f = open(path)
            data = json.load(f)

            # if we have an index for a spec, there are a list of specs in the file and we need to get correct one
            if spec_index is not None:
                data = data[spec_index]

            name = data.get("name")
            span_type = data.get("type", None)
            tag_checks_json = data.get("specification", {}).get("tags", {})

            return SpanTagChecks.build(name=name, tags=tag_checks_json, span_type=span_type)
        else:
            raise FileNotFoundError(f"Specification file not found for path {path}")

    def find_span_tag_check(self, span: Span) -> Dict[str, SpanTagChecks]:
        component: str = span.get("meta", {}).get("component", "")
        span_name: str = span.get("name")
        span_checks: Dict[str, SpanTagChecks] = {}

        if component != "":
            if component in self.integration_specs.keys():
                if span_name in self.integration_specs[component].keys():
                    spec = self.integration_specs[component][span_name]
                else:
                    spec = self.integration_specs[component][component + ".*"]
                span_checks["integration_span_check"] = spec

                if span_checks["integration_span_check"].span_type:
                    span_type = span_checks["integration_span_check"].span_type

                    if span_type in TESTED_SPAN_TYPES:  # remove later once all types added
                        span_checks["type_span_check"] = self.type_specs[span_type]
            else:
                span_checks["blank_integration_span_check"] = SpanTagChecks(span_name, tag_checks={}, span_type=span.get("type", None))

        span_type = span.get("type", None)
        if (
            span_type and "integration_span_check" not in span_checks.keys() and span_type in TESTED_SPAN_TYPES
        ):  # remove later once all types added
            span_checks["type_span_check"] = self.type_specs[span_type]

        return span_checks