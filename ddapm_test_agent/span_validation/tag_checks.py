import json
import logging
from pathlib import Path
from typing import Any

from ddapm_test_agent.trace import Span

from ..checks import Check
from ..checks import CheckTrace
from .span_check_logger import ConsoleSpanCheckLogger


log = logging.getLogger(__name__)

logger: ConsoleSpanCheckLogger = ConsoleSpanCheckLogger(log)

indent1 = "-" * 20
indent2 = " " * 30


def unpack(data, initial={}):
    for k, v in data.items():
        if isinstance(v, dict):
            initial = unpack(v, initial)
        else:
            initial[k] = v
    return initial


class TagCheck(Check):
    def __init__(self, name: str, val_type: str, required: bool, value: Any = None):
        self.name = name
        self.val_type: str = val_type
        self.required: bool = required
        self.value: Any = value
        self._failed: bool = False

    def check(self, span: Span) -> None:
        flattened_span = unpack(span)
        if self.required and self.value:
            logger.log_message(
                f" Asserting on span: {span['name']} having matching expected tag: {self.name} with value: {self.value} ",
                indent2,
            )
            if flattened_span["name"] != self.value:
                self.fail(f"Expected tag: {self.name} to be have value: {self.value} for span: {span['name']}")

        elif self.required:
            logger.log_message(f" Asserting on span: {span['name']} having required tag: {self.name} ", indent2)
            if self.name not in flattened_span.keys():
                self.fail(f"Expected tag: {self.name} to be found within span: {span['name']}")

        else:
            if self.name not in flattened_span.keys():
                logger.log_message(
                    f" Assertion on span: {span['name']} having optional tag: {self.name} found FALSE ", indent2
                )
            else:
                logger.log_message(
                    f" Assertion on span: {span['name']} having optional tag: {self.name} found TRUE ", indent2
                )


class SpanTagChecks(Check):
    def __init__(self, name, tags, span_type=None):
        self.name = name
        self.span_type: str = span_type
        self.tag_checks: list[TagCheck] = []
        self._failed: bool = False
        for tag_name in tags.keys():
            tag_spec = tags[tag_name]
            tag_check = TagCheck(
                name=tag_name,
                required=tag_spec.get("required", None),
                val_type=tag_spec.get("type", None),
                value=tag_spec.get("value", None),
            )
            self.tag_checks.append(tag_check)

    def check(self, span_validator_check):
        logger.log_message(
            f" Asserting on span: {span_validator_check.span['name']} with Span Tag Checks: {self.name} ", indent1, "-"
        )

        with CheckTrace.add_frame(f"SpanTagChecks: {self.name}") as f:
            for tag_check in self.tag_checks:
                f.add_check(tag_check)
                tag_check.check(span_validator_check.span)

                # if f.has_fails():
                #     self.fail(f"Span Tag Checks: {self.name} has failed for span: {span_validator_check.span['name']}.")

                if tag_check.name in span_validator_check._tags.keys():
                    del span_validator_check._tags[tag_check.name]


class SpanTagChecksLoader:
    def __init__(self):
        self.integration_spec_path: Path = Path("./specifications/integration/")
        self.general_spec_path: Path = Path("./specifications/ddtrace/")
        self.integration_specs: dict[
            str, dict[str, int]
        ] = {}  # { <INTEGRATION_NAME>: { <SPEC_NAME> : <SPEC_INDEX_IN_FILE> } }

        if not self.integration_spec_path.is_dir():
            raise FileNotFoundError(
                f"Integration Path {self.integration_spec_path} not found! Ensure you mounted specification directory."
            )

        for spec_file in self.integration_spec_path.iterdir():
            if spec_file.is_file():
                f = open(Path(spec_file))
                data = json.load(f)

                integration_specs = {}

                if type(data) == list:
                    for i, span_spec in enumerate(data):
                        integration_specs[span_spec.get("name")] = i

                self.integration_specs[str(spec_file.name)[:-10]] = integration_specs

    def load_span_tag_check(self, path: Path, spec_index: int = None) -> SpanTagChecks:
        if path.is_file():
            f = open(path)
            data = json.load(f)

            # if we have an index for a spec, there are a list of specs in the file and we need to get correct one
            if spec_index:
                data = data[spec_index]

            name = data.get("name")
            span_type = data.get("type", None)
            tag_checks_json = data.get("specification", {}).get("tags", {})

            return SpanTagChecks(name=name, tags=tag_checks_json, span_type=span_type)
        else:
            raise FileNotFoundError(f"Specification file not found for path {path}")

    def find_span_tag_check(self, span: Span) -> dict[str, SpanTagChecks]:
        component: str = span.get("component", "")
        span_name: str = span.get("name")
        span_checks: dict[str, SpanTagChecks] = {}

        if component != "" and component in self.integration_specs.keys():

            if span_name in self.integration_specs[component].keys():
                spec_index = self.integration_specs[component][span_name]
            else:
                spec_index = self.integration_specs[component][component + ".*"]
            span_checks["integration_span_check"] = self.load_span_tag_check(
                self.integration_spec_path / (component + "-spec.json"), spec_index=spec_index
            )

            if span_checks["integration_span_check"].span_type:
                span_type = span_checks["integration_span_check"].span_type

                span_checks["type_span_check"] = self.load_span_tag_check(
                    self.general_spec_path / (span_type + "-spec.json")
                )

        span_type = span.get("type", None)
        if span_type and "integration_span_check" not in span_checks.keys():
            span_checks["type_span_check"] = self.load_span_tag_check(
                self.general_spec_path / (span_type + "-spec.json")
            )

        return span_checks
