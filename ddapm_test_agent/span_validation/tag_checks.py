import json
from pathlib import Path
from typing import Any
from typing import Optional

from ddapm_test_agent.trace import Span

from ..checks import Check


class TagCheck(Check):
    val_type: type
    required: bool
    value: Optional[Any]

    def __init__(self, val_type, required, value=None):
        self.val_type = val_type
        self.required = required
        self.value = value

    def check(self, span: Span) -> None:
        # doing assertion for tag check blah blah blah
        if self.required:
            if self.name not in span.keys():
                self.fail(f"Expected tag: {self.name} to be found within span: {span['name']}")
            # Verified existence of tag
            if self.value:
                # aserting on matching tags value
                if span.get([self.name]) != self.value:
                    self.fail(f"Expected tag: {self.name} to be have value: {self.value} for span: {span['name']}")
        else:
            # print verified
            if self.name not in span.keys():
                # verified existence of optional tag
                pass


class SpanTagChecks(Check):
    tag_checks: list[TagCheck]
    span_type: str

    def __init__(self, name, tags, span_type=None):
        self.name = name
        self.span_type = span_type
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
        # asserting on name of check
        try:
            for tag_check in self.tag_checks:
                tag_check.check(span_validator_check.span)
                if self.name in span_validator_check._tags.keys():
                    del span_validator_check._tags[tag_check.name]
        except Exception as e:
            # failed check
            # print failed check of some sort
            self.fail(str(e))


class SpanTagChecksLoader:
    def __init__(self):
        self.integration_spec_path = Path("./specifications/integration/")
        self.general_spec_path = Path("./specifications/ddtrace/")
        self.integration_specs: dict[
            str, dict[str, int]
        ] = {}  # { <INTEGRATION_NAME>: { <SPEC_NAME> : <SPEC_INDEX_IN_FILE> } }

        if not self.integration_spec_path.is_dir():
            self.fail(
                f"Integration Path {self.integration_spec_path} not found! Ensure you mounted specification directory."
            )

        for spec_file in self.integration_spec_path.iterdir():
            if spec_file.is_file():
                f = open(Path(spec_file))
                data = json.load(f)

                integration_specs = {}

                if type(data) == list:
                    for i, span_spec in enumerate(data):
                        integration_specs[span_spec["name"]] = i

                self.integration_specs[spec_file[:-10]] = integration_specs

    def load_span_tag_check(self, path: Path, spec_index: Any = None) -> SpanTagChecks:
        if path.is_file():
            f = open(path)
            data = json.load(f)

            # if we have an index for a spec, there are a list of specs in the file and we need to get correct one
            if spec_index:
                data = data[spec_index]

            name = data["name"]
            span_type = data.get("type", None)
            tag_checks_json = data.get("specification", {}).get("tags", {})

            return SpanTagChecks(name=name, tags=tag_checks_json, span_type=span_type)
        else:
            raise FileNotFoundError(f"Specification file not found for path {path}")

    def find_span_tag_check(self, span: Span) -> dict[str, SpanTagChecks]:
        component: str = span.get("component", "")
        span_name: str = span.get("name")
        span_checks: dict[str, SpanTagChecks] = {}

        if component in self.integration_specs.keys():

            if span_name in self.integration_specs[component].keys():
                spec_index = self.integration_specs[component][span_name]
            else:
                spec_index = self.integration_specs[component][component + ".*"]
            span_checks["integration_span_check"] = self.load_span_tag_check(
                Path(str(self.integration_spec_path) + component + "-spec.json"), spec_index=spec_index
            )

            if span_checks["integration_span_check"].span_type:
                span_type = span_checks["integration_span_check"].span_type

                span_checks["type_span_check"] = self.load_span_tag_check(
                    self.general_spec_path + span_type + "-spec.json"
                )

        span_type = span.get("type", None)
        if span_type and "integration_span_check" not in span_checks.keys():
            span_checks["type_span_check"] = self.load_span_tag_check(
                Path(self.general_spec_path + span_type + "-spec.json")
            )

        return span_checks
