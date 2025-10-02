from typing import Any, Dict, Set

from .checks import Check
from .span_validation import SpanAssertion
from .span_validation.span_type_rules import db_client_rules, dbm_propagation_rules
from .trace_checks import TraceCheck


class CheckDBRequest(Check):
    name = "db_request"
    description = "Ensures that database spans have all the required tags."
    category = "Database"
    team = "APM"

    def check(self, span):
        if span.get("type") != "sql":
            return

        SpanAssertion(span, self).assert_span_matches(db_client_rules)


class CheckDBMPropagation(TraceCheck):
    name = "dbm_propagation"
    description = "Checks for DBM propagation comments in SQL queries."
    category = "Database"
    team = "APM"

    def __init__(self) -> None:
        super().__init__()
        self.dbm_propagation_modes: Set[str] = set()

    def on_span(self, span: dict) -> None:
        if span.get("type") != "db":
            return
        if "dbm.propagation.mode" in span.get("meta", {}):
            self.dbm_propagation_modes.add(span["meta"]["dbm.propagation.mode"])

    def on_trace_complete(self) -> None:
        if not self.dbm_propagation_modes:
            self.skip("No DBM propagation modes found in trace.")
        if "full" not in self.dbm_propagation_modes:
            self.fail("Expected at least one span with dbm.propagation.mode='full'.")
        if "service" not in self.dbm_propagation_modes:
            self.fail("Expected at least one span with dbm.propagation.mode='service'.")
