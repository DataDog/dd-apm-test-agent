from typing import Any, Dict

from .checks import Check
from .span_validation import SpanAssertion
from .span_validation.span_type_rules import db_client_rules, dbm_propagation_rules


class CheckDBRequest(Check):
    name = "db_request"
    description = "Ensures that database spans have all the required tags."
    category = "Database"
    team = "APM"

    def check(self, span):
        if span.get("type") != "sql":
            return

        SpanAssertion(span, self).assert_span_matches(db_client_rules)


class CheckDBMPropagation(Check):
    name = "dbm_propagation"
    description = "Checks for DBM propagation comments in SQL queries."
    category = "Database"
    team = "APM"

    def check(self, span, dd_config_env):
        dbm_propagation_mode = dd_config_env.get("DD_DBM_PROPAGATION_MODE", "disabled")
        if dbm_propagation_mode != "full":
            self.skip(
                f"Skipping DBM propagation check because DD_DBM_PROPAGATION_MODE is '{dbm_propagation_mode}'."
            )
            return

        if span.get("type") != "sql":
            return

        SpanAssertion(span, self).assert_span_matches(dbm_propagation_rules)
