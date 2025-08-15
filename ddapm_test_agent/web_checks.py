from .checks import Check
from .span_validation import SpanAssertion
from .span_validation.span_type_rules import http_server_rules


class CheckWebRequest(Check):
    name = "web_request"
    description = "Ensures that web spans have all the required tags."
    category = "Web"
    team = "APM INTEGRATIONS"

    def check(self, span):
        if span.get("type") != "web":
            return
        SpanAssertion(span, self).assert_span_matches(http_server_rules)
