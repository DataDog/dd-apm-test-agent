from typing import Any
from typing import Dict

from ..span_tag_rules import SpanTagRules


# ------------------------ Create rules for integration specific span (ie: rules for every django.request span to abide by)---------------------|

aiohttp_request_tag_rules = SpanTagRules(
    name="aiohttp.request",
    # matches={
    #     "span.kind": "server",
    # },
    span_type="web",
)

aiohttp_client_request_tag_rules = SpanTagRules(
    name="aiohttp.request",
    # matches={
    #     "span.kind": "client",
    # },
    span_type="http",
)

redis_command_tag_rules = SpanTagRules(
    name="redis.command",
    required_tags=["redis.raw_command", "out.host", "out.port"],
    # matches={
    #     "span.kind": "client",
    # },
    span_type="redis",
)

root_span_tag_rules_by_integration_map: Dict[str, Any] = dict(
    {
        "aiohttp.request": {
            "aiohttp": aiohttp_request_tag_rules,
            "aiohttp_client": aiohttp_client_request_tag_rules,
        },
        "redis.command": redis_command_tag_rules,
    }
)
