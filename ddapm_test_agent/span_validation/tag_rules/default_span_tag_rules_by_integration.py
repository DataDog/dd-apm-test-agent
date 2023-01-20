from typing import Any
from typing import Dict

from ..span_tag_rules import SpanTagRules


# ------------------------- Create rules for integration basic span (ie: rules for every django span to abide by) ------------------------------|

aiohttp_tag_rules = SpanTagRules(
    name="aiohttp",
    matches={"component": "aiohttp"},
)

aiohttp_client_tag_rules = SpanTagRules(
    name="aiohttp_client",
    matches={"component": "aiohttp_client"},
)
redis_tag_rules = SpanTagRules(
    name="redis",
    matches={"component": "redis"},
)

default_span_tag_rules_by_integration_map: Dict[str, Any] = dict(
    {
        "aiohttp": aiohttp_tag_rules,
        "aiohttp_client": aiohttp_client_tag_rules,
        "redis": redis_tag_rules,
    }
)
