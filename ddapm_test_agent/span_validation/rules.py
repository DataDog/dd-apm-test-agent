from .span_tag_rules import SpanTagRules


# ------------------------------------------ Span WhiteList for Skipping Span Validation ----------------------------------------|

span_whitelist = ["TCPConnector.connect"]

# ------------------------------------------ Create rules for General / Internal Span Tags --------------------------------------|

general_tag_rules = SpanTagRules(
    name="General",
    required_tags=[
        "component",
        "error"
    ],
    optional_tags=[
        "language",
        "error.msg",
        "error.type",
        "error.stack",
    ],
    first_span_in_chunk_tags=["runtime-id", "process_id"]
)
internal_tag_rules = SpanTagRules(
    name="Internal",
    optional_tags=[
        "_dd.p.dm",
        "_dd.agent_psr",
        "_dd.measured",
        "_dd.top_level",
        "_sampling_priority_v1",
        "_dd.tracer_kr",
    ],
)

# ------------------------------------------ Create rules for Type Specific Span Tags ---------------------------------------------------------|

http_tag_rules = SpanTagRules(
    name="HTTP",
    required_tags=["http.method", "http.url", "http.status_code", "http.status_msg"],
    optional_tags=["http.useragent", "http.query.string", "http.route", "http.version"],
)
error_tag_rules = SpanTagRules(
    name="error",
    optional_tags=["error.message", "error.type", "error.stack"],
)

type_tag_rules_map = {
    "error": error_tag_rules,
    "general": general_tag_rules,
    "internal": internal_tag_rules,
    "http": http_tag_rules,
}

# ------------------------- Create rules for integration basic span (ie: rules for every django span to abide by) ------------------------------|

aiohttp_tag_rules = SpanTagRules(name="aiohttp", matches={ "component": "aiohttp" })
aiohttp_client_tag_rules = SpanTagRules(name="aiohttp_client", matches={ "component": "aiohttp_client" })
redis_tag_rules = SpanTagRules(name="redis", matches={ "component": "redis" })

integration_general_span_tag_rules_map = {
    "aiohttp": aiohttp_tag_rules,
    "aiohttp_client": aiohttp_client_tag_rules,
    "redis": redis_tag_rules,
}

# ------------------------ Create rules for integration specific span (ie: rules for every django.request span to abide by)---------------------|

aiohttp_request_tag_rules = SpanTagRules(
    name="aiohttp.request",
    # matches={
    #     "span.kind": "server",
    # },
    type="web",
    base_integration_tag_rules=aiohttp_tag_rules
)
aiohttp_client_request_tag_rules = SpanTagRules(
    name="aiohttp.request",
    # matches={
    #     "span.kind": "client",
    # },
    type="http",
    base_integration_tag_rules=aiohttp_client_tag_rules
)
redis_command_tag_rules = SpanTagRules(
    name="redis.command",
    required_tags=["redis.raw_command", "out.host", "out.port"],
    # matches={
    #     "span.kind": "client",
    # },
    type="redis",
    base_integration_tag_rules=redis_tag_rules
)

integration_specific_span_tag_rules_map = {
    "aiohttp.request": {
        "aiohttp": aiohttp_request_tag_rules,
        "aiohttp_client": aiohttp_client_request_tag_rules
    },
    "redis.command": redis_command_tag_rules,
}
