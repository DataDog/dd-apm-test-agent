from .span_metadata_rules import SpanMetadataRules


# ------------------------------------------ Create rules for basic span types --------------------------------------------------|

general_metadata_rules = SpanMetadataRules(
    name="GENERAL",
    required_tags=[
        "duration",
        "resource",
        "span_id",
        "runtime-id",
        "process_id",
        "trace_id",
        "start",
    ],
    optional_tags=[
        "version",
        "language",
        "error.msg",
        "error.type",
        "error.stack",
        "parent_id",
        "service",
        "env",
    ],
)
internal_metadata_rules = SpanMetadataRules(
    name="INTERNAL",
    optional_tags=[
        "_dd.p.dm",
        "_dd.agent_psr",
        "_dd.measured",
        "_dd.top_level",
        "_sampling_priority_v1",
        "_dd.tracer_kr",
    ],
)
http_metadata_rules = SpanMetadataRules(
    name="HTTP",
    required_tags=["http.method", "http.url", "http.status_code", "http.status_msg"],
    optional_tags=["http.useragent", "http.query.string", "http.route", "http.version"],
)
error_metadata_rules = SpanMetadataRules(
    name="error",
    optional_tags=["error.message", "error.type", "error.stack"],
)

type_metadata_rules_map = {
    "error": error_metadata_rules,
    "general": general_metadata_rules,
    "internal": internal_metadata_rules,
    "http": http_metadata_rules,
}

# ------------------------------------------ Create rules for integration span --------------------------------------------------|

aiohttp_metadata_rules = SpanMetadataRules(name="aiohttp.request", type="http")
redis_metadata_rules = SpanMetadataRules(
    name="redis.command",
    type="redis",
    required_tags=["redis.raw_command", "out.host", "out.port"],
    matches={
        "component": "redis",
        "span.kind": "client",
    },
)

integration_metadata_rules_map = {
    "aiohttp.request": aiohttp_metadata_rules,
    "redis.command": redis_metadata_rules,
}
