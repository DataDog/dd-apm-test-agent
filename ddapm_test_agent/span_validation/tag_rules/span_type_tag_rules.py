from enum import Enum
from typing import Dict

from ..span_tag_rules import SpanTagRules


class SpanType(Enum):
    CACHE = "cache"
    CASSANDRA = "cassandra"
    ELASTICSEARCH = "elasticsearch"
    GRPC = "grpc"
    GRAPHQL = "graphql"
    HTTP = "http"
    MONGODB = "mongodb"
    REDIS = "redis"
    SQL = "sql"
    TEMPLATE = "template"
    TEST = "test"
    WEB = "web"
    WORKER = "worker"


http_tag_rules = SpanTagRules(
    name="HTTP",
    required_tags=["http.method", "http.url", "http.status_code"],
    optional_tags=[
        "http.useragent",
        "http.query.string",
        "http.route",
        "http.version",
        "http.status_msg",
    ],
)

span_type_tag_rules_map: Dict[str, SpanTagRules] = dict(
    {
        "http": http_tag_rules,
    }
)
