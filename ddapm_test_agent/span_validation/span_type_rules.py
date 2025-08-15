from . import Exists, Matches, IsInstanceOf

# Default rules for every span.
span_rules = {
    "name": Exists(),
    "span_id": IsInstanceOf(int),
    "trace_id": IsInstanceOf(int),
    "start": IsInstanceOf(int),
    "duration": IsInstanceOf(int),
    "error": IsInstanceOf(int),
    "meta": {},
    "metrics": {},
}

# Rules for specific span types.
http_server_rules = {
    "name": "http.server.request",
    "type": "web",
    "resource": Exists(),
    "meta": {
        "span.kind": "server",
        "http.method": Matches(r"^(GET|POST|PUT|DELETE|PATCH)$"),
        "http.status_code": Matches(r"^\d{3}$"),
        "component": Exists(),
        "http.url": Matches(r"^http://localhost:\d+/user$"),
    },
    "metrics": {
        "http.status_code": IsInstanceOf(int),
    },
}

db_client_rules = {
    "name": Matches(r".*query"),
    "service": Exists(),
    "resource": Exists(),
    "type": "sql",
    "meta": {
        "span.kind": "client",
        "db.name": Exists(),
        "db.user": Exists(),
        "db.type": Exists(),
        "component": Exists(),
    },
    "metrics": {
        "network.destination.port": IsInstanceOf(int),
    },
}

dbm_propagation_rules = {
    "meta": {
        "_dd.dbm_trace_injected": "true",
    },
}
