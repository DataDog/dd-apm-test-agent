"""Shared CORS helpers for LLMObs and lapdog UI endpoints."""

import re
from typing import Dict
from typing import Optional

from aiohttp.web import Request


ALLOWED_ORIGIN_PATTERN = re.compile(
    r"^https?://(localhost(:\d+)?|127\.0\.0\.1(:\d+)?|[\w.-]+\.datadoghq\.(com|eu)|"
    r"[\w.-]+\.ddog-gov\.com|[\w.-]+\.datad0g\.com|[\w.-]+\.static-app\.us1\.staging\.dog)$"
)

_DEFAULT_ALLOW_HEADERS = (
    "Content-Type, Authorization, X-DD-Api-Key, X-DD-Application-Key, "
    "X-CSRF-Token, x-csrf-token, x-web-ui-version, X-Datadog-Trace-ID, "
    "X-Datadog-Parent-ID, X-Datadog-Origin, X-Datadog-Sampling-Priority, Accept, Origin, Referer"
)


def cors_headers(
    request: Request,
    *,
    allow_methods: str = "GET, POST, OPTIONS",
    allow_headers: str = _DEFAULT_ALLOW_HEADERS,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build CORS headers, only allowing known origins."""
    headers: Dict[str, str] = {
        "Access-Control-Allow-Methods": allow_methods,
        "Access-Control-Allow-Headers": allow_headers,
        "Vary": "Origin",
    }
    if extra:
        headers.update(extra)
    origin = request.headers.get("Origin", "")
    if ALLOWED_ORIGIN_PATTERN.match(origin):
        headers["Access-Control-Allow-Origin"] = origin
    return headers
