import asyncio
import json
import logging
from aiohttp.web import Request
from typing import Any
from typing import Dict
from typing import cast

log = logging.getLogger(__name__)

TelemetryEvent = Dict[str, Any]

async def v2_decode_request(request: Request, data: bytes) -> TelemetryEvent:
    headers = request.headers

    if "X-Datadog-Test-Stall-Seconds" in headers:
        duration = float(headers["X-Datadog-Test-Stall-Seconds"])
    else:
        duration = request.app["trace_request_delay"]
    if duration > 0:
        log.info("Stalling for %r seconds.", duration)
        await asyncio.sleep(duration)
    v2_decode(data)


def v2_decode(data: bytes) -> TelemetryEvent:
    """Decode v2 apm telemetry request data as a dict"""
    # TODO: Handle decoding into a telemetry payload object
    return cast(TelemetryEvent, json.loads(data))
