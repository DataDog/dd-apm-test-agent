import asyncio
import logging
from typing import Dict

from aiohttp.web import Request

from .checks import Check


log = logging.getLogger(__name__)


class CheckTraceCountHeader(Check):
    name = "trace_count_header"
    description = """
The number of traces included in a payload must be included as the
X-Datadog-Trace-Count http header with each payload. The value of the
header must match the number of traces included in the payload.
""".strip()
    default_enabled = True

    def check(self, headers: Dict[str, str], num_traces: int) -> None:  # type: ignore
        if "X-Datadog-Trace-Count" not in headers:
            self.fail("X-Datadog-Trace-Count header not found in headers")
            return
        try:
            count = int(headers["X-Datadog-Trace-Count"])
        except ValueError:
            self.fail("X-Datadog-Trace-Count header is not a valid integer")
            return
        else:
            if num_traces != count:
                self.fail(
                    f"X-Datadog-Trace-Count value ({count}) does not match actual number of traces ({num_traces})"
                )


class CheckMetaTracerVersionHeader(Check):
    name = "meta_tracer_version_header"
    description = (
        """v0.4 payloads must include the Datadog-Meta-Tracer-Version header."""
    )
    default_enabled = True

    def check(self, headers: Dict[str, str]) -> None:  # type: ignore
        if "Datadog-Meta-Tracer-Version" not in headers:
            self.fail("Datadog-Meta-Tracer-Version not found in headers")


class CheckTraceContentLength(Check):
    name = "trace_content_length"
    description = """
The max content size of a trace payload is 50MB.
""".strip()
    default_enabled = True

    def check(self, headers: Dict[str, str]) -> None:  # type: ignore
        if "Content-Length" not in headers:
            self.fail(
                f"content length header 'Content-Length' not in http headers {headers}"
            )
            return
        content_length = int(headers["Content-Length"])
        if content_length > 5e7:
            self.fail(f"content length {content_length} too large.")


class CheckTraceStallAsync(Check):
    name = "trace_stall"
    description = """
Stall the trace (mimicking an overwhelmed or throttled agent) for the given duration in seconds.

Enable the check by submitting the X-Datadog-Test-Stall-Seconds http header (unit is seconds)
with the request.

Note that only the request for this trace is stalled, subsequent requests will not be
affected.
""".strip()
    default_enabled = True

    async def check(self, headers: Dict[str, str], request: Request) -> None:  # type: ignore
        duration = float(0)
        if "X-Datadog-Test-Stall-Seconds" in headers:
            duration = float(headers["X-Datadog-Test-Stall-Seconds"])
        elif request.app["trace_request_delay"] is not None:
            duration = float(request.app["trace_request_delay"])
        if duration > 0:
            log.info("Stalling for %r seconds.", duration)
            await asyncio.sleep(duration)
