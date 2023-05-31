import asyncio
import logging

from aiohttp.web import Request
from multidict import CIMultiDictProxy

from .checks import Check
from .trace import Span


log = logging.getLogger(__name__)


class CheckTraceCountHeader(Check):
    name = "trace_count_header"
    description = """
The number of traces included in a payload must be included as the
X-Datadog-Trace-Count http header with each payload. The value of the
header must match the number of traces included in the payload.
""".strip()
    default_enabled = True

    def check(self, headers: CIMultiDictProxy, num_traces: int) -> None:
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
    description = """v0.4 payloads must include the Datadog-Meta-Tracer-Version header."""
    default_enabled = True

    def check(self, headers: CIMultiDictProxy) -> None:
        if "Datadog-Meta-Tracer-Version" not in headers:
            self.fail("Datadog-Meta-Tracer-Version not found in headers")


class CheckTraceContentLength(Check):
    name = "trace_content_length"
    description = """
The max content size of a trace payload is 50MB.
""".strip()
    default_enabled = True

    def check(self, headers: CIMultiDictProxy) -> None:
        if "Content-Length" not in headers:
            self.fail(f"content length header 'Content-Length' not in http headers {headers}")
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

    async def check(self, headers: CIMultiDictProxy, request: Request) -> None:
        if "X-Datadog-Test-Stall-Seconds" in headers:
            duration = float(headers["X-Datadog-Test-Stall-Seconds"])
        else:
            duration = request.app["trace_request_delay"]
        if duration > 0:
            log.info("Stalling for %r seconds.", duration)
            await asyncio.sleep(duration)


class CheckTracePeerService(Check):
    name = "trace_peer_service"
    description = """
The ``peer.service`` tag is correctly set for Client / Producer spans.
""".strip()
    default_enabled = True

    def check(self, span: Span) -> None:
        log.info("Performing ``peer.service`` Span Check")
        meta = span.get("meta", {})
        if meta.get("span.kind", "").lower() in ["client", "producer"]:
            if meta.get("peer.service", None) is None:
                self.fail(f"Span: {span['name']} of kind: {meta['span.kind']} should have tag ``peer.service`` set.")
            
            peer_service = meta.get("peer.service")
            peer_service_calculated = meta.get("_dd.peer.service.source", None)
            if peer_service != peer_service_calculated:
                self.fail(f"Span: {span['name']} expected to have ``peer.service`` tag equal to ``_dd.peer.service.source`` of: {peer_service_calculated}, actual: {peer_service} {meta['span.kind']}.")
            return


# class CheckTraceSpanMeasured(Check):
#     name = "trace_span_measured"
#     description = """
# The ``_dd.measured`` tag is correctly set to 1 for Client / Producer spans.
# """.strip()
#     default_enabled = True

#     def check(self, span: Span, trace_config: CIMultiDictProxy) -> None:
#         log.info("Performing ``_dd.measured`` Span Check")
#         schema_version = trace_config.get("DD_TRACE_SPAN_ATTRIBUTE_SCHEMA", "v0")
#         if schema_version == "v1":
#             meta = span.get("meta", {})
#             if meta.get("span.kind", "").lower() in ["client", "producer"]:
#                 if meta.get("_dd.measured", None) != 1:
#                     self.fail(f"Span: {span['name']} of kind: {meta['span.kind']} should have tag ``_dd.measured`` set to ``1``.")
#                 return
