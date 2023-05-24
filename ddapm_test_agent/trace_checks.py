import asyncio
import logging
from trace import Trace

from aiohttp.web import Request
from multidict import CIMultiDictProxy

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


class CheckTraceServiceName(Check):
    name = "trace_service_name"
    description = """
Datadog Traces should abide by the new Service Naming initiative. Tracers should set the 
``DD_TRACE_SPAN_ATTRIBUTE_SCHEMA`` to either ``v0`` or ``v1``, and all received traces should abide
by the schema for Service Name. The schema defaults to v0 if not explicitly set.
""".strip()
    default_enabled = True

    def check(self, trace: Trace, headers: dict) -> None:
        schema_version = headers.get("DD_TRACE_SPAN_ATTRIBUTE_SCHEMA", "v0").lower()
        dd_service = headers.get("DD_SERVICE", None)
        for span in trace:
            span_service_name = span.get("service")
            peer_service = span.get("meta", None).get("peer.service", None)
            if schema_version == "v1":
                if not dd_service:
                    self.fail(f"Could not verify Schema v1 Service Naming, no DD_SERVICE sent within trace headers. \n Failing Span: {span}\n Trace Headers: {headers}\n")
                elif dd_service != span_service_name:
                    self.fail(f"Span service name: {span_service_name} does not match DD_SERVICE {dd_service} for Schema v1 Service Naming. \n Failing Span: {span}\n Trace Headers: {headers}\n")
                # elif not peer_service:
                #     self.fail(f"Tag `peer.service` should be set for Schema v1 Service Naming. \n Failing Span: {span}\n Trace Headers: {headers}\n")
            elif schema_version == "v0":
                if not dd_service:
                    self.fail(f"Could not verify Schema v0 Service Naming, no DD_SERVICE sent within trace headers. \n Failing Span: {span}\n Trace Headers: {headers}\n")
                elif dd_service != span_service_name:
                    self.fail(f"Span service name: {span_service_name} does not match DD_SERVICE {dd_service} for Schema v0 Service Naming. \n Failing Span: {span}\n Trace Headers: {headers}\n")