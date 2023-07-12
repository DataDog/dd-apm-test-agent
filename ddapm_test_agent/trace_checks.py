import asyncio
import json
import logging
from typing import Dict
from typing import List

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

    def check(self, headers: CIMultiDictProxy) -> None:
        if "Datadog-Meta-Tracer-Version" not in headers:
            self.fail("Datadog-Meta-Tracer-Version not found in headers")


class CheckTraceContentLength(Check):
    name = "trace_content_length"
    description = """
The max content size of a trace payload is 50MB.
""".strip()

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

    def check(self, span: Span, dd_config_env: Dict[str, str]) -> None:
        log.info("Performing ``peer.service`` Span Check")
        meta = span.get("meta", {})

        whitelisted_components = ["couchbase"]

        if dd_config_env.get("DD_TRACE_SPAN_ATTRIBUTE_SCHEMA", "v0") != "v0":
            if "peer.service" in meta.keys():
                for component in whitelisted_components:
                    if component in meta.get("component", ""):
                        skipped_component = meta.get("component", "")
                        log.debug(
                            f"Skipped ``peer.service`` Span Check for Span: {span['name']} with component {skipped_component}."
                        )
                        self.skip(
                            f"Skipped ``peer.service`` Span Check for Span: {span['name']} with component {skipped_component}."
                        )
                        return

                # if meta.get("peer.service", None) is None:
                # self.fail(json.dumps(span, indent=4) + f"\nSpan: {span['name']} of kind: {meta['span.kind']} should have tag ``peer.service`` set.")

                peer_service = meta.get("peer.service")
                peer_service_source_key = meta.get("_dd.peer.service.source", "")
                peer_service_source_val = meta.get(peer_service_source_key, "")
                if peer_service != peer_service_source_val:
                    self.fail(
                        json.dumps(span, indent=4)
                        + f"\nSpan: {span['name']} expected to have ``peer.service`` tag equal to ``{peer_service_source_key}`` of: {peer_service_source_val}, actual: {peer_service}."
                    )
                log.debug(f"Successfully completed `peer.`service`` tag Span Check for Span: {span['name']}")
                return
            else:
                log.debug(f"Skipped ``peer.service`` Span Check for Span: {span['name']} with no `peer.service` tag")
                self.skip(f"Skipped ``peer.service`` Span Check for Span: {span['name']} with no `peer.service` tag")
        else:
            log.debug(
                f"Skipped ``peer.service`` Span Check for Span: {span['name']} with DD_TRACE_SPAN_ATTRIBUTE_SCHEMA `v0`."
            )
            self.skip(
                f"Skipped ``peer.service`` Span Check for Span: {span['name']} with DD_TRACE_SPAN_ATTRIBUTE_SCHEMA `v0`."
            )


class CheckTraceDDService(Check):
    name = "trace_dd_service"
    description = """
The ``service`` name is correctly set to ``DD_SERVICE`` for V1 auto-instrumented spans.
""".strip()
    default_enabled = True

    def check(self, trace: List[Span], dd_config_env: Dict[str, str]) -> None:
        log.info("Performing ``DD_SERVICE`` Trace Check")

        # trace context can be set to service for each span
        trace_context = None

        whitelisted_components = ["rabbitmq", "jms", "kafka", "java-web-servlet-response"]

        if dd_config_env.get("DD_TRACE_SPAN_ATTRIBUTE_SCHEMA", "v0") != "v1":
            log.debug("Skipping Span Check `trace_dd_service` for Span Attribute Schema v0")
            self.skip("Skipping Span Check `trace_dd_service` for Span Attribute Schema v0")
            return

        if dd_config_env.get("DD_TRACE_HTTP_CLIENT_SPLIT_BY_DOMAIN", False) or dd_config_env.get(
            "DD_TRACE_DB_CLIENT_SPLIT_BY_INSTANCE", False
        ):
            log.debug(
                f"Skipped ``DD_SERVICE`` Span Check for trace with SPLIT_BY config variable set within config: \n   {json.dumps(dd_config_env, indent=4)}."
            )
            self.skip(
                f"Skipped ``DD_SERVICE`` Span Check for trace with SPLIT_BY config variable set within config: \n   {json.dumps(dd_config_env, indent=4)}."
            )
            return

        for span in trace:
            meta = span.get("meta", {})
            for component in whitelisted_components:
                if component in meta.get("component", ""):
                    skipped_component = meta.get("component", "")
                    log.debug(
                        f"Skipped ``DD_SERVICE`` Span Check for Span: {span['name']} with component {skipped_component}."
                    )
                    self.skip(
                        f"Skipped ``DD_SERVICE`` Span Check for Span: {span['name']} with component {skipped_component}."
                    )
                    return

            component = meta.get("component", "")
            if component != "":
                dd_service = dd_config_env.get(f"DD_{component.upper()}_SERVICE", None)
                if not dd_service:
                    log.error("DD_SERVICE not set for component: %s. Args %s", component, dd_config_env)
                dd_service = dd_service or dd_config_env.get("DD_SERVICE", None)
                if dd_service is None:
                    self.fail(
                        json.dumps(dd_config_env, indent=4)
                        + f"\n``DD_SERVICE`` env not set for Span: {span['name']} with service: {span['service']}."
                    )

                service = span.get("service")
                if service != dd_service:
                    # check for special case where span is of type web and has context as service
                    if "servlet.context" in meta.keys() or trace_context:
                        trace_context = (
                            trace_context
                            if trace_context is not None
                            else meta.get("servlet.context", "").replace("/", "")
                        )
                        if service != trace_context:
                            self.fail(
                                json.dumps(span, indent=4)
                                + f"\nSpan: {span['name']} expected to have ``service`` name equal to context of ``{trace_context}``. Actual: {service}."
                            )
                        elif span.get("type") in ["web", "http"]:
                            log.debug(
                                f"Skipped ``DD_SERVICE`` Span Check for Span: {span['name']} of type: [`web`, `http`]"
                            )
                            self.skip(
                                f"Skipped ``DD_SERVICE`` Span Check for Span: {span['name']} of type: [`web`, `http`]"
                            )
                            pass
                    else:
                        self.fail(
                            json.dumps(span, indent=4)
                            + f"\nSpan: {span['name']} expected to have ``service`` name equal to DD_SERVICE of ``{dd_service}``. Actual: {service}."
                        )
                else:
                    log.debug(f"Successfully completed ``service`` name Span Check for Span: {span['name']}")
        return
