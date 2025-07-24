import argparse
import atexit
import base64
from collections import OrderedDict
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
import json
import logging
import os
import pprint
import re
import socket
import sys
from typing import Awaitable
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Literal
from typing import Mapping
from typing import Optional
from typing import Set
from typing import Tuple
from typing import cast
from urllib.parse import urlparse
from urllib.parse import urlunparse

from aiohttp import ClientResponse
from aiohttp import ClientSession
from aiohttp import web
from aiohttp.web import HTTPException
from aiohttp.web import Request
from aiohttp.web import middleware
from msgpack.exceptions import ExtraData as MsgPackExtraDataException
from multidict import CIMultiDict

from . import _get_version
from . import trace_snapshot
from . import tracestats_snapshot
from .apmtelemetry import TelemetryEvent
from .apmtelemetry import v2_decode_request as v2_apmtelemetry_decode_request
from .checks import CheckTrace
from .checks import Checks
from .checks import start_trace
from .integration import Integration
from .remoteconfig import RemoteConfigServer
from .trace import Span
from .trace import Trace
from .trace import TraceMap
from .trace import decode_v04 as trace_decode_v04
from .trace import decode_v05 as trace_decode_v05
from .trace import decode_v07 as trace_decode_v07
from .trace import pprint_trace
from .trace import v04TracePayload
from .trace_checks import CheckMetaTracerVersionHeader
from .trace_checks import CheckTraceContentLength
from .trace_checks import CheckTraceCountHeader
from .trace_checks import CheckTraceDDService
from .trace_checks import CheckTracePeerService
from .trace_checks import CheckTraceStallAsync
from .tracerflare import TracerFlareEvent
from .tracerflare import v1_decode as v1_tracerflare_decode
from .tracestats import decode_v06 as tracestats_decode_v06
from .tracestats import v06StatsPayload
from .vcr_proxy import proxy_request
from .vcr_proxy import start_vcr_test
from .vcr_proxy import stop_vcr_test


class NoSuchSessionException(Exception):
    pass


_Handler = Callable[[Request], Awaitable[web.Response]]


log = logging.getLogger(__name__)


def _parse_csv(s: str) -> List[str]:
    """Return the values of a csv string.

    >>> _parse_csv("a,b,c")
    ['a', 'b', 'c']
    >>> _parse_csv(" a, b ,c ")
    ['a', 'b', 'c']
    >>> _parse_csv(" a,b,c ")
    ['a', 'b', 'c']
    >>> _parse_csv(" a,")
    ['a']
    >>> _parse_csv("a, ")
    ['a']
    """
    return [s.strip() for s in s.split(",") if s.strip() != ""]


def _parse_map(s: str) -> Dict[str, str]:
    """Return the values of a csv string.

    >>> _parse_map("a:b,b:c,c:d")
    {'a': 'b', 'b': 'c', 'c': 'd'}
    """
    return dict([s.strip().split(":", 1) for s in s.split(",") if s.strip()])


def _session_token(request: Request) -> Optional[str]:
    token: Optional[str]
    if "X-Datadog-Test-Session-Token" in request.headers:
        token = request.headers["X-Datadog-Test-Session-Token"]
    elif "test_session_token" in request.url.query:
        token = request.url.query.get("test_session_token")
    else:
        token = None
    return token


@middleware
async def session_token_middleware(request: Request, handler: _Handler) -> web.Response:
    """Extract session token from the request and store it in the request.

    The token is retrieved from the headers or params of the request.
    """
    token = _session_token(request)
    request["session_token"] = token
    return await handler(request)


@middleware
async def handle_exception_middleware(request: Request, handler: _Handler) -> web.Response:
    """Turn exceptions into 400s with the reason from the exception."""
    try:
        response = await handler(request)
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise web.HTTPBadRequest(reason=str(e))


async def _forward_request(
    request_data: bytes, headers: Mapping[str, str], full_agent_url: str
) -> tuple[ClientResponse, str]:
    async with ClientSession() as session:
        async with session.post(
            full_agent_url,
            headers=headers,
            data=request_data,
        ) as resp:
            assert resp.status == 200, f"Request to agent unsuccessful, received [{resp.status}] response."

            if "text/plain" in resp.content_type:
                response_data = await resp.text()
                log.info("Response %r from agent:", response_data)
            else:
                raw_response_data = await resp.read()
                if len(raw_response_data) == 0:
                    log.info("Received empty response: %r from agent.", raw_response_data)
                    response_data = ""
                else:
                    if isinstance(raw_response_data, bytes):
                        response_data = raw_response_data.decode()
                    try:
                        response_data = json.dumps(json.loads(raw_response_data))
                    except json.JSONDecodeError as e:
                        log.warning("Error decoding response data: %s, data=%r", str(e), response_data)
                        log.warning("Original Request: %r", request_data)
                        response_data = ""
                    log.info("Response %r from agent:", response_data)
            return resp, response_data


async def _prepare_and_send_request(data: bytes, request: Request, headers: Mapping[str, str]) -> web.Response:
    headers = {
        "Content-Type": headers.get("Content-Type", "application/msgpack"),
        **{k: v for k, v in headers.items() if k.lower() not in ["content-type", "host", "transfer-encoding"]},
    }
    agent_url = request.app["agent_url"]
    full_agent_url = agent_url + request.path
    log.info("Forwarding request to agent at %r", full_agent_url)
    log.debug(f"Using headers: {headers}")

    (client_response, body) = await _forward_request(data, headers, full_agent_url)
    return web.Response(
        status=client_response.status,
        headers=client_response.headers,
        body=body,
    )


def update_trace_agent_port(url, new_port):
    # Updates the Agent URL with a new port number, returning the updated URL and old port
    parsed_url = urlparse(url)
    old_port = parsed_url.port
    new_netloc = parsed_url.netloc.replace(f":{old_port}", f":{new_port}")
    new_url = urlunparse(
        (parsed_url.scheme, new_netloc, parsed_url.path, parsed_url.params, parsed_url.query, parsed_url.fragment)
    )
    return new_url


def default_value_trace_check_results_by_check():
    return defaultdict(default_value_trace_results_summary)


def default_value_trace_failures():
    return []


def default_value_trace_results_summary():
    return {
        "Passed_Checks": 0,
        "Failed_Checks": 0,
        "Skipped_Checks": 0,
    }


@dataclass
class _AgentSession:
    """Maintain Agent state across requests."""

    sample_rate_by_service_env: Dict[str, float] = field(default_factory=dict)


class Agent:
    def __init__(self) -> None:
        """
        Try to only store the requests sent to the agent. There are many representations
        of data but typically information is lost while transforming the data so it is best
        to keep the original and compute transformation when needed.
        """
        # Token to be used if running test cases synchronously
        self._requests: List[Request] = []
        self._rc_server = RemoteConfigServer()
        self._trace_failures: Dict[str, List[Tuple[CheckTrace, str]]] = defaultdict(default_value_trace_failures)
        self._trace_check_results_by_check: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
            default_value_trace_check_results_by_check
        )
        self._forward_endpoints: List[str] = [
            "/v0.4/traces",
            "/v0.5/traces",
            "/v0.7/traces",
            "/v0.6/stats",
            "/v0.7/config",
            "/telemetry/proxy/api/v2/apmtelemetry",
            "/v0.1/pipeline_stats",
            "/tracer_flare/v1",
            "/evp_proxy/v2/api/v2/llmobs",
            "/evp_proxy/v2/api/intake/llm-obs/v1/eval-metric",
            "/evp_proxy/v2/api/intake/llm-obs/v2/eval-metric",
        ]

        # Note that sessions are not cleared at any point since we don't know
        # definitively when a session is over.
        self._sessions: DefaultDict[Optional[str], _AgentSession] = defaultdict(
            lambda: _AgentSession(sample_rate_by_service_env={})
        )

    async def traces(self) -> TraceMap:
        """Return the traces stored by the agent in the order in which they
        arrived.

        Spans from trace chunks are aggregated by trace id and returned as
        complete lists.
        """
        _traces: TraceMap = OrderedDict()
        for req in reversed(self._requests):
            traces = await self._traces_from_request(req)
            for t in traces:
                for s in t:
                    trace_id = s["trace_id"]
                    if trace_id not in _traces:
                        _traces[trace_id] = []
                    _traces[trace_id].append(s)
        return _traces

    async def clear_trace_check_failures(self, request: Request) -> web.Response:
        """Clear traces by session token provided."""
        token = request["session_token"]
        clear_all = "clear_all" in request.query and request.query["clear_all"].lower() == "true"
        if clear_all:
            failures_by_token = self._trace_failures
            trace_failures = [value for sublist in failures_by_token.values() for value in sublist]
            self._trace_failures = defaultdict(default_value_trace_failures)
            self._trace_check_results_by_check = defaultdict(default_value_trace_check_results_by_check)
        else:
            trace_failures = self._trace_failures[token]
            del self._trace_failures[token]
            del self._trace_check_results_by_check[token]
        log.info(f"Clearing {len(trace_failures)} Trace Check Failures for Token {token}, clear_all={clear_all}")
        log.info(trace_failures)
        return web.HTTPOk()

    async def get_trace_check_failures(self, request: Request) -> web.Response:
        """Return the Trace Check failures that occurred, if pooling is enabled,
        returned as either a Text (by default) or JSON response.
        """
        token = request["session_token"]
        return_all = "return_all" in request.query and request.query["return_all"].lower() == "true"

        if return_all:
            # check for whether to return all results
            trace_check_failures = []
            for f in self._trace_failures.values():
                trace_check_failures.extend(f)
            n_failures = len(trace_check_failures)
            log.info(f"{n_failures} Trace Failures Occurred in Total")
        else:
            # or return results by token
            trace_check_failures = self._trace_failures.get(token, [])
            n_failures = len(trace_check_failures)
            log.info(f"{n_failures} Trace Failures Occurred for Token {token}")
        if n_failures > 0:
            if "use_json" in request.query and request.query["use_json"].lower() == "true":
                # check what response type to use
                results: Dict[str, List[str]] = {}
                for check_trace, failure_message in trace_check_failures:
                    results = check_trace.get_failures_by_check(results)
                json_summary = json.dumps(results)
                raise web.HTTPBadRequest(body=json_summary, content_type="application/json")
            else:
                # or use default response of text
                msg = f"APM Test Agent Validation failed with {n_failures} Trace Check failures.\n"
                for check_trace, failure_message in trace_check_failures:
                    msg += failure_message
                raise web.HTTPBadRequest(text=msg)
        else:
            return web.HTTPOk()

    async def get_trace_check_summary(self, request: Request) -> web.Response:
        token = request["session_token"]
        summary: Dict[str, Dict[str, int]] = defaultdict(default_value_trace_results_summary)
        return_all = "return_all" in request.query and request.query["return_all"].lower() == "true"

        if return_all:
            for token, token_results in self._trace_check_results_by_check.items():
                for check_name, check_results in token_results.items():
                    summary[check_name]["Passed_Checks"] += check_results["Passed_Checks"]
                    summary[check_name]["Failed_Checks"] += check_results["Failed_Checks"]
                    summary[check_name]["Skipped_Checks"] += check_results["Skipped_Checks"]
        else:
            summary = self._trace_check_results_by_check.get(token, {})
        json_summary = json.dumps(summary)
        return web.HTTPOk(body=json_summary, content_type="application/json")

    async def apmtelemetry(self) -> List[TelemetryEvent]:
        """Return the telemetry events stored by the agent"""
        _events: List[TelemetryEvent] = []
        for req in reversed(self._requests):
            if req.match_info.handler == self.handle_v2_apmtelemetry:
                _events.append(await v2_apmtelemetry_decode_request(req, await req.read()))
        return _events

    async def _trace_by_trace_id(self, trace_id: int) -> Trace:
        return (await self.traces())[trace_id]

    async def _apmtelemetry_by_runtime_id(self, runtime_id: str) -> List[TelemetryEvent]:
        return [event for event in await self.apmtelemetry() if event["runtime_id"] == runtime_id]

    async def _store_request(self, request: Request) -> None:
        """Store the request object so that it can be queried later."""
        # Store the request data on the request object to avoid concurrent read()s of the data which can
        # result in: RuntimeError: readany() called while another coroutine is already waiting for incoming data
        # See: https://github.com/DataDog/dd-apm-test-agent/pull/101 for more info
        request["_testagent_data"] = await request.read()
        self._requests.append(request)

    def _request_data(self, request: Request) -> bytes:
        """Return the data from the request.

        Note *only* use this method for requests stored with `_store_request()`.
        """
        return cast(bytes, request["_testagent_data"])

    def _requests_by_session(self, token: Optional[str]) -> List[Request]:
        """Return the latest requests sent with the given token.

        All requests since the most recent /session/start request are included.

        If no /session/start is given for the token then all requests made with
        the token are returned.
        """
        # Go backwards in the requests received gathering requests until
        # the /session-start request for the token is found.
        # Note that this may not return all associated traces, because some
        # may be generated before the session-start call
        session_reqs: List[Tuple[int, Request]] = []
        sessionless_reqs: List[Tuple[int, Request]] = []
        matched = token is None

        for i, req in enumerate(reversed(self._requests)):
            if req.match_info.handler == self.handle_session_start:
                if token is None:
                    # If no token is specified, then we match the latest session
                    break
                elif _session_token(req) == token:
                    # If a token is specified and it matches, we've hit the start of our session
                    matched = True
                    break
                elif _session_token(req) != token:
                    # If a token is specified and it doesn't match, we've hit the start of a different session
                    # So we reset the list of requests
                    sessionless_reqs = []
                    continue
            if _session_token(req) == token:
                session_reqs.append((i, req))
            elif _session_token(req) is None:
                sessionless_reqs.append((i, req))

        if not matched and not session_reqs:
            raise NoSuchSessionException(f"No session found for token '{token}'")
        return [x[1] for x in sorted(session_reqs + sessionless_reqs, key=lambda x: x[0])]

    async def _traces_from_request(self, req: Request) -> List[List[Span]]:
        """Return the trace from a trace request."""
        if req.match_info.handler == self.handle_v04_traces:
            return self._decode_v04_traces(req)
        elif req.match_info.handler == self.handle_v05_traces:
            return self._decode_v05_traces(req)
        elif req.match_info.handler == self.handle_v07_traces:
            return self._decode_v07_traces(req)
        return []

    async def _traces_by_session(self, token: Optional[str]) -> List[Trace]:
        """Return the traces that belong to the given session token.

        If token is None or if the token was used to manually start a session
        with /session-start then return all traces that were sent since the last
        /session-start request was made.

        Spans are aggregated by trace_id (no ordering is performed).
        """
        tracemap: TraceMap = OrderedDict()
        for req in self._requests_by_session(token):
            traces = await self._traces_from_request(req)
            for trace in traces:
                for span in trace:
                    trace_id = span["trace_id"]
                    if trace_id not in tracemap:
                        tracemap[trace_id] = []
                    tracemap[trace_id].append(span)
        return list(tracemap.values())

    async def _apmtelemetry_by_session(self, token: Optional[str]) -> List[TelemetryEvent]:
        """Return the telemetry events that belong to the given session token.

        If token is None or if the token was used to manually start a session
        with /session-start then return all telemetry events that were sent since
        the last /session-start request was made.
        """
        events: List[TelemetryEvent] = []
        for req in self._requests_by_session(token):
            if req.match_info.handler == self.handle_v2_apmtelemetry:
                events.append(await v2_apmtelemetry_decode_request(req, await req.read()))

        # TODO: Sort the events?
        return events

    async def _tracerflares_by_session(self, token: Optional[str]) -> List[TracerFlareEvent]:
        """Return the tracer-flare events that belong to the given session token.

        If token is None or if the token was used to manually start a session
        with /session-start then return all tracer-flare events that were sent
        since the last /session-start request was made.
        """
        events: List[TracerFlareEvent] = []
        for req in self._requests_by_session(token):
            if req.match_info.handler == self.handle_v1_tracer_flare:
                events.append(await v1_tracerflare_decode(req, await req.read()))
        return events

    async def _tracestats_by_session(self, token: Optional[str]) -> List[v06StatsPayload]:
        stats: List[v06StatsPayload] = []
        for req in self._requests_by_session(token):
            if req.match_info.handler == self.handle_v06_tracestats:
                s = self._decode_v06_tracestats(req)
                stats.append(s)
        return stats

    async def _integration_requests_by_session(
        self,
        token: Optional[str],
        include_sent_integrations: Optional[bool] = False,
    ) -> List[Request]:
        """Get all requests with an associated tested Integration."""
        integration_requests: List[Request] = []
        requests = self._requests if token is None else self._requests_by_session(token)
        for req in requests:
            # see if the request was to update with a newly tested integration
            if req.match_info.handler == self.handle_put_tested_integrations:
                if "integration" not in req:
                    data = json.loads(await req.read())
                    integration_name = data.get("integration_name", None)
                    integration_version = data.get("integration_version", None)
                    req["integration"] = Integration(
                        integration_name=integration_name,
                        integration_version=integration_version,
                        dependency_name=data.get("dependency_name", integration_name),
                    )
                    req["tracer_version"] = data.get("tracer_version", None)
                    req["tracer_language"] = data.get("tracer_language", None)
                    integration_requests.append(req)
                elif include_sent_integrations:
                    integration_requests.append(req)
            # check if integration data was provided in the trace request instead
            elif (
                "_dd_trace_env_variables" in req
                and "DD_INTEGRATION" in req["_dd_trace_env_variables"]
                and "DD_INTEGRATION_VERSION" in req["_dd_trace_env_variables"]
            ):
                integration_name = req["_dd_trace_env_variables"]["DD_INTEGRATION"]
                integration_version = req["_dd_trace_env_variables"]["DD_INTEGRATION_VERSION"]

                if "integration" not in req:
                    req["integration"] = Integration(
                        integration_name=integration_name,
                        integration_version=integration_version,
                        dependency_name=req["_dd_trace_env_variables"].get("DD_DEPENDENCY_NAME", integration_name),
                    )

                    if req.headers.get("dd-client-library-version", None):
                        req["tracer_version"] = req.headers.get("dd-client-library-version")
                    elif req.headers.get("datadog-meta-tracer-version", None):
                        req["tracer_version"] = req.headers.get("datadog-meta-tracer-version")

                    if req.headers.get("dd-client-library-language", None):
                        req["tracer_language"] = req.headers.get("dd-client-library-language")
                    elif req.headers.get("datadog-meta-lang", None):
                        req["tracer_language"] = req.headers.get("datadog-meta-lang")
                    integration_requests.append(req)
                elif include_sent_integrations:
                    integration_requests.append(req)
        return integration_requests

    def _decode_v04_traces(self, request: Request) -> v04TracePayload:
        content_type = request.content_type
        raw_data = self._request_data(request)
        return trace_decode_v04(content_type, raw_data, request.app["suppress_trace_parse_errors"])

    def _decode_v05_traces(self, request: Request) -> v04TracePayload:
        raw_data = self._request_data(request)
        return trace_decode_v05(raw_data)

    def _decode_v07_traces(self, request: Request) -> v04TracePayload:
        raw_data = self._request_data(request)
        return trace_decode_v07(raw_data)

    def _decode_v06_tracestats(self, request: Request) -> v06StatsPayload:
        raw_data = self._request_data(request)
        return tracestats_decode_v06(raw_data)

    async def handle_v04_traces(self, request: Request) -> web.Response:
        return await self._handle_traces(request, version="v0.4")

    async def handle_v05_traces(self, request: Request) -> web.Response:
        return await self._handle_traces(request, version="v0.5")

    async def handle_v07_traces(self, request: Request) -> web.Response:
        return await self._handle_traces(request, version="v0.7")

    async def handle_v06_tracestats(self, request: Request) -> web.Response:
        stats = self._decode_v06_tracestats(request)
        nstats = len(stats["Stats"])
        log.info(
            "received /v0.6/stats payload with %r stats bucket%s",
            nstats,
            "s" if nstats else "",
        )
        return web.HTTPOk()

    async def handle_v01_pipelinestats(self, request: Request) -> web.Response:
        log.info("received /v0.1/pipeline_stats payload")
        return web.HTTPOk()

    async def handle_v07_remoteconfig(self, request: Request) -> web.Response:
        """Emulates Remote Config endpoint: /v0.7/config"""
        token = _session_token(request)
        data = await self._rc_server.get_config_response(token)
        return web.json_response(data)

    async def handle_v07_remoteconfig_create(self, request: Request) -> web.Response:
        """Configure the response payload of /v0.7/config."""
        raw_data = await request.read()
        token = _session_token(request)
        self._rc_server.create_config_response(token, json.loads(raw_data))
        return web.HTTPAccepted()

    async def handle_v07_remoteconfig_path_create(self, request: Request) -> web.Response:
        """
        Remote Config payloads are quite complex. This endpoints builds a remote config payload with a target
        file path and the content of it (msg)
        """
        raw_data = await request.read()
        content = json.loads(raw_data)
        path = content["path"]
        msg = content["msg"]
        token = _session_token(request)
        self._rc_server.create_config_path_response(token, path, msg)
        return web.HTTPAccepted()

    async def handle_v07_remoteconfig_put(self, request: Request) -> web.Response:
        """Configure the response payload of /v0.7/config"""
        raw_data = await request.read()
        token = _session_token(request)
        self._rc_server.update_config_response(token, json.loads(raw_data))
        return web.HTTPAccepted()

    async def handle_v2_apmtelemetry(self, request: Request) -> web.Response:
        await v2_apmtelemetry_decode_request(request, self._request_data(request))
        # TODO: Validation
        # TODO: Snapshots
        return web.HTTPOk()

    async def handle_v1_tracer_flare(self, request: Request) -> web.Response:
        tracer_flare: TracerFlareEvent = await v1_tracerflare_decode(request, self._request_data(request))

        if "error" in tracer_flare:
            msg = f"Error while parsing flare request: {tracer_flare['error']}"
            log.error(msg)
            raise web.HTTPBadRequest(text=msg)

        expectedFields = ["source", "case_id", "email", "hostname", "flare_file"]
        missingFields = [k for k in expectedFields if k not in tracer_flare]

        if len(missingFields) == 0:
            return web.HTTPOk()
        else:
            msg = f"Flare request is missing {','.join(missingFields)}"
            log.error(msg)
            raise web.HTTPBadRequest(text=msg)

    async def handle_evp_proxy_v2_api_v2_llmobs(self, request: Request) -> web.Response:
        return web.HTTPOk()

    async def handle_evp_proxy_v2_llmobs_eval_metric(self, request: Request) -> web.Response:
        return web.HTTPOk()

    async def handle_put_tested_integrations(self, request: Request) -> web.Response:
        # we need to store the request manually since this is not a real DD agent endpoint
        await self._store_request(request)
        return web.HTTPOk()

    async def handle_get_tested_integrations(self, request: Request) -> web.Response:
        """Return all tested integrations according to integration data received by agent."""
        text_headers = ["language_name", "tracer_version", "integration_name", "integration_version", "dependency_name"]
        aggregated_text = ""
        seen_integrations = set()
        req_headers = {}
        token = _session_token(request)

        # get all requests associated with an integration
        reqs = await self._integration_requests_by_session(token=token, include_sent_integrations=True)
        for req in reqs:
            integration = req["integration"]

            # only include the integration in response if all data is included and integration hasn't already been added
            if (
                integration.integration_name
                and integration.integration_version
                and integration.dependency_name
                and req["tracer_language"]
                and req["tracer_version"]
                and f"{integration.integration_name}@{integration.integration_version}" not in seen_integrations
            ):
                aggregated_text += (
                    ",".join(
                        [
                            req["tracer_language"],
                            ".".join(req["tracer_version"].split("-")[0].split(".")[0:3]),  # ensure semver
                            integration.integration_name,
                            integration.integration_version,
                            integration.dependency_name,
                        ]
                    )
                    + "\n"
                )
                # update seen integrations to skip this specific integration and version next loop from another request
                seen_integrations.add(f"{integration.integration_name}@{integration.integration_version}")
                # given that we will mainly see one integration per call, set a header for the calling lib to know the
                # integration name
                req_headers["file-name"] = integration.integration_name
        if len(aggregated_text) > 0:
            aggregated_text = ",".join(text_headers) + "\n" + aggregated_text
        return web.Response(body=aggregated_text, content_type="text/plain", headers=req_headers)

    async def handle_settings(self, request: Request) -> web.Response:
        """Allow to change test agent settings on the fly"""
        raw_data = await request.read()
        data = json.loads(raw_data)

        # First pass to validate the data
        for key in data:
            if key not in request.app:
                return web.HTTPUnprocessableEntity(text=f"Unknown key: '{key}'")

        # Second pass to apply the config
        for key in data:
            request.app[key] = data[key]

        return web.HTTPAccepted()

    async def handle_info(self, request: Request) -> web.Response:
        return web.json_response(
            {
                "version": "test",
                "endpoints": [
                    "/v0.4/traces",
                    "/v0.5/traces",
                    "/v0.7/traces",
                    "/v0.6/stats",
                    "/telemetry/proxy/",
                    "/v0.7/config",
                    "/tracer_flare/v1",
                    "/evp_proxy/v2/",
                ],
                "feature_flags": [],
                "config": {},
                "client_drop_p0s": True,
                # Just a random selection of some peer_tags to aggregate on for testing, not exhaustive
                "peer_tags": ["db.name", "mongodb.db", "messaging.system"],
                "span_events": True,  # Advertise support for the top-level Span field for Span Events
            },
            headers={"Datadog-Agent-State": "03e868b3ecdd62a91423cc4c3917d0d151fb9fa486736911ab7f5a0750c63824"},
        )

    async def _handle_traces(self, request: Request, version: Literal["v0.4", "v0.5", "v0.7"]) -> web.Response:
        token = request["session_token"]
        checks: Checks = request.app["checks"]
        headers = request.headers

        # TODO: This method requires all checks are hard coded

        await checks.check("trace_stall", headers=headers, request=request)

        with CheckTrace.add_frame("headers") as f:
            f.add_item(pprint.pformat(dict(headers)))
            await checks.check("meta_tracer_version_header", headers=headers)
            await checks.check("trace_content_length", headers=headers)

            try:
                if version == "v0.4":
                    traces = self._decode_v04_traces(request)
                elif version == "v0.5":
                    traces = self._decode_v05_traces(request)
                elif version == "v0.7":
                    traces = self._decode_v07_traces(request)
                log.info(
                    "received trace for token %r payload with %r trace chunks",
                    token,
                    len(traces),
                )
                for i, trace in enumerate(traces):
                    try:
                        log.info(
                            "Chunk %d\n%s",
                            i,
                            pprint_trace(trace, request.app["log_span_fmt"]),
                        )
                    except ValueError:
                        log.info("Chunk %d could not be displayed (might be incomplete).", i)

                    # perform peer service check on span
                    for span in trace:
                        await checks.check(
                            "trace_peer_service", span=span, dd_config_env=request.get("_dd_trace_env_variables", {})
                        )

                    await checks.check(
                        "trace_dd_service", trace=trace, dd_config_env=request.get("_dd_trace_env_variables", {})
                    )
                log.info("end of payload %s", "-" * 40)

                with CheckTrace.add_frame(f"payload ({len(traces)} traces)"):
                    await checks.check(
                        "trace_count_header",
                        headers=headers,
                        num_traces=len(traces),
                    )
            except MsgPackExtraDataException as e:
                log.error(f"Error unpacking trace bytes with Msgpack: {str(e)}, error {e}")

        return web.json_response(data={"rate_by_service": self._sessions[token].sample_rate_by_service_env})

    async def handle_session_start(self, request: Request) -> web.Response:
        rates = json.loads(request.url.query.get("agent_sample_rate_by_service", "{}"))
        self._requests.append(request)
        session = self._sessions[_session_token(request)]
        session.sample_rate_by_service_env = rates
        log.info("Starting new session with token %r: %r", _session_token(request), session)
        return web.HTTPOk()

    async def handle_snapshot(self, request: Request) -> web.Response:
        """Generate a snapshot or perform a snapshot test."""
        token = request["session_token"]
        snap_dir = request.url.query.get("dir", request.app["snapshot_dir"])
        snap_ci_mode = request.app["snapshot_ci_mode"]
        log.info(
            "performing snapshot with token=%r, ci_mode=%r and snapshot directory=%r",
            token,
            snap_ci_mode,
            snap_dir,
        )

        # Get the span attributes that are to be ignored for this snapshot.
        default_span_ignores: Set[str] = request.app["snapshot_ignored_attrs"]
        overrides = set(_parse_csv(request.url.query.get("ignores", "")))
        span_ignores = list(default_span_ignores | overrides)
        log.info("using ignores %r", span_ignores)

        # Get the span attributes that are to be removed for this snapshot.
        default_span_removes: Set[str] = request.app["snapshot_removed_attrs"]
        overrides = set(_parse_csv(request.url.query.get("removes", "")))
        span_removes = list(default_span_removes | overrides)
        log.info("using removes %r", span_removes)

        # Get the span attributes that are to be removed for this snapshot.
        default_attribute_regex_replaces: Dict[str, str] = request.app["snapshot_regex_placeholders"]
        regex_overrides = _parse_map(request.url.query.get("regex_placeholders", ""))
        attribute_regex_replaces = dict(
            (f"{{{key}}}", re.compile(regex))
            for (key, regex) in (default_attribute_regex_replaces | regex_overrides).items()
        )
        log.info("using regex placeholders %r", attribute_regex_replaces)

        if "span_id" in span_removes:
            raise AssertionError("Cannot remove 'span_id' from spans")

        with CheckTrace.add_frame(f"snapshot (token='{token}')") as frame:
            frame.add_item(f"Directory: {snap_dir}")
            frame.add_item(f"CI mode: {snap_ci_mode}")

            if "X-Datadog-Test-Snapshot-Filename" in request.headers:
                snap_file = request.headers["X-Datadog-Test-Snapshot-Filename"]
            elif "file" in request.url.query:
                snap_file = request.url.query["file"]
            else:
                snap_file = os.path.join(snap_dir, token)

            # The logic from here is mostly duplicated for traces and trace stats.
            # If another data type is to be snapshotted then it probably makes sense to abstract away
            # the required pieces of snapshotting (loading, generating and comparing).

            # For backwards compatibility traces don't have a postfix of `_trace.json`
            trace_snap_file = f"{snap_file}.json"
            tracestats_snap_file = f"{snap_file}_tracestats.json"

            frame.add_item(f"Trace File: {trace_snap_file}")
            frame.add_item(f"Stats File: {tracestats_snap_file}")
            log.info("using snapshot files %r and %r", trace_snap_file, tracestats_snap_file)

            trace_snap_path_exists = os.path.exists(trace_snap_file)

            received_traces = await self._traces_by_session(token)
            if snap_ci_mode and received_traces and not trace_snap_path_exists:
                raise AssertionError(
                    f"Trace snapshot file '{trace_snap_file}' not found. "
                    "Perhaps the file was not checked into source control? "
                    "The snapshot file is automatically generated when the test agent is not in CI mode."
                )
            elif trace_snap_path_exists:
                # Do the snapshot comparison
                with open(trace_snap_file, mode="r") as f:
                    raw_snapshot = json.load(f)
                trace_snapshot.snapshot(
                    expected_traces=raw_snapshot,
                    received_traces=received_traces,
                    ignored=span_ignores,
                    attribute_regex_replaces=attribute_regex_replaces,
                )
            elif received_traces:
                # Create a new snapshot for the data received
                with open(trace_snap_file, mode="w") as f:
                    f.write(
                        trace_snapshot.generate_snapshot(
                            received_traces=received_traces,
                            removed=span_removes,
                            attribute_regex_replaces=attribute_regex_replaces,
                        )
                    )
                log.info("wrote new trace snapshot to %r", os.path.abspath(trace_snap_file))

            # Get all stats buckets from the payloads since we don't care about the other fields (hostname, env, etc)
            # in the payload.
            received_stats = [bucket for p in (await self._tracestats_by_session(token)) for bucket in p["Stats"]]
            tracestats_snap_path_exists = os.path.exists(tracestats_snap_file)
            if snap_ci_mode and received_stats and not tracestats_snap_path_exists:
                raise AssertionError(
                    f"Trace stats snapshot file '{tracestats_snap_file}' not found. "
                    "Perhaps the file was not checked into source control? "
                    "The snapshot file is automatically generated when the test case is run when not in CI mode."
                )
            elif tracestats_snap_path_exists:
                # Do the snapshot comparison
                with open(tracestats_snap_file, mode="r") as f:
                    raw_snapshot = json.load(f)
                tracestats_snapshot.snapshot(
                    expected_stats=raw_snapshot,
                    received_stats=received_stats,
                )
            elif received_stats:
                # Create a new snapshot for the data received
                with open(tracestats_snap_file, mode="w") as f:
                    f.write(tracestats_snapshot.generate(received_stats))
                log.info(
                    "wrote new tracestats snapshot to %r",
                    os.path.abspath(tracestats_snap_file),
                )
        return web.HTTPOk()

    async def handle_session_traces(self, request: Request) -> web.Response:
        token = request["session_token"]
        traces = []
        try:
            traces = await self._traces_by_session(token)
        except NoSuchSessionException as e:
            raise web.HTTPNotFound(reason=str(e))

        return web.json_response(traces)

    async def handle_session_apmtelemetry(self, request: Request) -> web.Response:
        token = request["session_token"]
        events = await self._apmtelemetry_by_session(token)
        return web.json_response(events)

    async def handle_session_tracerflares(self, request: Request) -> web.Response:
        token = request["session_token"]
        events = await self._tracerflares_by_session(token)
        return web.json_response(events)

    async def handle_session_tracestats(self, request: Request) -> web.Response:
        token = request["session_token"]
        stats = await self._tracestats_by_session(token)
        return web.json_response(stats)

    async def handle_session_requests(self, request: Request) -> web.Response:
        token = request["session_token"]
        resp = []
        for req in reversed(self._requests_by_session(token)):
            if req.match_info.handler not in (
                self.handle_v04_traces,
                self.handle_v05_traces,
                self.handle_v07_traces,
                self.handle_v06_tracestats,
                self.handle_v01_pipelinestats,
                self.handle_v2_apmtelemetry,
                self.handle_v1_profiling,
                self.handle_v07_remoteconfig,
                self.handle_v1_tracer_flare,
                self.handle_evp_proxy_v2_api_v2_llmobs,
                self.handle_evp_proxy_v2_llmobs_eval_metric,
            ):
                continue
            resp.append(
                {
                    "headers": dict(req.headers),
                    "body": base64.b64encode(await req.read()).decode(),
                    "url": str(req.url),
                    "method": req.method,
                }
            )
        return web.json_response(resp)

    async def handle_test_traces(self, request: Request) -> web.Response:
        """Return requested traces as JSON.

        Traces can be requested by providing a header X-Datadog-Trace-Ids or
        a query param trace_ids.
        """
        raw_trace_ids = request.url.query.get("trace_ids", request.headers.get("X-Datadog-Trace-Ids", ""))
        if raw_trace_ids:
            trace_ids = map(int, raw_trace_ids.split(","))
            traces = []
            for tid in trace_ids:
                try:
                    traces.append(await self._trace_by_trace_id(tid))
                except KeyError:
                    traces.append([])
        else:
            traces = list((await self.traces()).values())
        return web.json_response(data=traces)

    async def handle_test_apmtelemetry(self, request: Request) -> web.Response:
        """Return requested telemetry events as JSON.

        Telemetry events can be requested by providing a header X-Datadog-Runtime-Ids or
        a query param runtime_ids.
        """
        raw_runtime_ids = request.url.query.get("runtime_ids", request.headers.get("X-Datadog-Runtime-Ids", ""))
        if raw_runtime_ids:
            runtime_ids = raw_runtime_ids.split(",")
            events: List[TelemetryEvent] = []
            for rid in runtime_ids:
                events.extend(await self._apmtelemetry_by_runtime_id(rid))
        else:
            events = await self.apmtelemetry()
        return web.json_response(data=events)

    async def handle_v1_profiling(self, request: Request) -> web.Response:
        await request.read()
        self._requests.append(request)
        # TODO: valid response?
        return web.HTTPOk()

    async def handle_session_clear(self, request: Request) -> web.Response:
        """Clear traces by session token or all traces if none is provided."""
        session_token = request["session_token"]
        if session_token is not None:
            # Clear any synchronous sessions.
            in_token_sync_session = False
            for req in self._requests:
                if req.match_info.handler == self.handle_session_start:
                    if _session_token(req) == session_token:
                        in_token_sync_session = True
                        continue  # Don't clear the session start
                    else:
                        in_token_sync_session = False
                if in_token_sync_session:
                    setattr(req, "__delete", True)

            # Filter out all requests marked for deletion.
            # Keep session starts.
            self._requests = [
                r
                for r in self._requests
                if (_session_token(r) != session_token or r.match_info.handler == self.handle_session_start)
                and not hasattr(r, "__delete")
            ]
        else:
            self._requests = []
        return web.HTTPOk()

    async def handle_trace_analyze(self, request: Request) -> web.Response:
        # client.get("/span/start")
        # client.get("/span/tag")
        # client.get("/span/finish")
        # wait 1s, gather traces and assert tags
        raise NotImplementedError

    @middleware
    async def store_request_middleware(self, request: Request, handler: _Handler) -> web.Response:
        # only store requests for specific endpoints
        if request.path in self._forward_endpoints:
            await self._store_request(request)

        # Call the original handler
        return await handler(request)

    @middleware
    async def request_forwarder_middleware(self, request: Request, handler: _Handler) -> web.Response:
        headers = CIMultiDict(request.headers)

        if "X-Datadog-Trace-Env-Variables" in headers:
            var_string = headers.pop("X-Datadog-Trace-Env-Variables")
            env_vars = {
                key.strip(): value.strip() for key, value in (pair.split("=") for pair in var_string.split(","))
            }
            log.debug("Found the following Datadog Trace Env Variables: " + str(env_vars))
            request["_dd_trace_env_variables"] = env_vars

        if "X-Datadog-Agent-Proxy-Disabled" in headers:
            request["_proxy_to_agent"] = (
                headers.pop("X-Datadog-Agent-Proxy-Disabled").lower() != "true" and request.app["agent_url"] != ""
            )

        if "X-Datadog-Proxy-Port" in headers:
            port = headers.pop("X-Datadog-Proxy-Port")
            request.app["agent_url"] = update_trace_agent_port(request.app["agent_url"], new_port=port)
            log.info("Found port in headers, new trace agent URL is: {}".format(request.app["agent_url"]))

        request["_headers"] = headers
        if request.path in self._forward_endpoints:
            # forward the request then call the handler
            return await self._forward_request_to_agent(request, handler)
        else:
            # Call the original handler and do nothing
            return await handler(request)

    async def _forward_request_to_agent(self, request: Request, handler: _Handler) -> web.Response:
        """Forward all requests to the agent_url if set."""
        data = self._request_data(request)
        headers = request["_headers"]
        agent_url = request.app["agent_url"]
        proxy_to_agent = request.get("_proxy_to_agent", True)

        log.debug(f"New request: {request} with headers: {headers}")
        log.debug(f"Request Data: {data!r}")

        if agent_url and proxy_to_agent:
            agent_response = await _prepare_and_send_request(data, request, headers)

        endpoint_response = await handler(request)

        # return the agent response if this was sent to a trace endpoint
        endpoint_path = request.path
        if "traces" in endpoint_path and agent_url and proxy_to_agent:
            return agent_response
        else:
            return endpoint_response

    @middleware
    async def check_failure_middleware(self, request: Request, handler: _Handler) -> web.Response:
        """Convert any failed checks into an HttpException."""
        trace = start_trace("request %r" % request)
        try:
            response = await handler(request)
        except AssertionError as e:
            token = request["session_token"]

            # update trace_check results
            trace.update_results(self._trace_check_results_by_check[token])

            # only save trace failures to memory if necessary
            msg = str(trace) + str(e)
            if request.app["pool_trace_check_failures"]:
                log.info(f"Storing Trace Check Failure for Session Token: {token}.")
                # append failure to trace failures
                self._trace_failures[token].append((trace, msg))
            log.error(msg)
            raise web.HTTPBadRequest(body=msg)
        else:
            token = request["session_token"]
            # update trace_check results
            trace.update_results(self._trace_check_results_by_check[token])
            if trace.has_fails():
                # only save trace failures to memory if necessary
                pool_failures = request.app["pool_trace_check_failures"]
                log.error(
                    f"Trace had the following failures, using config: token={token}, DD_POOL_TRACE_CHECK_FAILURES={pool_failures}"
                )
                msg = str(trace)
                if request.app["pool_trace_check_failures"]:
                    log.info(f"Storing Trace Check Failure for Session Token: {token}.")
                    # append failure to trace failures
                    self._trace_failures[token].append((trace, msg))
                log.error(msg)
                if request.app["disable_error_responses"]:
                    return response
                raise web.HTTPBadRequest(body=msg)
        return response


def make_app(
    enabled_checks: List[str],
    log_span_fmt: str,
    snapshot_dir: str,
    snapshot_ci_mode: bool,
    snapshot_ignored_attrs: List[str],
    agent_url: str,
    trace_request_delay: float,
    suppress_trace_parse_errors: bool,
    pool_trace_check_failures: bool,
    disable_error_responses: bool,
    snapshot_removed_attrs: List[str],
    snapshot_regex_placeholders: Dict[str, str],
    vcr_cassettes_directory: str,
) -> web.Application:
    async def handle_vcr_proxy(request: Request) -> web.Response:
        return await proxy_request(request, vcr_cassettes_directory)
    
    agent = Agent()
    app = web.Application(
        client_max_size=int(100e6),  # 100MB - arbitrary
        middlewares=[
            handle_exception_middleware,  # type: ignore
            agent.check_failure_middleware,  # type: ignore
            agent.store_request_middleware,  # type: ignore
            agent.request_forwarder_middleware,  # type: ignore
            session_token_middleware,  # type: ignore
        ],
    )
    app.add_routes(
        [
            web.post("/v0.4/traces", agent.handle_v04_traces),
            web.put("/v0.4/traces", agent.handle_v04_traces),
            web.post("/v0.5/traces", agent.handle_v05_traces),
            web.put("/v0.5/traces", agent.handle_v05_traces),
            web.post("/v0.7/traces", agent.handle_v07_traces),
            web.put("/v0.7/traces", agent.handle_v07_traces),
            web.post("/v0.6/stats", agent.handle_v06_tracestats),
            web.post("/v0.1/pipeline_stats", agent.handle_v01_pipelinestats),
            web.put("/v0.6/stats", agent.handle_v06_tracestats),
            web.get("/v0.7/config", agent.handle_v07_remoteconfig),
            web.post("/v0.7/config", agent.handle_v07_remoteconfig),
            web.post("/telemetry/proxy/api/v2/apmtelemetry", agent.handle_v2_apmtelemetry),
            web.post("/profiling/v1/input", agent.handle_v1_profiling),
            web.post("/tracer_flare/v1", agent.handle_v1_tracer_flare),
            web.post("/evp_proxy/v2/api/v2/llmobs", agent.handle_evp_proxy_v2_api_v2_llmobs),
            web.post("/evp_proxy/v2/api/intake/llm-obs/v1/eval-metric", agent.handle_evp_proxy_v2_llmobs_eval_metric),
            web.post("/evp_proxy/v2/api/intake/llm-obs/v2/eval-metric", agent.handle_evp_proxy_v2_llmobs_eval_metric),
            web.get("/info", agent.handle_info),
            web.get("/test/session/start", agent.handle_session_start),
            web.get("/test/session/clear", agent.handle_session_clear),
            web.get("/test/session/snapshot", agent.handle_snapshot),
            web.get("/test/session/traces", agent.handle_session_traces),
            web.get("/test/session/apmtelemetry", agent.handle_session_apmtelemetry),
            web.get("/test/session/tracerflares", agent.handle_session_tracerflares),
            web.get("/test/session/stats", agent.handle_session_tracestats),
            web.get("/test/session/requests", agent.handle_session_requests),
            web.post("/test/session/responses/config", agent.handle_v07_remoteconfig_create),
            web.post("/test/session/responses/config/path", agent.handle_v07_remoteconfig_path_create),
            web.put("/test/session/responses/config", agent.handle_v07_remoteconfig_put),
            web.put("/test/session/integrations", agent.handle_put_tested_integrations),
            web.get("/test/traces", agent.handle_test_traces),
            web.get("/test/apmtelemetry", agent.handle_test_apmtelemetry),
            # web.get("/test/benchmark", agent.handle_test_traces),
            web.get("/test/trace/analyze", agent.handle_trace_analyze),
            web.get("/test/trace_check/failures", agent.get_trace_check_failures),
            web.get("/test/trace_check/clear", agent.clear_trace_check_failures),
            web.get("/test/trace_check/summary", agent.get_trace_check_summary),
            web.get("/test/integrations/tested_versions", agent.handle_get_tested_integrations),
            web.post("/test/settings", agent.handle_settings),
            web.post("/vcr/test/start", start_vcr_test),
            web.post("/vcr/test/stop", stop_vcr_test),
            web.route(
                "*",
                "/vcr/{path:.*}",
                handle_vcr_proxy,
            ),
        ]
    )
    checks = Checks(
        checks=[
            CheckMetaTracerVersionHeader,
            CheckTraceCountHeader,
            CheckTraceContentLength,
            CheckTraceStallAsync,
            CheckTracePeerService,
            CheckTraceDDService,
        ],
        enabled=enabled_checks,
    )
    app["checks"] = checks
    app["snapshot_dir"] = snapshot_dir
    app["snapshot_ci_mode"] = snapshot_ci_mode
    app["log_span_fmt"] = log_span_fmt
    app["snapshot_ignored_attrs"] = snapshot_ignored_attrs
    app["agent_url"] = agent_url
    app["trace_request_delay"] = trace_request_delay
    app["suppress_trace_parse_errors"] = suppress_trace_parse_errors
    app["pool_trace_check_failures"] = pool_trace_check_failures
    app["disable_error_responses"] = disable_error_responses
    app["snapshot_removed_attrs"] = snapshot_removed_attrs
    app["snapshot_regex_placeholders"] = snapshot_regex_placeholders
    app["vcr_cassettes_directory"] = vcr_cassettes_directory
    return app


def main(args: Optional[List[str]] = None) -> None:
    if args is None:
        args = sys.argv[1:]
    parser = argparse.ArgumentParser(
        description="Datadog APM test agent",
        prog="ddapm-test-agent",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        dest="version",
        help="Print version info and exit.",
    )
    parser.add_argument("-p", "--port", type=int, default=int(os.environ.get("PORT", 8126)))
    parser.add_argument(
        "--snapshot-dir",
        type=str,
        default=os.environ.get("SNAPSHOT_DIR", "snapshots"),
        help="Directory to store snapshots.",
    )
    parser.add_argument(
        "--snapshot-ci-mode",
        type=int,
        default=int(os.environ.get("SNAPSHOT_CI", 0)),
        help="Enable CI mode for snapshotting. Enforces that snapshot files exist.",
    )
    parser.add_argument(
        "--snapshot-ignored-attrs",
        type=Set[str],
        default=set(_parse_csv(os.environ.get("SNAPSHOT_IGNORED_ATTRS", trace_snapshot.DEFAULT_SNAPSHOT_IGNORES))),
        help=(
            "Comma-separated values of span attributes to ignore. "
            "meta/metrics attributes can be ignored by prefixing the key "
            "with meta. or metrics."
        ),
    )
    parser.add_argument(
        "--snapshot-removed-attrs",
        type=Set[str],
        default=set(_parse_csv(os.environ.get("SNAPSHOT_REMOVED_ATTRS", ""))),
        help=(
            "Comma-separated values of span attributes to remove. "
            "meta/metrics attributes can be removed by prefixing the key "
            "with meta. or metrics."
        ),
    )
    parser.add_argument(
        "--snapshot-regex-placeholders",
        type=_parse_map,
        default=os.environ.get("SNAPSHOT_REGEX_PLACEHOLDERS", ""),
        help=(
            "Comma-separated list of placeholder:regex tuples where to remove the matching regexes with the placeholder."
        ),
    )
    parser.add_argument(
        "--enabled-checks",
        type=List[str],
        default=_parse_csv(os.environ.get("ENABLED_CHECKS", "")),
        help=(
            "Comma-separated values of checks to enable. None are enabled "
            " by default. For the list of values see "
            "https://github.com/datadog/dd-trace-test-agent"
        ),
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Set the log level. DEBUG, INFO, WARNING, ERROR, CRITICAL.",
    )
    parser.add_argument(
        "--log-span-fmt",
        type=str,
        default=os.environ.get("LOG_SPAN_FMT", "[{name}]"),
        help=("Format to use when logging spans. Default is '[{name}]'. " "All span attributes are available."),
    )
    parser.add_argument(
        "--agent-url",
        type=str,
        default=os.environ.get("DD_TRACE_AGENT_URL", os.environ.get("DD_AGENT_URL", "")),
        help=("Datadog agent URL. If provided, any received data will be forwarded " "to the agent."),
    )
    parser.add_argument(
        "--trace-uds-socket",
        type=str,
        default=os.environ.get("DD_APM_RECEIVER_SOCKET", None),
        help=("Will listen for traces on the specified socket path"),
    )
    parser.add_argument(
        "--trace-request-delay",
        type=float,
        default=os.environ.get("DD_TEST_STALL_REQUEST_SECONDS", 0.0),
        help=("Will stall trace and telemetry requests for specified amount of time"),
    )
    parser.add_argument(
        "--suppress-trace-parse-errors",
        type=bool,
        default=os.environ.get("DD_SUPPRESS_TRACE_PARSE_ERRORS", False),
        help=(
            "Will change the test agent trace decoder to use a more resilient parser to prevent decode and span verification errors"
        ),
    )
    parser.add_argument(
        "--pool-trace-check-failures",
        type=bool,
        default=os.environ.get("DD_POOL_TRACE_CHECK_FAILURES", False),
        help=("Will change the test agent to pool Trace Check failures in memory that can later be asserted on"),
    )
    parser.add_argument(
        "--disable-error-responses",
        type=bool,
        default=os.environ.get("DD_DISABLE_ERROR_RESPONSES", False),
        help=("Will change the test agent to send [200: Ok] responses instead of error responses back to the tracer."),
    )
    parser.add_argument(
        "--vcr-cassettes-directory",
        type=str,
        default=os.environ.get("VCR_CASSETTES_DIRECTORY", os.path.join(os.getcwd(), "vcr-cassettes")),
        help="Directory to read and store third party API cassettes.",
    )
    parsed_args = parser.parse_args(args=args)
    logging.basicConfig(level=parsed_args.log_level)

    if parsed_args.version:
        print(_get_version())
        sys.exit(0)

    apm_sock: Optional[socket.socket] = None
    if parsed_args.trace_uds_socket is not None:
        if os.path.exists(parsed_args.trace_uds_socket):
            os.unlink(parsed_args.trace_uds_socket)
        apm_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        apm_sock.bind(parsed_args.trace_uds_socket)
        try:
            os.chmod(parsed_args.trace_uds_socket, 0o722)
        except OSError as e:
            log.warning("could not set permissions on UDS socket %r due to %r", parsed_args.trace_uds_socket, str(e))
        atexit.register(lambda: os.unlink(parsed_args.trace_uds_socket))

    if parsed_args.trace_request_delay is not None:
        log.info(
            "Trace request stall seconds setting set to %r.",
            parsed_args.trace_request_delay,
        )
    if not os.path.exists(parsed_args.snapshot_dir) or not os.access(parsed_args.snapshot_dir, os.W_OK | os.X_OK):
        log.warning(
            "default snapshot directory %r does not exist or is not readable. Snapshotting will not work.",
            os.path.abspath(parsed_args.snapshot_dir),
        )
    app = make_app(
        enabled_checks=parsed_args.enabled_checks,
        log_span_fmt=parsed_args.log_span_fmt,
        snapshot_dir=parsed_args.snapshot_dir,
        snapshot_ci_mode=parsed_args.snapshot_ci_mode,
        snapshot_ignored_attrs=parsed_args.snapshot_ignored_attrs,
        agent_url=parsed_args.agent_url,
        trace_request_delay=parsed_args.trace_request_delay,
        suppress_trace_parse_errors=parsed_args.suppress_trace_parse_errors,
        pool_trace_check_failures=parsed_args.pool_trace_check_failures,
        disable_error_responses=parsed_args.disable_error_responses,
        snapshot_removed_attrs=parsed_args.snapshot_removed_attrs,
        snapshot_regex_placeholders=parsed_args.snapshot_regex_placeholders,
        vcr_cassettes_directory=parsed_args.vcr_cassettes_directory,
    )

    web.run_app(app, sock=apm_sock, port=parsed_args.port)


if __name__ == "__main__":
    main()
