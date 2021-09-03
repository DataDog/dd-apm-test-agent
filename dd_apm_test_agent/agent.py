import argparse
from collections import OrderedDict
import json
import logging
import os
import pprint
from typing import Awaitable
from typing import Callable
from typing import List
from typing import Optional

from aiohttp import web
from aiohttp.web import Request
from aiohttp.web import middleware

from .checks import CheckTrace
from .checks import Checks
from .checks import start_trace
from .snapshot import generate_snapshot
from .snapshot import snapshot
from .trace import Trace
from .trace import TraceMap
from .trace import decode_v04
from .trace import v04TraceChunk
from .trace_checks import CheckMetaTracerVersionHeader
from .trace_checks import CheckTraceCountHeader


_Handler = Callable[[Request], Awaitable[web.Response]]


log = logging.getLogger(__name__)


@middleware  # type: ignore
async def check_failure_middleware(request: Request, handler: _Handler) -> web.Response:
    """Convert any failed checks into an HttpException."""
    trace = start_trace("request %r" % request)
    try:
        response = await handler(request)
    except AssertionError as e:
        return web.HTTPBadRequest(body=str(trace) + str(e))
    else:
        if trace.has_fails():
            return web.HTTPBadRequest(body=str(trace))
    return response


def _session_token(request: Request) -> Optional[str]:
    token: Optional[str]
    if "X-Datadog-Test-Session-Token" in request.headers:
        token = request.headers["X-Datadog-Test-Session-Token"]
    elif "test_session_token" in request.url.query:
        token = request.url.query.get("test_session_token")
    else:
        token = None
    return token


@middleware  # type: ignore
async def session_token_middleware(request: Request, handler: _Handler) -> web.Response:
    """Extract session token from the request and store it in the request.

    The token is retrieved from the headers or params of the request.
    """
    token = _session_token(request)
    request["session_token"] = token
    return await handler(request)


class Agent:
    def __init__(self):
        """Only store the requests sent to the agent. There are many representations
        of data but typically information is lost while transforming the data.

        Storing exactly what is sent to the agent enables us to transform the data
        however we desire later on.
        """
        # Token to be used if running test cases synchronously
        self._requests: List[Request] = []

    async def traces(self) -> TraceMap:
        """Return the traces stored by the agent in the order in which they
        arrived.

        Spans from trace chunks are aggregated by trace id and returned as
        complete lists.
        """
        _traces: TraceMap = OrderedDict()
        for req in reversed(self._requests):
            traces = await self._decode_v04_traces(req)
            for t in traces:
                for s in t:
                    trace_id = s["trace_id"]
                    if trace_id not in _traces:
                        _traces[trace_id] = []
                    _traces[trace_id].append(s)
        return _traces

    async def _trace_by_trace_id(self, trace_id: int) -> Trace:
        return (await self.traces())[trace_id]

    def _requests_by_session(self, token: Optional[str]) -> List[Request]:
        # Go backwards in the requests received gathering requests until
        # the /session-start request for the token is found.
        manual_reqs: List[Request] = []
        for req in reversed(self._requests):
            if req.match_info.handler == self.handle_session_start:
                if token is None or _session_token(req) == token:
                    break
                else:
                    # The requests made were from a different manual session
                    # so discard them.
                    manual_reqs = []
                    break
            manual_reqs.append(req)
        else:
            manual_reqs = []

        assoc_reqs = (
            [
                r
                for r in self._requests
                if _session_token(r) == token and r not in manual_reqs
            ]
            if token is not None
            else []
        )
        return manual_reqs + assoc_reqs

    async def _traces_by_session(self, token: Optional[str]) -> List[Trace]:
        """Return the traces that belong to the given session token.

        If token is None or if the token was used to manually start a session
        with /session-start then return all traces that were sent since the last
        /session-start request was made.

        Spans are aggregated by trace_id (no ordering is performed).
        """
        tracemap: TraceMap = OrderedDict()
        for req in self._requests_by_session(token):
            if req.match_info.handler == self.handle_v04_traces:
                for trace in await self._decode_v04_traces(req):
                    for span in trace:
                        trace_id = span["trace_id"]
                        if trace_id not in tracemap:
                            tracemap[trace_id] = []
                        tracemap[trace_id].append(span)
        return list(tracemap.values())

    async def _decode_v04_traces(self, request: Request) -> v04TraceChunk:
        content_type = request.content_type
        raw_data = await request.read()
        return decode_v04(content_type, raw_data)

    async def handle_v04_traces(self, request: Request) -> web.Response:
        self._requests.append(request)
        checks: Checks = request.app["checks"]

        with CheckTrace.add_frame("headers") as f:
            f.add_item(pprint.pformat(dict(request.headers)))
            checks.check("meta_tracer_version_header", headers=dict(request.headers))
            traces = await self._decode_v04_traces(request)

            with CheckTrace.add_frame(f"payload ({len(traces)} traces)"):
                checks.check(
                    "trace_count_header",
                    headers=dict(request.headers),
                    num_traces=len(traces),
                )

        # TODO: implement sampling logic
        return web.json_response(data={"rate_by_service": {}})

    async def handle_v05(self, request: Request) -> web.Response:
        raise NotImplementedError

    async def handle_session_start(self, request: Request) -> web.Response:
        self._requests.append(request)
        return web.HTTPOk()

    async def handle_snapshot(self, request: Request) -> web.Response:
        token = request["session_token"]
        snap_dir = request.app["snapshot_dir"]
        snap_ci_mode = request.app["snapshot_ci_mode"]
        # TODO: ignore_keys

        with CheckTrace.add_frame(f"snapshot (token='{token}')") as frame:
            frame.add_item(f"Directory: {snap_dir}")
            frame.add_item(f"CI mode: {snap_ci_mode}")

            if "X-Datadog-Test-Snapshot-Filename" in request.headers:
                snap_file = request.headers["X-Datadog-Test-Snapshot-Filename"]
            elif "test_snapshot_filename" in request.url.query:
                snap_file = request.url.query.get("test_snapshot_filename")
            else:
                snap_file = token
            snap_file = f"{snap_file}.json"
            frame.add_item(f"File: {snap_file}")
            snap_path = os.path.join(snap_dir, snap_file)
            log.info("Using snapshot file %s", snap_path)

            snap_path_exists = os.path.exists(snap_path)
            if snap_ci_mode and not snap_path_exists:
                raise AssertionError(
                    f"Snapshot file '{snap_path}' not found."
                    "Perhaps the file was not checked into source control?"
                    "The snapshot file is automatically generated when the test case is run when not in CI mode."
                )
            elif snap_path_exists:
                # Do the snapshot comparison
                received_traces = await self._traces_by_session(token)
                with open(snap_path, mode="r") as f:
                    raw_snapshot = json.load(f)

                snapshot(expected_traces=raw_snapshot, received_traces=received_traces)
            else:
                # Create a new snapshot for the data received
                traces = await self._traces_by_session(token)
                with open(snap_path, mode="w") as f:
                    # TODO: pretty print + sort keys
                    f.write(json.dumps(generate_snapshot(traces), indent=2))
        return web.HTTPOk()

    async def handle_session_traces(self, request: Request) -> web.Response:
        token = request["session_token"]
        traces = await self._traces_by_session(token)
        return web.json_response(traces)

    async def handle_test_traces(self, request: Request) -> web.Response:
        """Return requested traces as JSON.

        Traces can be requested by providing a header X-Datadog-Trace-Ids or
        a query param trace_ids.
        """
        raw_trace_ids = request.url.query.get(
            "trace_ids", request.headers.get("X-Datadog-Trace-Ids", "")
        )
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

    async def handle_session_clear(self, request: Request) -> web.Response:
        """Clear traces by session token or all traces if none is provided."""
        session_token = request["session_token"]
        if session_token is not None:
            self._requests = [
                r for r in self._requests if _session_token(r) != session_token
            ]
        else:
            # Clear all requests made after a /session-start
            i = len(self._requests)
            for i, req in enumerate(reversed(self._requests)):
                if req.match_info.handler == self.handle_session_start:
                    break
                i -= 1
            self._requests = self._requests[0:i]
        return web.HTTPOk()


def make_app(
    disabled_checks: List[str], snapshot_dir: str, snapshot_ci_mode: bool
) -> web.Application:
    agent = Agent()
    app = web.Application(
        middlewares=[
            check_failure_middleware,
            session_token_middleware,
        ]
    )
    app.add_routes(
        [
            web.post("/v0.4/traces", agent.handle_v04_traces),
            web.put("/v0.4/traces", agent.handle_v04_traces),
            web.put("/v0.5/traces", agent.handle_v05),
            web.get("/test/session/start", agent.handle_session_start),
            web.get("/test/session/clear", agent.handle_session_clear),
            web.get("/test/session/snapshot", agent.handle_snapshot),
            web.get("/test/session/traces", agent.handle_session_traces),
            web.get("/test/traces", agent.handle_test_traces),
        ]
    )
    checks = Checks(
        checks=[
            CheckMetaTracerVersionHeader,
            CheckTraceCountHeader,
        ],
        disabled=disabled_checks,
    )
    app["checks"] = checks
    app["snapshot_dir"] = snapshot_dir
    app["snapshot_ci_mode"] = snapshot_ci_mode
    # TODO: add option for failing /traces endpoint requests when bad data
    # default should be False
    # Also add a /tests/traces-check
    return app


def main():
    parser = argparse.ArgumentParser(
        description="Datadog APM test agent",
        prog="agent",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=int(os.environ.get("PORT", 8126))
    )
    parser.add_argument(
        "--snapshot-dir", type=str, default=os.environ.get("SNAPSHOT_DIR", "snaps")
    )
    parser.add_argument(
        "--snapshot-ci-mode", type=int, default=int(os.environ.get("SNAPSHOT_CI", 0))
    )
    parser.add_argument(
        "--strictness", type=int, default=int(os.environ.get("STRICTNESS", 0))
    )
    parser.add_argument(
        "--disabled-checks",
        type=list,
        default=[s.upper() for s in os.environ.get("DISABLED_CHECKS", "").split(",")],
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default=os.environ.get("LOG_LEVEL", "INFO"),
        help="Set the log level. DEBUG, INFO, WARNING, ERROR, CRITICAL",
    )
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level)
    app = make_app(
        disabled_checks=args.disabled_checks,
        snapshot_dir=args.snapshot_dir,
        snapshot_ci_mode=args.snapshot_ci_mode,
    )
    web.run_app(app, port=args.port)


if __name__ == "__main__":
    main()
