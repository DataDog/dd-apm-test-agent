import argparse
import collections
import contextlib
import contextvars
import dataclasses
import logging
import os
import pprint
import textwrap
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Dict
from typing import Generator
from typing import List
from typing import Optional
from typing import Tuple
from typing import Type

from aiohttp import web
from aiohttp.web import Request
from aiohttp.web import middleware

from .trace import Trace
from .trace import TraceMap
from .trace import decode_v04


_Handler = Callable[[Request], Awaitable[web.Response]]


log = logging.getLogger(__name__)

CHECK_TRACE: contextvars.ContextVar["CheckTrace"] = contextvars.ContextVar(
    "check_trace"
)


class CheckTraceFrame:
    def __init__(self, name: str, long: str) -> None:
        self._checks: List["Check"] = []
        self._name = name
        self._long = long
        self._children: List["CheckTraceFrame"] = []

    def add_check(self, check: "Check") -> None:
        self._checks.append(check)

    def add_frame(self, frame: "CheckTraceFrame") -> None:
        self._children.append(frame)

    def has_fails(self) -> bool:
        for c in self._checks:
            if c.failed:
                return True
        return False

    def __repr__(self) -> str:
        return f"<CheckTraceFrame name='{self._name}' children={len(self._children)}>"


class CheckTrace:
    """A trace of a check used to provide helpful debugging information for failed checks.

    At payload 1 (inspect this payload at localhost:8126/test/request/1bacf34db):
        - /v04/trace (40kb, 5 traces)
        At headers:
            { ... }
            ERROR: X-Datadog-Trace-Count does not match number of traces in payload
        At trace 0 ("django.request", 20 spans):
            At span 0 ("django.request", "/users/"):
                ERROR: ...
        At trace 2 ("http.request", 10 spans):
            ERROR:
    """

    def __init__(self, root: CheckTraceFrame):
        self._root = root
        self._active = root

    @classmethod
    @contextlib.contextmanager
    def add_frame(cls, frame: CheckTraceFrame) -> Generator["CheckTrace", None, None]:
        """Add a frame to the trace."""
        ctx = CHECK_TRACE.get()
        ctx._active.add_frame(frame)
        prev_active = ctx._active
        ctx._active = frame
        yield ctx
        ctx._active = prev_active

    @classmethod
    def add_check(cls, check: "Check") -> None:
        """Add the given check to the current frame."""
        ctx = CHECK_TRACE.get()
        ctx._active.add_check(check)

    def frames(self) -> Generator[CheckTraceFrame, None, None]:
        fs: List[CheckTraceFrame] = [self._root]
        while fs:
            frame = fs.pop(0)
            yield frame
            fs = frame._children + fs

    def frames_dfs(self) -> Generator[Tuple[CheckTraceFrame, int], None, None]:
        fs: List[Tuple[CheckTraceFrame, int]] = [(self._root, 0)]
        while fs:
            frame, depth = fs.pop(0)
            yield frame, depth
            fs = [(f, depth + 1) for f in frame._children] + fs

    def has_fails(self) -> bool:
        return len([f for f in self.frames() if f.has_fails()]) > 0

    def __str__(self) -> str:
        s = ""
        # TODO: only include frames that have fails
        for frame, depth in self.frames_dfs():
            indent = " " * (depth + 2) if depth > 0 else ""
            s += f"{indent}At {frame._name}:\n"
            if frame._long:
                s += textwrap.indent(f"- {frame._long}", prefix=f" {indent}")
                s += "\n"

            for c in frame._checks:
                if c.failed:
                    s += f"{indent}❌ Check '{c.name}' failed: {c._msg}\n"
        return s


class Check:
    name: str
    """Name of the check. Should be as succinct and representative as possible."""

    description: str
    """Description of the check. Be as descriptive as possible as this will be included
    with error messages returned to the test case.
    """

    default_enabled: bool
    """Whether the check is enabled by default or not."""

    def __init__(self):
        self._failed: bool = False
        self._msg: str = ""

    @property
    def failed(self) -> bool:
        return self._failed

    def fail(self, msg: str) -> None:
        self._failed = True
        self._msg = msg

    def check(self, *args, **kwargs):
        """Perform any checking required for this Check.

        CheckFailures should be raised for any failing checks.
        """
        raise NotImplementedError


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


class CheckNotFound(IndexError):
    pass


@dataclasses.dataclass()
class Checks:
    checks: List[Type[Check]] = dataclasses.field(init=True)
    disabled: List[str] = dataclasses.field(init=True)

    def _get_check(self, name: str) -> Type[Check]:
        for c in self.checks:
            if c.name == name:
                return c
        else:
            raise CheckNotFound("Check for code %r not found" % name)

    def is_enabled(self, name: str) -> bool:
        check = self._get_check(name)
        if check.name in self.disabled:
            return False
        return check.default_enabled

    def check(self, name: str, *args: Tuple[Any], **kwargs: Dict[str, Any]) -> None:
        check = self._get_check(name)()
        CheckTrace.add_check(check)
        if self.is_enabled(name):
            check.check(*args, **kwargs)


@middleware  # type: ignore
async def check_failure_middleware(request: Request, handler: _Handler) -> web.Response:
    """Convert any failed checks into an HttpException."""
    ctx = CheckTrace(CheckTraceFrame(name="request %r" % request, long=""))
    CHECK_TRACE.set(ctx)
    try:
        response = await handler(request)
    except AssertionError as e:
        return web.HTTPBadRequest(body=str(e))
    else:
        if ctx.has_fails():
            return web.HTTPBadRequest(body=str(ctx))
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
    request["session_token"] = _session_token(request)
    return await handler(request)


class Agent:
    def __init__(self):
        """Only store the requests sent to the agent. There are many representations
        of data but typically information is lost while transforming the data.

        Storing exactly what is sent to the agent enables us to transform the data
        however we desire later on.
        """

        # Token to be used if running test cases synchronously
        self._sync_session_token: Optional[str] = None
        self._requests: List[Request] = []

    async def traces(self) -> TraceMap:
        """Return the traces stored by the agent."""
        _traces: TraceMap = collections.defaultdict(lambda: [])

        for req in self._requests:
            traces = await self._decode_v04_traces(req)
            for t in traces:
                for s in t:
                    _traces[int(s["trace_id"])].append(s)
        return _traces

    async def get_trace(self, trace_id: int) -> Trace:
        return (await self.traces())[trace_id]

    async def _decode_v04_traces(self, request: Request) -> Any:
        content_type = request.content_type
        raw_data = await request.read()
        return decode_v04(content_type, raw_data)

    async def handle_v04_traces(self, request: Request) -> web.Response:
        self._requests.append(request)

        with CheckTrace.add_frame(
            CheckTraceFrame(name="headers", long=pprint.pformat(dict(request.headers)))
        ):
            request.app["checks"].check(
                "meta_tracer_version_header", headers=dict(request.headers)
            )
            traces = await self._decode_v04_traces(request)

            with CheckTrace.add_frame(
                CheckTraceFrame(name=f"payload ({len(traces)} traces)", long="")
            ):
                request.app["checks"].check(
                    "trace_count_header",
                    headers=dict(request.headers),
                    num_traces=len(traces),
                )

        # TODO: implement sampling logic
        return web.json_response(data={"rate_by_service": {}})

    async def handle_v05(self, request: Request) -> web.Response:
        raise NotImplementedError

    async def handle_start_session(self, request: Request) -> web.Response:
        token = request["session_token"]
        assert token is not None
        self._sync_session_token = token
        return web.HTTPOk()

    async def handle_snapshot(self, request: Request) -> web.Response:
        token = request["session_token"]
        snap_dir = request.app["snapshot_dir"]
        snap_ci_mode = request.app["snapshot_ci_mode"]

        if "X-Datadog-Test-Snapshot-Filename" in request.headers:
            snap_file = request.headers["X-Datadog-Test-Snapshot-Filename"]
        elif "test_snapshot_filename" in request.url.query:
            snap_file = request.url.query.get("test_snapshot_filename")
        else:
            snap_file = token
        snap_file = f"{snap_file}.json"

        snap_path = os.path.join(snap_dir, snap_file)
        log.info("Using snapshot file %s", snap_path)

        snap_path_exists = os.path.exists(snap_path)
        if snap_ci_mode and not snap_path_exists:
            raise AssertionError("")
        elif snap_path_exists:
            with open(snap_path, mode="r") as f:
                f.readlines()
        else:
            with open(snap_path, mode="w") as f:
                f.write("test")

        return web.HTTPOk()

    async def handle_test_traces(self, request: Request) -> web.Response:
        """Return requested traces as JSON.

        Traces can be requested by providing a header X-Datadog-Trace-Ids or
        a query param trace_ids.
        """
        trace_ids = map(
            int,
            request.url.query.get(
                "trace_ids", request.headers.get("X-Datadog-Trace-Ids", "")
            ).split(","),
        )
        assert trace_ids
        traces = [await self.get_trace(tid) for tid in trace_ids]
        return web.json_response(data=traces)

    async def handle_clear_traces(self, request: Request) -> web.Response:
        """Clear traces by session token or all traces if none is provided."""
        session_token = request["session_token"]
        if session_token:
            self._requests = [
                r for r in self._requests if _session_token(r) != session_token
            ]
        else:
            self._requests = []
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
            web.get("/test/session-start", agent.handle_start_session),
            web.get("/test/session-clear", agent.handle_clear_traces),
            web.get("/test/session-snapshot", agent.handle_snapshot),
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
        "--disable-checks",
        type=list,
        default=[s.upper() for s in os.environ.get("DISABLED_CHECKS", "").split(",")],
    )
    args = parser.parse_args()

    app = make_app(
        disabled_checks=args.disabled_checks,
        snapshot_dir=args.snapshot_dir,
        snapshot_ci_mode=args.snapshot_ci_mode,
    )
    web.run_app(app, port=args.port)


if __name__ == "__main__":
    main()
