import argparse
import contextlib
import contextvars
import collections
import dataclasses
import json
import logging
import os
import pprint
import textwrap
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import OrderedDict
from typing import Type

from aiohttp import web
from aiohttp.web import Request
from aiohttp.web import middleware
import msgpack


log = logging.getLogger(__name__)

CHECK_CONTEXT: contextvars.ContextVar[
    Optional["CheckContext"]
] = contextvars.ContextVar("check_context", default=None)


@dataclasses.dataclass()
class CheckContext:
    _ctx: OrderedDict = dataclasses.field(
        init=False, default_factory=collections.OrderedDict
    )
    _checks: List["Check"] = dataclasses.field(init=False, default_factory=list)

    def __getitem__(self, item: str) -> Any:
        return self._ctx[item]

    def add(self, k, v):
        self._ctx[k] = v

    def copy(self) -> "CheckContext":
        c = CheckContext()
        c._ctx = self._ctx.copy()
        return c

    @classmethod
    @contextlib.contextmanager
    def add_items(cls, **items):
        ctx = CHECK_CONTEXT.get()
        old = ctx._ctx.copy()
        ctx._ctx.update(items)
        yield ctx
        ctx._ctx.clear()
        ctx._ctx.update(old)

    def remove(self, k):
        del self._ctx[k]

    @classmethod
    def add_check(cls, check: "Check"):
        ctx = CHECK_CONTEXT.get()
        ctx._checks.append(check)

    def has_fails(self) -> bool:
        return len(self.fails()) > 0

    def fails(self) -> List["CheckFailure"]:
        return [f for c in self._checks for f in c.fails()]

    def straceback(self) -> str:
        return "\n".join([f"{k} = {pprint.pformat(v)}" for k, v in self._ctx.items()])


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
        self._failures: List["CheckFailure"] = []

    def failed(self) -> bool:
        return len(self._failures) > 0

    def fail(self, msg: str) -> None:
        ctx = CHECK_CONTEXT.get()
        self._failures.append(CheckFailure(self, msg, ctx.copy()))

    def fails(self) -> List["CheckFailure"]:
        return self._failures

    def check(self, *args: List[Any], **kwargs: Dict[str, Any]) -> None:
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

    def check(self, headers: Dict[str, str], num_traces: int):
        # TODO: could do this by default if defined in parent
        # or if do _check approach
        with CheckContext.add_items(
            payload_headers=headers,
            num_traces=num_traces,
        ):
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

    def check(self, headers: Dict[str, str]) -> None:
        if "Datadog-Meta-Tracer-Version" not in headers:
            self.fail("Datadog-Meta-Tracer-Version not found in headers")


class CheckFailure(Exception):
    def __init__(self, check: Check, msg: str, context: CheckContext):
        self._check: Check = check
        self._msg: str = msg
        self._context: CheckContext = context
        super().__init__()

    def __str__(self) -> str:
        return f"""Check '{self._check.name}' failed.
Description\n{textwrap.indent(self._check.description, "    ")}
Context\n{textwrap.indent(self._context.straceback(), "    ")}
Reason: {self._msg}"""

    def __repr__(self) -> str:
        return f"<CheckFailure({self._check.name}, msg='{self._msg}')>"


@dataclasses.dataclass()
class Checks:
    checks: List[Type[Check]] = dataclasses.field(init=True)
    disabled: List[str] = dataclasses.field(init=True)

    class CheckNotFound(IndexError):
        pass

    def _get_check(self, name: str) -> Type[Check]:
        for c in self.checks:
            if c.name == name:
                return c
        else:
            raise self.CheckNotFound("Check for code %r not found" % name)

    def is_enabled(self, name: str) -> bool:
        check = self._get_check(name)
        if check.name in self.disabled:
            return False
        return check.default_enabled

    def check(self, name: str, *args, **kwargs) -> None:
        check = self._get_check(name)()
        CheckContext.add_check(check)
        if self.is_enabled(name):
            check.check(*args, **kwargs)


@middleware
async def check_failure_middleware(request: Request, handler: Callable) -> web.Response:
    """Convert any failed checks into an HttpException."""
    ctx = CheckContext()
    CHECK_CONTEXT.set(ctx)
    response = await handler(request)
    if ctx.has_fails():
        msg = "\n".join(str(f) for f in ctx.fails())
        return web.HTTPBadRequest(body=msg)
    return response


@middleware
async def snapshot_token_middleware(
    request: Request, handler: Callable
) -> web.Response:
    """Extracts snapshot token from the request and store it in the request.

    The snapshot token is retrieved from the headers or params of the request.
    """
    token: Optional[str]
    if "X-Datadog-Test-Token" in request.headers:
        token = request.headers["X-Datadog-Test-Token"]
    elif "token" in request.url.query:
        token = request.url.query.get("token")
    else:
        token = None

    request["snapshot_token"] = token
    return await handler(request)


class Agent:
    def __init__(self):
        """Only store the requests sent to the agent. There are many representations
        of data but typically information is lost while transforming the data.

        Storing exactly what is sent to the agent enables us to transform the data
        however we desire later on.
        """
        self._requests: List[Request] = []

    async def traces(self) -> Dict[int, List[Dict]]:
        """Return the traces stored by the agent."""
        _traces: Dict[int, List[Dict]] = collections.defaultdict(lambda: [])

        for req in self._requests:
            traces = await self._decode_v04_traces(req)
            for t in traces:
                for s in t:
                    _traces[int(s["trace_id"])].append(s)
        return _traces

    async def get_trace(self, trace_id: int) -> List[Dict]:
        return (await self.traces())[trace_id]

    async def _decode_v04_traces(self, request: Request) -> List:
        content_type = request.content_type
        if content_type == "application/msgpack":
            payload = msgpack.unpackb(await request.read())
        elif content_type == "application/json":
            payload = json.loads(await request.read())
        else:
            raise ValidationError(reason="Content type %r not supported" % content_type)
        return payload

    async def handle_v04_traces(self, request: Request) -> web.Response:
        self._requests.append(request)
        traces = await self._decode_v04_traces(request)
        assert isinstance(traces, list)

        request.app["checks"].check(
            "trace_count_header",
            headers=dict(request.headers),
            num_traces=len(traces),
        )
        request.app["checks"].check(
            "meta_tracer_version_header", headers=dict(request.headers)
        )

        # TODO json response with sample rates
        return web.Response(text="OK")

    async def handle_v05(self, request: Request) -> web.Response:
        raise NotImplementedError

    async def handle_start_snapshot(self, request: Request) -> web.Response:
        assert request["snapshot_token"]
        return web.HTTPOk(text="hello")

    async def handle_snapshot(self, request: Request) -> web.Response:
        return web.HTTPOk(text="hello")

    async def handle_test_traces(self, request: Request) -> web.Response:
        """Return requested traces as JSON."""
        trace_ids = map(
            int,
            request.url.query.get(
                "trace_ids", request.headers.get("X-Datadog-Trace-Ids")
            ).split(","),
        )
        traces = [await self.get_trace(tid) for tid in trace_ids]
        return web.json_response(data=traces)

    async def handle_clear_traces(self, request: Request):
        raise NotImplementedError


def make_app(disabled_checks: List[str]) -> web.Application:
    agent = Agent()
    app = web.Application(
        middlewares=[
            check_failure_middleware,
            snapshot_token_middleware,
        ]
    )
    app.add_routes(
        [
            web.post("/v0.4/traces", agent.handle_v04_traces),
            web.put("/v0.4/traces", agent.handle_v04_traces),
            web.put("/v0.5/traces", agent.handle_v05),
            web.get("/test/start", agent.handle_start_snapshot),
            web.get("/test/session-start", agent.handle_start_snapshot),
            web.get("/test/session-clear-traces", agent.handle_clear_traces),
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
        # strict_mode=args.strictness,
        # snapshot_dir=args.snapshot_dir,
        # snapshot_ci_mode=args.snapshot_ci_mode,
    )
    app["strict_mode"] = args.snapshot_dir
    app["snapshot_dir"] = args.snapshot_dir
    app["snapshot_ci_mode"] = args.snapshot_ci_mode
    web.run_app(app, port=args.port)


if __name__ == "__main__":
    main()
