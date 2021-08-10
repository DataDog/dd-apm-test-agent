import argparse
import contextlib
import dataclasses
import json
import logging
import os
import pprint
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
import unittest

from aiohttp import web
from aiohttp.web import Request
from aiohttp.web import middleware
import msgpack


log = logging.getLogger(__name__)


@dataclasses.dataclass()
class CheckContext:
    pre: str = dataclasses.field(default="")
    items: Dict = dataclasses.field(default_factory=dict)
    body: str = dataclasses.field(default="")
    post: str = dataclasses.field(default="")

    def __str__(self):
        return f"""{self.pre}
        ---------------------------
        Context:
        {pprint.pformat(self.items)}

        {self.body}
        ---------------------------
        {self.post}
        """

    def add_item(self, k: Any, v: Any) -> None:
        self.items[k] = v

    def add_pre(self, s: str):
        self.pre += s


@dataclasses.dataclass()
class Check:
    """Name of the check. Should be as succinct and representative as possible."""

    name: str = dataclasses.field(init=True)
    """Description of the check. Be as descriptive as possible as this will be included
    with error messages returned to the test case.
    """
    description: str = dataclasses.field(init=True)
    """Whether the check is enabled by default or not."""
    default_enabled: bool = dataclasses.field(init=True)


class CheckFailure(Exception):
    def __init__(self, check: Check, context: CheckContext):
        super().__init__()
        self._check = check
        self._context = context

    def __str__(self):
        return f"""Check '{self._check.name}' failed.
    {self._check.description}
    {self._context}
        """


@dataclasses.dataclass()
class Checks:
    checks: List[Check] = dataclasses.field(init=True)
    disabled: List[str] = dataclasses.field(init=True)

    class CheckNotFound(IndexError):
        pass

    def _get_check(self, name: str) -> Check:
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

    @contextlib.contextmanager
    def check(self, name: str, context: Dict = {}) -> "Checker":
        ctx = CheckContext()
        for k, v in context.items():
            ctx.add_item(k, v)

        check = self._get_check(name)
        try:
            yield CheckerTest()
        except AssertionError as e:
            if self.is_enabled(name):
                raise CheckFailure(check, ctx) from e


class CheckerTest(unittest.TestCase):
    pass


class ValidationError(web.HTTPClientError):
    status_code = 400


@middleware
async def check_failure_middleware(request: Request, handler: Callable) -> web.Response:
    try:
        return await handler(request)
    except CheckFailure as e:
        return web.HTTPBadRequest(body=str(e))


@middleware
async def snapshot_token_middleware(
    request: Request, handler: Callable
) -> web.Response:
    """Extracts snapshot token from the request and store it in the request.

    The snapshot token is retrieved from the headers or params of the request.
    """
    if "X-Datadog-Test-Token" in request.headers:
        token = request.headers["X-Datadog-Test-Token"]
    elif "token" in request.url.query:
        token = request.url.query.get("token")
    else:
        token = None

    request["snapshot_token"] = token
    return await handler(request)


@dataclasses.dataclass()
class Error:
    msg: str = dataclasses.field(init=True)


@dataclasses.dataclass()
class AgentRequest:
    request: Request = dataclasses.field(init=True)
    snapshot_token: Optional[str] = dataclasses.field(init=True)
    errors: List[Error] = dataclasses.field(init=False)

    def add_error(self, error: Error):
        self.errors.append(error)


class Agent:
    def __init__(self):
        """Only store the requests sent to the agent. There are many representations
        of data but typically information is lost while transforming the data.

        Storing exactly what is sent to the agent enables us to transform the data
        however we desire later on.
        """
        self._requests: List[Request] = []

    def traces(self) -> Dict[int, List[Dict]]:
        """Return the traces stored by the agent."""
        _traces: Dict[int, List[Dict]] = {}

        for req in self._requests:
            pass

        return _traces

    async def _decode_v04_traces(self, request: Request) -> bytes:
        content_type = request.content_type
        if content_type == "application/msgpack":
            payload = msgpack.unpackb(await request.read())
        elif content_type == "application/json":
            payload = json.loads(await request.read())
        else:
            raise ValidationError(reason="Content type %r not supported" % content_type)
        return payload

    async def handle_v04_traces(self, request: Request):
        self._requests.append(request)
        traces = await self._decode_v04_traces(request)
        assert isinstance(traces, list)

        with request.app["checks"].check(
            "trace_count_header",
            context=dict(
                headers=dict(request.headers),
            ),
        ) as test:
            # Cast to dict for better pretty printing
            test.assertIn("X-Datadog-Trace-Count", dict(request.headers))
            test.assertEqual(int(request.headers["X-Datadog-Trace-Count"]), len(traces))

        with request.app["checks"].check("meta_tracer_version_header") as test:
            test.assertIn("Datadog-Meta-Tracer-Version", dict(request.headers))

        # TODO json response with sample rates
        return web.Response(text="OK")

    async def handle_v05(self, request: Request):
        raise NotImplementedError

    async def handle_start_snapshot(self, request: Request):
        assert request["snapshot_token"]
        return web.HTTPOk(text="hello")

    async def handle_snapshot(self, request: Request):
        return web.HTTPOk(text="hello")

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
            web.get("/test/start-snapshot", agent.handle_start_snapshot),
            web.get("/test/clear-traces", agent.handle_clear_traces),
            web.get("/test/snapshot", agent.handle_snapshot),
        ]
    )
    checks = Checks(
        checks=[
            Check(
                name="meta_tracer_version_header",
                description="""v0.4 payloads must include the Datadog-Meta-Tracer-Version header""",
                default_enabled=True,
            ),
            Check(
                name="trace_count_header",
                description="""
    The number of traces included in a payload must be included as the
    X-Datadog-Trace-Count http header with each payload and must match the
    number of traces included in the payload.""".lstrip().strip(),
                default_enabled=True,
            ),
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
