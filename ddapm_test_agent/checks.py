import asyncio
import contextlib
import contextvars
import dataclasses
import textwrap
from typing import Any
from typing import Generator
from typing import List
from typing import Tuple
from typing import Type

import logging

log = logging.getLogger(__name__)


CHECK_TRACE: contextvars.ContextVar["CheckTrace"] = contextvars.ContextVar("check_trace")


class CheckNotFound(IndexError):
    pass


class CheckTraceFrame:
    def __init__(self, name: str) -> None:
        self._checks: List["Check"] = []
        self._name = name
        self._children: List["CheckTraceFrame"] = []
        self._items: List[str] = []

    def add_item(self, item: str) -> None:
        self._items.append(item)

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
    """A trace of a check used to provide helpful debugging information for failed checks."""

    def __init__(self, root: CheckTraceFrame):
        self._root = root
        self._active = root

    @classmethod
    @contextlib.contextmanager
    def add_frame(cls, title: str) -> Generator["CheckTraceFrame", None, None]:
        """Add a frame to the trace."""
        ctx = CHECK_TRACE.get()
        frame = CheckTraceFrame(title)
        ctx._active.add_frame(frame)
        prev_active = ctx._active
        ctx._active = frame
        yield frame
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
        # TODO?: only include frames that have fails
        for frame, depth in self.frames_dfs():
            indent = " " * (depth + 2) if depth > 0 else ""
            s += f"{indent}At {frame._name}:\n"
            for item in frame._items:
                s += textwrap.indent(f"- {item}", prefix=f" {indent}")
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

    async def check(self, name: str, *args: Any, **kwargs: Any) -> None:
        """Find and run the check with the given ``name`` if it is enabled."""
        check = self._get_check(name)()
        log.info("name" + str(name))
        log.info("enabled?: " + str(self.is_enabled(name)))
        log.info(self.disabled)

        if self.is_enabled(name):
            # Register the check with the current trace
            CheckTrace.add_check(check)

            # Run the check
            if asyncio.iscoroutinefunction(check.check):
                await check.check(*args, **kwargs)
            else:
                check.check(*args, **kwargs)


def start_trace(msg: str) -> CheckTrace:
    trace = CheckTrace(CheckTraceFrame(name=msg))
    CHECK_TRACE.set(trace)
    return trace
