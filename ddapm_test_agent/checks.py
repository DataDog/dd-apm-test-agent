import asyncio
import contextlib
import contextvars
import dataclasses
import logging
import textwrap
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Tuple
from typing import Type

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

    def update_results(self, results: Dict[str, Dict[str, Any]], trace_ids: List[int]) -> Dict[str, Dict[str, Any]]:
        """Return as follows
        output = { check.name: { "Passed_Checks": int, "Failed_Checks": int, "Skipped_Checks": int, "passed_traces": [], "failed_traces": []}}

        """
        for c in self._checks:
            if c.failed:
                results[c.name]["Failed_Checks"] += 1
                for trace_id in trace_ids:
                    results[c.name]["failed_traces"].append({"id": trace_id, "reason": c.message})
            elif c.skipped:
                results[c.name]["Skipped_Checks"] += 1
            else:
                results[c.name]["Passed_Checks"] += 1
                results[c.name]["passed_traces"].extend(trace_ids)
        return results

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

    def update_results(self, results: Dict[str, Dict[str, Any]], trace_ids: List[int]) -> Dict[str, Dict[str, Any]]:
        for f in self.frames():
            f.update_results(results, trace_ids)
        return results

    def get_failures_by_check(self, failures_by_check: Dict[str, List[str]]) -> Dict[str, List[str]]:
        # TODO?: refactor so this code isnt duplicated with __str__
        frame_s = ""
        for frame, depth in self.frames_dfs():
            indent = " " * (depth + 2) if depth > 0 else ""

            frame_s += f"{indent}At {frame._name}:\n"
            for item in frame._items:
                frame_s += textwrap.indent(f"- {item}", prefix=f" {indent}")
                frame_s += "\n"

            for c in frame._checks:
                if c.failed:
                    check_s = f"{indent}❌ Check '{c.name}' failed: {c.message}\n"
                    if c.name in failures_by_check:
                        failures_by_check[c.name].append(frame_s + check_s)
                    else:
                        failures_by_check[c.name] = [frame_s + check_s]
        return failures_by_check

    def __str__(self) -> str:
        s = ""
        # TODO?: only include frames that have fails
        for frame, depth in self.frames_dfs():
            indent = " " * (depth + 2) if depth > 0 else ""
            if frame._name == "headers":
                s += f"{indent}At headers:\n"
            else:
                s += f"{indent}At {frame._name}:\n"
            for item in frame._items:
                s += textwrap.indent(f"- {item}", prefix=f" {indent}")
                s += "\n"

            for c in frame._checks:
                if c.failed:
                    s += f"{indent}❌ Check '{c.name}' failed: {c.message}\n"
        return s


class Check:
    name: str
    """Name of the check. Should be as succinct and representative as possible."""

    description: str
    """Description of the check. Be as descriptive as possible as this will be included
    with error messages returned to the test case.
    """

    category: str = "General"
    """Category of the check. This is used to group checks in the UI."""

    team: str = "Core"
    """Team that owns the check."""

    def __init__(self) -> None:
        self._failed: bool = False
        self._skipped: bool = False
        self._msgs: List[str] = []

    @property
    def failed(self) -> bool:
        return self._failed

    @property
    def skipped(self) -> bool:
        return self._skipped

    @property
    def message(self) -> str:
        return "; ".join(self._msgs)

    def fail(self, msg: str) -> None:
        self._failed = True
        self._msgs.append(msg)

    def skip(self, msg: str) -> None:
        self._skipped = True
        self._msgs.append(msg)

    def check(self, *args, **kwargs):
        """Perform any checking required for this Check.

        CheckFailures should be raised for any failing checks.
        """
        pass


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: Dict[str, Type[Check]] = {}

    def register(self, check: Type[Check]) -> None:
        if check.name in self._checks:
            raise ValueError(f"Check with name '{check.name}' is already registered.")
        self._checks[check.name] = check

    def unregister(self, name: str) -> None:
        if name not in self._checks:
            raise CheckNotFound(f"Check with name '{name}' not found.")
        del self._checks[name]

    def get(self, name: str) -> Type[Check]:
        if name not in self._checks:
            raise CheckNotFound(f"Check with name '{name}' not found.")
        return self._checks[name]

    def all(self) -> List[Type[Check]]:
        return list(self._checks.values())


check_registry = CheckRegistry()

@dataclasses.dataclass()
class Checks:
    enabled: List[str] = dataclasses.field(init=True)

    def _get_check(self, name: str) -> Type[Check]:
        return check_registry.get(name)

    def is_enabled(self, name: str) -> bool:
        return name in self.enabled

    async def check(self, name: str, *args: Any, **kwargs: Any) -> None:
        """Find and run the check with the given ``name`` if it is enabled."""
        if self.is_enabled(name):
            log.info("Running check: %r", name)
            check = self._get_check(name)()
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
