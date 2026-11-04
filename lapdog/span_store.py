"""Memory-bounded storage for spans and raw hook events retained by Lapdog."""

import json
import logging
import os
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set


log = logging.getLogger(__name__)

MAX_MEMORY_ENV = "LAPDOG_MAX_MEMORY"

# Python object overhead for a span's dicts, lists, and small strings beyond its JSON size.
_SPAN_OVERHEAD_BYTES = 3500
_LOW_WATERMARK = 0.9
# Fraction of the memory budget given to each raw hook event log; spans get the rest.
RAW_EVENT_LOG_SHARE = 0.1
_RAW_EVENT_LOG_COUNT = 3

_SIZE_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*$", re.IGNORECASE)
_SIZE_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_memory_size(value: str) -> int:
    """Parse sizes like ``512MB``, ``2GB``, ``1.5g``, or ``1048576`` into bytes."""
    match = _SIZE_PATTERN.match(value)
    if not match:
        raise ValueError(f"invalid memory size {value!r}; expected e.g. 512MB or 2GB")
    unit = (match.group(2) or "").lower().rstrip("b").rstrip("i")
    size = int(float(match.group(1)) * _SIZE_UNITS[unit])
    if size <= 0:
        raise ValueError(f"memory size must be positive, got {value!r}")
    return size


def max_memory_from_env() -> Optional[int]:
    value = os.environ.get(MAX_MEMORY_ENV, "").strip()
    if not value:
        return None
    try:
        return parse_memory_size(value)
    except ValueError as e:
        log.warning("Ignoring %s: %s", MAX_MEMORY_ENV, e)
        return None


def span_budget(max_memory_bytes: Optional[int]) -> Optional[int]:
    if max_memory_bytes is None:
        return None
    return int(max_memory_bytes * (1 - RAW_EVENT_LOG_SHARE * _RAW_EVENT_LOG_COUNT))


def raw_event_budget(max_memory_bytes: Optional[int]) -> Optional[int]:
    if max_memory_bytes is None:
        return None
    return int(max_memory_bytes * RAW_EVENT_LOG_SHARE)


def estimate_size(obj: Any) -> int:
    """Approximate in-memory size: UTF-8 JSON length plus fixed Python object overhead."""
    try:
        encoded = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8", errors="replace")
    except (TypeError, ValueError):
        encoded = str(obj).encode("utf-8", errors="replace")
    return len(encoded) + _SPAN_OVERHEAD_BYTES


def trace_key(span: Dict[str, Any]) -> str:
    trace_id = span.get("trace_id")
    if trace_id:
        return str(trace_id)
    return f"span:{span.get('span_id')}"


class SpanStore(List[Dict[str, Any]]):
    """List of spans that evicts the oldest finished traces once over a byte budget.

    Without a budget it behaves exactly like a list. With one, writes must go
    through ``append``, ``insert``, ``extend``, or ``remove_where`` so the size
    accounting stays correct. Traces reported by an active trace source are
    never evicted, since hook handlers still hold references to their spans.
    """

    def __init__(self, max_bytes: Optional[int] = None) -> None:
        super().__init__()
        self.max_bytes = max_bytes
        self.evicted_spans = 0
        self.evicted_traces = 0
        self._sizes: Dict[int, int] = {}
        self._total = 0
        self._unsettled: Dict[int, Dict[str, Any]] = {}
        self._active_sources: List[Callable[[], Iterable[str]]] = []
        self._last_active: FrozenSet[str] = frozenset()
        self._eviction_blocked = False

    @property
    def estimated_bytes(self) -> int:
        return self._total

    def add_active_trace_source(self, source: Callable[[], Iterable[str]]) -> None:
        self._active_sources.append(source)

    def append(self, span: Dict[str, Any]) -> None:
        super().append(span)
        self._track([span])

    def insert(self, index: Any, span: Dict[str, Any]) -> None:
        super().insert(index, span)
        self._track([span])

    def extend(self, spans: Iterable[Dict[str, Any]]) -> None:
        spans = list(spans)
        super().extend(spans)
        self._track(spans)

    def remove_where(self, predicate: Callable[[Dict[str, Any]], bool]) -> None:
        kept = [span for span in self if not predicate(span)]
        if len(kept) == len(self):
            return
        if self.max_bytes is not None:
            kept_ids = {id(span) for span in kept}
            for span in self:
                if id(span) not in kept_ids:
                    self._forget(span)
        self[:] = kept

    def _track(self, spans: List[Dict[str, Any]]) -> None:
        if self.max_bytes is None:
            return
        for span in spans:
            size = estimate_size(span)
            self._sizes[id(span)] = size
            self._total += size
            self._unsettled[id(span)] = span
        active = self._active_trace_ids()
        if active != self._last_active:
            self._last_active = active
            self._eviction_blocked = False
            self._settle(active)
        if self._total > self.max_bytes and not self._eviction_blocked:
            self._evict(active)

    def _forget(self, span: Dict[str, Any]) -> None:
        self._total -= self._sizes.pop(id(span), 0)
        self._unsettled.pop(id(span), None)

    def _active_trace_ids(self) -> FrozenSet[str]:
        active: Set[str] = set()
        for source in self._active_sources:
            active.update(source())
        return frozenset(active)

    def _settle(self, active: FrozenSet[str]) -> None:
        """Re-measure spans of traces that finished, since spans grow after they are appended."""
        for span_id, span in list(self._unsettled.items()):
            if trace_key(span) in active:
                continue
            size = estimate_size(span)
            self._total += size - self._sizes.get(span_id, 0)
            self._sizes[span_id] = size
            del self._unsettled[span_id]

    def _evict(self, active: FrozenSet[str]) -> None:
        assert self.max_bytes is not None
        trace_bytes: Dict[str, int] = {}
        for span in self:
            key = trace_key(span)
            trace_bytes[key] = trace_bytes.get(key, 0) + self._sizes.get(id(span), 0)

        target = self.max_bytes * _LOW_WATERMARK
        remaining = self._total
        evicted: Set[str] = set()
        for key, size in trace_bytes.items():
            if remaining <= target:
                break
            if key in active:
                continue
            evicted.add(key)
            remaining -= size

        if not evicted:
            self._eviction_blocked = True
            log.warning(
                "Span store is over its %d byte budget but every retained trace is still active",
                self.max_bytes,
            )
            return

        before = len(self)
        self.remove_where(lambda span: trace_key(span) in evicted)
        self.evicted_spans += before - len(self)
        self.evicted_traces += len(evicted)
        log.info(
            "Evicted %d spans from %d traces; ~%d bytes retained (budget %d)",
            before - len(self),
            len(evicted),
            self._total,
            self.max_bytes,
        )


class RawEventLog(List[Dict[str, Any]]):
    """List of raw hook events that drops the oldest events once over a byte budget."""

    def __init__(self, max_bytes: Optional[int] = None) -> None:
        super().__init__()
        self.max_bytes = max_bytes
        self._sizes: List[int] = []
        self._total = 0

    def append(self, event: Dict[str, Any]) -> None:
        super().append(event)
        if self.max_bytes is None:
            return
        size = estimate_size(event)
        self._sizes.append(size)
        self._total += size
        if self._total <= self.max_bytes:
            return
        target = self.max_bytes * _LOW_WATERMARK
        drop = 0
        while drop < len(self._sizes) - 1 and self._total > target:
            self._total -= self._sizes[drop]
            drop += 1
        del self[:drop]
        del self._sizes[:drop]
