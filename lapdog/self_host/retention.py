"""Retention and disk-cap enforcement for ``lapdog server``.

Spans live in daily partitions. Every few minutes (and right after a settings
change) the enforcer:

1. drops partitions older than the retention window;
2. while stored data exceeds the disk cap, or free disk is low, drops
   the oldest remaining partition (never today's);
3. if only today's data is left and limits are still exceeded, pauses ingest
   (intake answers 503) until usage is back under the cap. Queries keep working.

The table TTL is a backstop; partition drops do the actual cleanup.
"""

import asyncio
import dataclasses
import datetime
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from .clickhouse import ClickHouseClient
from .clickhouse import quote
from .clickhouse import quote_identifier
from .config import Settings
from .schema import spans_ttl

log = logging.getLogger(__name__)

ENFORCE_INTERVAL_SECONDS = 300
# Free-disk floors: a fraction of the disk, capped so big disks aren't held to e.g. 5% of 2TB.
LOW_FREE_RATIO = 0.05
LOW_FREE_CAP_BYTES = 2 * 1024**3
CRITICAL_FREE_RATIO = 0.02
CRITICAL_FREE_CAP_BYTES = 512 * 1024**2


@dataclasses.dataclass
class ServerState:
    settings: Settings
    ingest_paused: bool = False
    pause_reason: Optional[str] = None
    last_check: Optional[str] = None
    last_action: Optional[Dict[str, Any]] = None


@dataclasses.dataclass
class DiskUsage:
    used_bytes: int
    pending_free_bytes: int
    free_bytes: int
    total_bytes: int

    def free_below(self, ratio: float, cap_bytes: int) -> bool:
        """Whether free space (counting parts about to be deleted) is under ``min(ratio * total, cap)``."""
        if not self.total_bytes:
            return False
        return self.free_bytes + self.pending_free_bytes < min(ratio * self.total_bytes, cap_bytes)


def _today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def _partition_id(day: datetime.date) -> str:
    return day.strftime("%Y%m%d")


def _partition_date(partition_id: str) -> Optional[datetime.date]:
    try:
        return datetime.datetime.strptime(partition_id, "%Y%m%d").date()
    except ValueError:
        return None


class RetentionEnforcer:
    def __init__(self, client: ClickHouseClient, database: str, state: ServerState) -> None:
        self.client = client
        self.database = database
        self.state = state
        self.table = f"{quote_identifier(database)}.spans"
        self._wake = asyncio.Event()
        self._lock = asyncio.Lock()

    def trigger(self) -> None:
        self._wake.set()

    async def run(self, interval: float = ENFORCE_INTERVAL_SECONDS) -> None:
        while True:
            try:
                await self.enforce()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.error("Retention check failed: %s", e)
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def apply_settings(self, settings: Settings) -> Dict[str, Any]:
        """Switch to new settings: update the table TTL, then enforce right away."""
        if settings.retention_days != self.state.settings.retention_days:
            await self.client.command(
                f"ALTER TABLE {self.table} MODIFY TTL {spans_ttl(settings.retention_days)}",
                {"materialize_ttl_after_modify": 0},
            )
        self.state.settings = settings
        return await self.enforce()

    async def partitions(self) -> List[Tuple[str, int]]:
        """Active ``(partition_id, bytes_on_disk)`` for the spans table, oldest first."""
        rows = await self.client.query(
            "SELECT partition_id, sum(bytes_on_disk) AS bytes FROM system.parts "
            f"WHERE database = {quote(self.database)} AND table = 'spans' AND active "
            "GROUP BY partition_id ORDER BY partition_id"
        )
        return [(str(row["partition_id"]), int(row["bytes"])) for row in rows]

    async def disk_usage(self) -> DiskUsage:
        parts = await self.client.query(
            "SELECT sumIf(bytes_on_disk, active) AS used, sumIf(bytes_on_disk, NOT active) AS pending "
            f"FROM system.parts WHERE database = {quote(self.database)}"
        )
        disks = await self.client.query("SELECT free_space, total_space FROM system.disks WHERE name = 'default'")
        return DiskUsage(
            used_bytes=int(parts[0]["used"] or 0) if parts else 0,
            pending_free_bytes=int(parts[0]["pending"] or 0) if parts else 0,
            free_bytes=int(disks[0]["free_space"]) if disks else 0,
            total_bytes=int(disks[0]["total_space"]) if disks else 0,
        )

    async def _drop(self, partition_id: str) -> None:
        await self.client.command(f"ALTER TABLE {self.table} DROP PARTITION ID {quote(partition_id)}")

    async def enforce(self, today: Optional[datetime.date] = None) -> Dict[str, Any]:
        async with self._lock:
            return await self._enforce(today or _today())

    async def _enforce(self, today: datetime.date) -> Dict[str, Any]:
        settings = self.state.settings
        today_id = _partition_id(today)
        cutoff_id = _partition_id(today - datetime.timedelta(days=settings.retention_days))
        dropped: List[Dict[str, Any]] = []

        partitions = await self.partitions()
        for partition_id, size in partitions:
            if partition_id < cutoff_id:
                await self._drop(partition_id)
                dropped.append({"partition": partition_id, "bytes": size, "reason": "retention"})
        remaining = [(pid, size) for pid, size in partitions if pid >= cutoff_id]

        usage = await self.disk_usage()
        while True:
            reason = None
            if usage.used_bytes > settings.max_disk_bytes:
                reason = "max_disk"
            elif usage.free_below(LOW_FREE_RATIO, LOW_FREE_CAP_BYTES):
                reason = "low_free_disk"
            droppable = [(pid, size) for pid, size in remaining if pid < today_id]
            if reason is None or not droppable:
                break
            partition_id, size = droppable[0]
            await self._drop(partition_id)
            dropped.append({"partition": partition_id, "bytes": size, "reason": reason})
            remaining = [(pid, s) for pid, s in remaining if pid != partition_id]
            usage = await self.disk_usage()

        pause_reason = None
        if usage.used_bytes > settings.max_disk_bytes:
            pause_reason = "max_disk"
        elif usage.free_below(CRITICAL_FREE_RATIO, CRITICAL_FREE_CAP_BYTES):
            pause_reason = "low_free_disk"
        if pause_reason and not self.state.ingest_paused:
            log.warning(
                "Pausing ingest: %s (used %d bytes, cap %d)", pause_reason, usage.used_bytes, settings.max_disk_bytes
            )
        elif not pause_reason and self.state.ingest_paused:
            log.warning("Resuming ingest: usage is back under the limits")
        self.state.ingest_paused = pause_reason is not None
        self.state.pause_reason = pause_reason

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.state.last_check = now
        oldest = _partition_date(remaining[0][0]) if remaining else None
        action = {
            "at": now,
            "dropped_partitions": dropped,
            "effective_retention_days": (today - oldest).days + 1 if oldest else 0,
            "ingest_paused": self.state.ingest_paused,
        }
        if dropped:
            for drop in dropped:
                log.warning("Dropped spans for %s (%s, %d bytes)", drop["partition"], drop["reason"], drop["bytes"])
            self.state.last_action = action
        return action

    async def status(self) -> Dict[str, Any]:
        usage = await self.disk_usage()
        partitions = await self.partitions()
        rows = await self.client.query(f"SELECT count() AS c FROM {self.table}")
        days = [_partition_date(pid) for pid, _ in partitions]
        valid_days = [day for day in days if day is not None]
        return {
            "disk": {
                "used_bytes": usage.used_bytes,
                "free_bytes": usage.free_bytes,
                "total_bytes": usage.total_bytes,
            },
            "oldest_day": valid_days[0].isoformat() if valid_days else None,
            "newest_day": valid_days[-1].isoformat() if valid_days else None,
            "span_rows": int(rows[0]["c"]) if rows else 0,
            "ingest_paused": self.state.ingest_paused,
            "pause_reason": self.state.pause_reason,
            "last_check": self.state.last_check,
            "last_action": self.state.last_action,
        }
