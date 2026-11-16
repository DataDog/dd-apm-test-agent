"""Settings for ``lapdog server``: flags, environment variables, and the persisted settings file."""

import argparse
import dataclasses
import json
import os
import re
import shutil
from typing import Any
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional

from ..paths import SERVER_DIR
from ..span_store import parse_memory_size

SETTINGS_FILE = "server.json"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8126
DEFAULT_RETENTION_DAYS = 30
MIN_RETENTION_DAYS = 1
MAX_RETENTION_DAYS = 3650
DEFAULT_MAX_DISK_CAP = 20 * 1024**3
MIN_MAX_DISK = 1024**3
DEFAULT_CLICKHOUSE_MAX_MEMORY = "1GB"
DATABASE = "lapdog"

_RETENTION_PATTERN = re.compile(r"^\s*(\d+)\s*(d|days?|w|weeks?)?\s*$", re.IGNORECASE)


def parse_retention_days(value: str) -> int:
    """Parse ``30d``, ``2w``, or ``14`` (days) into a whole number of days, within bounds."""
    match = _RETENTION_PATTERN.match(str(value))
    if not match:
        raise ValueError(f"invalid retention {value!r}; expected e.g. 30d or 2w")
    days = int(match.group(1))
    if (match.group(2) or "d").lower().startswith("w"):
        days *= 7
    if not MIN_RETENTION_DAYS <= days <= MAX_RETENTION_DAYS:
        raise ValueError(f"retention must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS} days, got {days}")
    return days


def parse_max_disk(value: str) -> int:
    """Parse ``20GB``, ``500MB``, or ``1TiB`` into bytes, at least 1 GB."""
    size = parse_memory_size(str(value))
    if size < MIN_MAX_DISK:
        raise ValueError(f"max disk must be at least 1GB, got {value!r}")
    return size


def format_bytes(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024 or unit == "TB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"


def default_max_disk(data_dir: str) -> int:
    """Return the smaller of 20 GiB and half the free disk where the data lives."""
    os.makedirs(data_dir, exist_ok=True)
    free = shutil.disk_usage(data_dir).free
    return max(MIN_MAX_DISK, min(DEFAULT_MAX_DISK_CAP, free // 2))


class Settings(NamedTuple):
    """The live-adjustable controls, persisted to ``<data-dir>/server.json``."""

    retention_days: int
    max_disk_bytes: int


@dataclasses.dataclass
class ServerConfig:
    data_dir: str
    retention_days: int
    max_disk_bytes: int
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    clickhouse_binary: Optional[str] = None
    clickhouse_max_memory_bytes: int = parse_memory_size(DEFAULT_CLICKHOUSE_MAX_MEMORY)
    forward_to_datadog: bool = False
    dd_site: str = "datadoghq.com"
    dd_api_key: str = ""
    database: str = DATABASE

    @property
    def settings(self) -> Settings:
        return Settings(self.retention_days, self.max_disk_bytes)


def load_settings(data_dir: str) -> Optional[Settings]:
    path = os.path.join(data_dir, SETTINGS_FILE)
    try:
        with open(path) as f:
            raw = json.load(f)
        return Settings(int(raw["retention_days"]), int(raw["max_disk_bytes"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def save_settings(data_dir: str, settings: Settings) -> None:
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, SETTINGS_FILE)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(settings._asdict(), f, indent=2)
    os.replace(tmp, path)


def _env(name: str) -> Optional[str]:
    value = os.environ.get(f"LAPDOG_SERVER_{name}", "").strip()
    return value or None


def _env_flag(name: str) -> bool:
    return (_env(name) or "").lower() in ("1", "true", "yes", "on")


def add_server_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the flags shared by ``lapdog server start`` and ``python -m lapdog.team_server``.

    Every flag falls back to a ``LAPDOG_SERVER_*`` environment variable, for
    Docker and hosting platforms.
    """
    parser.add_argument("--host", default=_env("HOST") or DEFAULT_HOST, help="Address to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=int(_env("PORT") or DEFAULT_PORT), help="Port (default 8126)")
    parser.add_argument("--data-dir", default=_env("DATA_DIR") or SERVER_DIR, help="Where spans and settings live")
    parser.add_argument("--retention", default=_env("RETENTION"), help="Keep spans this long, e.g. 30d (default 30d)")
    parser.add_argument(
        "--max-disk",
        default=_env("MAX_DISK"),
        help="Disk cap for stored spans, e.g. 20GB (default min(20GB, 50%% free))",
    )
    parser.add_argument("--clickhouse-binary", default=_env("CLICKHOUSE_BINARY"), help="Path to a clickhouse binary")
    parser.add_argument(
        "--clickhouse-max-memory",
        default=_env("CLICKHOUSE_MAX_MEMORY") or DEFAULT_CLICKHOUSE_MAX_MEMORY,
        help="Memory cap for the ClickHouse process (default 1GB)",
    )
    parser.add_argument(
        "--forward-to-datadog",
        action="store_true",
        default=_env_flag("FORWARD_TO_DATADOG"),
        help="Also send spans to Datadog (uses DD_API_KEY and DD_SITE)",
    )


def config_from_args(args: argparse.Namespace) -> ServerConfig:
    """Resolve the effective config. Flags override the saved settings, and are saved in turn."""
    data_dir = os.path.abspath(os.path.expanduser(args.data_dir))
    saved = load_settings(data_dir)
    retention_days = (
        parse_retention_days(args.retention)
        if args.retention
        else (saved.retention_days if saved else DEFAULT_RETENTION_DAYS)
    )
    max_disk_bytes = (
        parse_max_disk(args.max_disk)
        if args.max_disk
        else (saved.max_disk_bytes if saved else default_max_disk(data_dir))
    )
    settings = Settings(retention_days, max_disk_bytes)
    if settings != saved:
        save_settings(data_dir, settings)

    return ServerConfig(
        data_dir=data_dir,
        retention_days=retention_days,
        max_disk_bytes=max_disk_bytes,
        host=args.host,
        port=args.port,
        clickhouse_binary=args.clickhouse_binary,
        clickhouse_max_memory_bytes=parse_memory_size(args.clickhouse_max_memory),
        forward_to_datadog=args.forward_to_datadog,
        dd_site=os.environ.get("DD_SITE", "datadoghq.com"),
        dd_api_key=os.environ.get("DD_API_KEY", ""),
    )


def settings_to_json(settings: Settings) -> Dict[str, Any]:
    return {
        "retention": f"{settings.retention_days}d",
        "retention_days": settings.retention_days,
        "max_disk": format_bytes(settings.max_disk_bytes),
        "max_disk_bytes": settings.max_disk_bytes,
    }


def parse_settings_update(body: Any, current: Settings) -> Settings:
    """Validate a settings update (``{"retention": "14d", "max_disk": "50GB"}``) against the current settings."""
    if not isinstance(body, dict):
        raise ValueError("expected a JSON object")
    unknown: List[str] = [key for key in body if key not in ("retention", "max_disk")]
    if unknown:
        raise ValueError(f"unknown settings: {', '.join(sorted(unknown))}")
    retention_days = parse_retention_days(body["retention"]) if "retention" in body else current.retention_days
    max_disk_bytes = parse_max_disk(body["max_disk"]) if "max_disk" in body else current.max_disk_bytes
    return Settings(retention_days, max_disk_bytes)
