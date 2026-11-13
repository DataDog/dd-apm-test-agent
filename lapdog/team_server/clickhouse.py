"""Run and talk to the ClickHouse server that stores ``lapdog server``'s spans.

Lapdog runs ClickHouse as a child process bound to 127.0.0.1 with a generated
config tuned for small machines (low memory caps, system log tables off), and
talks to it over the HTTP interface with aiohttp.
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
import urllib.error
import urllib.request

import aiohttp

from ..paths import BIN_DIR

log = logging.getLogger(__name__)

CLICKHOUSE_VERSION = "26.8.34.13"
_RELEASE_URL = f"https://github.com/ClickHouse/ClickHouse/releases/download/v{CLICKHOUSE_VERSION}-lts"

# (system, machine) -> (release asset, sha256). Linux assets are tarballs holding usr/bin/clickhouse.
_ASSETS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("Darwin", "arm64"): (
        "clickhouse-macos-aarch64",
        "d1666bb409243aee970c6ea76d8b97e18cbcb6351d61d52dd3d88baab14d26db",
    ),
    ("Darwin", "x86_64"): (
        "clickhouse-macos",
        "45b51d207a4df5f6b2cf3d47576b5a41c3301f0a83b6322c1b4de3fb359e06f2",
    ),
    ("Linux", "x86_64"): (
        f"clickhouse-common-static-{CLICKHOUSE_VERSION}-amd64.tgz",
        "d64b69ce0a13a1e89960b5ffcc6f07ea471b314ae21348e457dd232c8fa5506e",
    ),
    ("Linux", "aarch64"): (
        f"clickhouse-common-static-{CLICKHOUSE_VERSION}-arm64.tgz",
        "152b78259e897481260d65914bf40a63148235b072548e0229c11d9b7a80de37",
    ),
}
_MACHINE_ALIASES = {"amd64": "x86_64", "arm64": "aarch64"}


class ClickHouseError(Exception):
    pass


def _platform_asset() -> Tuple[str, str]:
    system = platform.system()
    machine = platform.machine()
    if system == "Linux":
        machine = _MACHINE_ALIASES.get(machine, machine)
    asset = _ASSETS.get((system, machine))
    if asset is None:
        raise ClickHouseError(
            f"lapdog server has no ClickHouse build for {system}/{machine}; "
            "install clickhouse yourself and pass --clickhouse-binary"
        )
    return asset


def bundled_binary_path() -> str:
    return os.path.join(BIN_DIR, "clickhouse")


def resolve_binary(explicit: Optional[str] = None) -> Optional[str]:
    """Find a clickhouse binary: the explicit path, then ``clickhouse`` on PATH, then a previous download."""
    if explicit:
        path = os.path.abspath(os.path.expanduser(explicit))
        if not os.access(path, os.X_OK):
            raise ClickHouseError(f"--clickhouse-binary {explicit!r} is not an executable file")
        return path
    on_path = shutil.which("clickhouse")
    if on_path:
        return on_path
    bundled = bundled_binary_path()
    if os.access(bundled, os.X_OK):
        return bundled
    return None


def download_binary(progress: bool = True) -> str:
    """Download the pinned ClickHouse release for this platform into ``~/.lapdog/bin``, checking its sha256."""
    asset, expected_sha = _platform_asset()
    url = f"{_RELEASE_URL}/{asset}"
    os.makedirs(BIN_DIR, exist_ok=True)
    target = bundled_binary_path()
    if progress:
        print(f"Downloading ClickHouse {CLICKHOUSE_VERSION} ({asset}) to {target} ...", file=sys.stderr)

    digest = hashlib.sha256()
    fd, tmp_path = tempfile.mkstemp(dir=BIN_DIR, prefix=".clickhouse-download-")
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=60) as resp:  # nosec: pinned + hashed
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            last_report = 0.0
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress and total and time.monotonic() - last_report > 1:
                    last_report = time.monotonic()
                    print(f"  {done * 100 // total}% of {total // (1024 * 1024)}MB", file=sys.stderr)
        if digest.hexdigest() != expected_sha:
            raise ClickHouseError(f"checksum mismatch for {asset}: got {digest.hexdigest()}, expected {expected_sha}")

        if asset.endswith(".tgz"):
            _extract_binary(tmp_path, target)
        else:
            os.chmod(tmp_path, 0o755)
            os.replace(tmp_path, target)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    if progress:
        print("ClickHouse downloaded.", file=sys.stderr)
    return target


def _extract_binary(tarball: str, target: str) -> None:
    with tarfile.open(tarball, "r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.isfile() and m.name.endswith("usr/bin/clickhouse")), None)
        if member is None:
            raise ClickHouseError("usr/bin/clickhouse not found in the ClickHouse release tarball")
        source = tar.extractfile(member)
        assert source is not None
        tmp_target = target + ".tmp"
        with source, open(tmp_target, "wb") as out:
            shutil.copyfileobj(source, out)
    os.chmod(tmp_target, 0o755)
    os.replace(tmp_target, target)


def ensure_binary(explicit: Optional[str] = None, progress: bool = True) -> str:
    return resolve_binary(explicit) or download_binary(progress=progress)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _xml_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_config(base_dir: str, port: int, password_sha256: str, max_memory_bytes: int) -> str:
    """Render a ClickHouse server config for a small, single-tenant, localhost-only install.

    Only the HTTP interface is opened. System log tables (query_log, part_log,
    trace_log, metric_log, ...) are left unconfigured so they aren't created;
    otherwise they grow without bound and fill small disks first.
    """
    d = _xml_escape(base_dir.rstrip("/"))
    query_memory = max(256 * 1024**2, int(max_memory_bytes * 0.8))
    return f"""<?xml version="1.0"?>
<clickhouse>
    <logger>
        <level>warning</level>
        <log>{d}/log/clickhouse-server.log</log>
        <errorlog>{d}/log/clickhouse-server.err.log</errorlog>
        <size>10M</size>
        <count>3</count>
    </logger>
    <listen_host>127.0.0.1</listen_host>
    <http_port>{port}</http_port>
    <path>{d}/data/</path>
    <tmp_path>{d}/tmp/</tmp_path>
    <user_files_path>{d}/user_files/</user_files_path>
    <format_schema_path>{d}/format_schemas/</format_schema_path>
    <custom_cached_disks_base_directory>{d}/caches/</custom_cached_disks_base_directory>
    <timezone>UTC</timezone>
    <mlock_executable>false</mlock_executable>
    <max_server_memory_usage>{max_memory_bytes}</max_server_memory_usage>
    <mark_cache_size>67108864</mark_cache_size>
    <index_mark_cache_size>16777216</index_mark_cache_size>
    <uncompressed_cache_size>0</uncompressed_cache_size>
    <max_concurrent_queries>32</max_concurrent_queries>
    <background_pool_size>4</background_pool_size>
    <background_schedule_pool_size>8</background_schedule_pool_size>
    <disable_internal_dns_cache>1</disable_internal_dns_cache>
    <merge_tree>
        <!-- Defaults assume a 16-thread merge pool; scale them to the smaller pool above. -->
        <number_of_free_entries_in_pool_to_execute_mutation>2</number_of_free_entries_in_pool_to_execute_mutation>
        <number_of_free_entries_in_pool_to_lower_max_size_of_merge>2</number_of_free_entries_in_pool_to_lower_max_size_of_merge>
        <number_of_free_entries_in_pool_to_execute_optimize_entire_partition>2</number_of_free_entries_in_pool_to_execute_optimize_entire_partition>
        <!-- Free disk soon after a partition drop rather than after the default 8 minutes. -->
        <old_parts_lifetime>30</old_parts_lifetime>
    </merge_tree>
    <users>
        <default>
            <password_sha256_hex>{password_sha256}</password_sha256_hex>
            <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
            <profile>default</profile>
            <quota>default</quota>
        </default>
    </users>
    <profiles>
        <default>
            <max_memory_usage>{query_memory}</max_memory_usage>
            <max_threads>4</max_threads>
            <log_queries>0</log_queries>
        </default>
    </profiles>
    <quotas><default/></quotas>
</clickhouse>
"""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _set_parent_death_signal() -> None:
    """On Linux, have the kernel stop ClickHouse if lapdog dies without cleaning up."""
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            ctypes.CDLL("libc.so.6", use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
        except Exception:
            pass


class ClickHouseProcess:
    """A ClickHouse server child process with its own config and data under ``base_dir``."""

    def __init__(self, binary: str, base_dir: str, max_memory_bytes: int) -> None:
        self.binary = binary
        self.base_dir = os.path.abspath(base_dir)
        self.max_memory_bytes = max_memory_bytes
        self.port = 0
        self.password = ""
        self.proc: Optional["subprocess.Popen[bytes]"] = None
        self.restarts = 0
        self._stopping = False
        self._pid_file = os.path.join(self.base_dir, "clickhouse.pid")

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def pid(self) -> Optional[int]:
        return self.proc.pid if self.proc else None

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _password(self) -> str:
        path = os.path.join(self.base_dir, "password")
        try:
            with open(path) as f:
                password = f.read().strip()
            if password:
                return password
        except OSError:
            pass
        password = secrets.token_hex(24)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(password)
        return password

    def _stop_stale(self) -> None:
        """Stop a ClickHouse left over from a lapdog that died, since it holds the data directory lock."""
        try:
            with open(self._pid_file) as f:
                pid = int(f.read().strip())
        except (OSError, ValueError):
            return
        if not _pid_alive(pid):
            return
        log.warning("Stopping leftover ClickHouse process %d", pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return
        deadline = time.monotonic() + 20
        while _pid_alive(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        if _pid_alive(pid):
            os.kill(pid, signal.SIGKILL)

    def start(self, timeout: float = 60.0) -> None:
        """Write the config, spawn ClickHouse, and block until it answers ``/ping``."""
        for sub in ("data", "tmp", "log", "user_files", "format_schemas", "caches"):
            os.makedirs(os.path.join(self.base_dir, sub), exist_ok=True)
        self._stop_stale()
        self.password = self._password()
        self.port = _free_port()
        config_path = os.path.join(self.base_dir, "config.xml")
        with open(config_path, "w") as f:
            f.write(
                render_config(
                    self.base_dir,
                    self.port,
                    hashlib.sha256(self.password.encode()).hexdigest(),
                    self.max_memory_bytes,
                )
            )

        stdout = open(os.path.join(self.base_dir, "log", "stdout.log"), "ab")
        self.proc = subprocess.Popen(
            [self.binary, "server", f"--config-file={config_path}"],
            cwd=self.base_dir,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            preexec_fn=_set_parent_death_signal if sys.platform.startswith("linux") else None,
        )
        stdout.close()
        with open(self._pid_file, "w") as f:
            f.write(str(self.proc.pid))
        self._wait_ready(timeout)

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                raise ClickHouseError(
                    f"ClickHouse exited with code {self.proc.returncode}; see {self.base_dir}/log/ for details"
                )
            try:
                with urllib.request.urlopen(f"{self.url}/ping", timeout=1) as resp:
                    if resp.status == 200:
                        return
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.2)
        self.stop()
        raise ClickHouseError(f"ClickHouse did not become ready within {timeout:.0f}s; see {self.base_dir}/log/")

    def stop(self, timeout: float = 20.0) -> None:
        self._stopping = True
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        try:
            os.remove(self._pid_file)
        except OSError:
            pass

    async def supervise(self, on_restart: Optional[Any] = None) -> None:
        """Restart ClickHouse with backoff if it exits unexpectedly. Runs until cancelled or stopped."""
        backoff = 1.0
        while not self._stopping:
            await asyncio.sleep(1)
            if self._stopping or self.running:
                if self.running:
                    backoff = 1.0
                continue
            code = self.proc.returncode if self.proc else None
            log.error("ClickHouse exited unexpectedly (code %s); restarting in %.0fs", code, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            if self._stopping:
                return
            try:
                port = self.port
                await asyncio.get_running_loop().run_in_executor(None, self._restart_same_port, port)
                self.restarts += 1
                if on_restart is not None:
                    on_restart()
            except Exception as e:
                log.error("Failed to restart ClickHouse: %s", e)

    def _restart_same_port(self, port: int) -> None:
        config_path = os.path.join(self.base_dir, "config.xml")
        stdout = open(os.path.join(self.base_dir, "log", "stdout.log"), "ab")
        self.proc = subprocess.Popen(
            [self.binary, "server", f"--config-file={config_path}"],
            cwd=self.base_dir,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            preexec_fn=_set_parent_death_signal if sys.platform.startswith("linux") else None,
        )
        stdout.close()
        self.port = port
        with open(self._pid_file, "w") as f:
            f.write(str(self.proc.pid))
        self._wait_ready(60)


def quote(value: Any) -> str:
    """Render a Python value as a ClickHouse SQL literal."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return f"'{text}'"


def quote_identifier(name: str) -> str:
    return "`" + name.replace("\\", "\\\\").replace("`", "\\`") + "`"


class ClickHouseClient:
    """Minimal async client for the ClickHouse HTTP interface."""

    def __init__(self, url: str, user: str = "default", password: str = "", database: str = "default") -> None:
        self.url = url.rstrip("/")
        self.user = user
        self.password = password
        self.database = database
        self._session: Optional[aiohttp.ClientSession] = None

    def _client(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120),
                headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.password},
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _post(self, body: bytes, settings: Optional[Dict[str, Any]] = None) -> str:
        params = {"database": self.database, "output_format_json_quote_64bit_integers": "0"}
        for key, value in (settings or {}).items():
            params[key] = str(value)
        async with self._client().post(self.url + "/", params=params, data=body) as resp:
            text = await resp.text()
            if resp.status != 200:
                raise ClickHouseError(text.strip()[:2000])
            return text

    async def command(self, sql: str, settings: Optional[Dict[str, Any]] = None) -> None:
        await self._post(sql.encode(), settings)

    async def query(self, sql: str, settings: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        text = await self._post((sql + "\nFORMAT JSONEachRow").encode(), settings)
        return [json.loads(line) for line in text.splitlines() if line]

    async def insert(self, table: str, rows: Iterable[Dict[str, Any]]) -> None:
        body = "\n".join(json.dumps(row, separators=(",", ":"), default=str) for row in rows)
        if not body:
            return
        sql = f"INSERT INTO {table} FORMAT JSONEachRow\n"
        await self._post(
            (sql + body).encode(),
            {"async_insert": 1, "wait_for_async_insert": 1, "input_format_skip_unknown_fields": 1},
        )

    async def ping(self) -> bool:
        try:
            async with self._client().get(self.url + "/ping") as resp:
                return resp.status == 200
        except aiohttp.ClientError:
            return False
