"""GitHub Copilot CLI launcher with OpenTelemetry export pointed at Lapdog."""

import os
import shutil
import sys
from typing import Dict
from typing import List
from typing import Optional

from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.os_runner import run
from lapdog.cli.runtime import ensure_lapdog_running


def _resolved_otlp_http_port() -> int:
    """Infer the OTLP HTTP port the same way the agent does: OTLP_HTTP_PORT env, else 4318."""
    return int(os.environ.get("OTLP_HTTP_PORT", "4318"))


def _default_otel_exporter_endpoint() -> str:
    return f"http://localhost:{_resolved_otlp_http_port()}"


def _merge_otel_resource_attributes(env: Dict[str, str], attrs: List[str]) -> None:
    """Prepend Lapdog resource attrs while preserving user-provided attrs."""
    merged = [attr for attr in attrs if attr]
    existing = env.get("OTEL_RESOURCE_ATTRIBUTES")
    if existing:
        merged.extend(part.strip() for part in existing.split(",") if part.strip())
    if merged:
        env["OTEL_RESOURCE_ATTRIBUTES"] = ",".join(merged)


def _run_copilot(args: Optional[List[str]] = None, launch_bin: Optional[str] = None) -> None:
    """Run GitHub Copilot CLI with OpenTelemetry export pointed at Lapdog."""
    if args is None:
        args = []
    launch_bin = launch_bin or shutil.which("copilot")
    if not launch_bin:
        print("[lapdog] 'copilot' not found in PATH", file=sys.stderr)
        sys.exit(1)

    env = os.environ.copy()
    env.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", _default_otel_exporter_endpoint())
    env.setdefault("OTEL_SERVICE_NAME", "github-copilot-cli")
    env.setdefault("COPILOT_OTEL_SOURCE_NAME", "github.copilot")
    env.setdefault("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false")
    _merge_otel_resource_attributes(
        env,
        [
            "service.name=github-copilot-cli",
            "agent.framework=github-copilot",
            "agent.runtime=cli",
        ],
    )

    run(bin_path=launch_bin, argv=([launch_bin] + args), env=env)


def cmd_copilot(sub_cmd_args: List[str], forward_data: bool, launch_bin: Optional[str] = None) -> None:
    """Ensure lapdog is running, then launch GitHub Copilot CLI with OTel tracing."""
    port = ensure_lapdog_running(forward_data, detached=True)
    if port is None:
        print("[lapdog] Could not determine lapdog port. Run 'lapdog status' for details.", file=sys.stderr)
        sys.exit(1)

    print(build_running_banner(data_type="coding session"))
    _run_copilot(args=sub_cmd_args, launch_bin=launch_bin)
