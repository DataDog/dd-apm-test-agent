"""``lapdog forward``: choose where lapdog sends traces besides its own memory."""

import json
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
import urllib.error
import urllib.request

from lapdog.cli.runtime import lapdog_alive
from lapdog.cli.runtime import read_pid_file
from lapdog.forwarding import ForwardingConfig
from lapdog.forwarding import load_forwarding_config
from lapdog.forwarding import normalize_server_url
from lapdog.forwarding import save_forwarding_config

FORWARD_USAGE = (
    "Usage: lapdog forward                                  Show where traces are forwarded\n"
    "       lapdog forward <self-hosted-url> [--include-coding-agents]\n"
    "                                                       Also send traces to a Self-hosted lapdog server\n"
    "       lapdog forward off                              Stop sending to the Self-hosted server\n"
    "       lapdog forward datadog on|off                   Send to Datadog (needs --forward credentials)\n"
    "\n"
    "Traces always stay in lapdog's memory too. Coding-agent sessions (Claude Code, Codex, pi)\n"
    "go to the Self-hosted server only with --include-coding-agents.\n"
)


def _request(url: str, body: Optional[Dict[str, Any]] = None, timeout: float = 5) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST" if body is not None else "GET"
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or "null")


def _lapdog_url() -> Optional[str]:
    if not lapdog_alive():
        return None
    _, port = read_pid_file()
    return f"http://127.0.0.1:{port}/lapdog/forwarding"


def _update_running(change: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    url = _lapdog_url()
    if url is None:
        return None
    try:
        result = _request(url, change)
    except urllib.error.HTTPError as e:
        message = json.loads(e.read().decode() or "{}").get("error", f"HTTP {e.code}")
        print(f"[lapdog] {message}", file=sys.stderr)
        sys.exit(1)
    return result if isinstance(result, dict) else None


def _print_status(state: Optional[Dict[str, Any]]) -> None:
    if state is None:
        config = load_forwarding_config()
        target = config.self_hosted or "off"
        print(f"[lapdog] Lapdog isn't running. Self-hosted: {target}. Datadog: set with 'lapdog --forward start'.")
        return
    self_hosted, datadog = state["self_hosted"], state["datadog"]
    if self_hosted["enabled"]:
        agents = "with" if self_hosted["coding_agents"] else "without"
        reach = {True: "reachable", False: "unreachable", None: "checking"}[self_hosted["reachable"]]
        print(f"Self-hosted  {self_hosted['url']} ({reach}, {agents} coding agents)")
        print(f"             {self_hosted['spans_last_hour']} spans in the last hour")
        if self_hosted["last_error"]:
            print(f"             last error: {self_hosted['last_error']}")
    else:
        print("Self-hosted  off ('lapdog forward <url>' to send there)")
    if datadog["enabled"]:
        print(f"Datadog      on ({datadog['site']}), {datadog['spans_last_hour']} spans in the last hour")
        if datadog["last_error"]:
            print(f"             last error: {datadog['last_error']}")
    else:
        print("Datadog      off" + ("" if datadog["available"] else " (start lapdog with --forward to enable)"))


def _check_self_hosted(url: str) -> None:
    try:
        info = _request(f"{url}/info")
    except Exception as e:
        print(f"[lapdog] Couldn't reach {url}: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(info, dict) or info.get("mode") != "server":
        print(f"[lapdog] {url} isn't a lapdog server (its /info has no mode: server).", file=sys.stderr)
        sys.exit(1)


def cmd_forward(argv: List[str]) -> None:
    if not argv:
        url = _lapdog_url()
        _print_status(_request(url) if url else None)
        return
    if argv[0] in ("-h", "--help"):
        print(FORWARD_USAGE)
        return
    if argv[0] == "datadog":
        if len(argv) != 2 or argv[1] not in ("on", "off"):
            print(FORWARD_USAGE, file=sys.stderr)
            sys.exit(2)
        state = _update_running({"datadog": argv[1] == "on"})
        if state is None:
            print("[lapdog] Lapdog isn't running. Start it with 'lapdog --forward start' to send to Datadog.")
            return
        _print_status(state)
        return
    if argv[0] == "off":
        state = _update_running({"self_hosted": None})
        if state is None:
            config = load_forwarding_config()
            save_forwarding_config(ForwardingConfig(None, config.self_hosted_coding_agents))
        print("[lapdog] Stopped sending to the Self-hosted server. Traces stay in lapdog's memory.")
        return

    include_coding_agents = "--include-coding-agents" in argv[1:]
    unknown = [a for a in argv[1:] if a != "--include-coding-agents"]
    server = normalize_server_url(argv[0])
    if server is None or unknown:
        print(FORWARD_USAGE, file=sys.stderr)
        sys.exit(2)
    _check_self_hosted(server)
    change = {"self_hosted": server, "self_hosted_coding_agents": include_coding_agents}
    state = _update_running(change)
    if state is None:
        save_forwarding_config(ForwardingConfig(server, include_coding_agents))
    agents = "including" if include_coding_agents else "not including"
    print(f"[lapdog] Sending traces to {server} ({agents} coding-agent sessions). They stay in memory here too.")
