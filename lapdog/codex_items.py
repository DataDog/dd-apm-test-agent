"""Structured tool completions from Codex transcripts."""

import re
import shlex
from typing import Any
from typing import Dict
from typing import Optional


def normalize_tool_name(name: str) -> str:
    """Match the identifier spelling used by the JavaScript tool bridge."""
    return re.sub(r"[^A-Za-z0-9_]", "_", name)


def tool_completion(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = item.get("type")
    if kind == "CommandExecution":
        command = item.get("command", [])
        if not isinstance(command, list) or not command:
            return None
        arguments = {
            "cmd": (
                command[-1]
                if len(command) >= 3 and command[-2] in ("-c", "-lc")
                else " ".join(shlex.quote(str(part)) for part in command)
            )
        }
        value = item.get("aggregated_output", "")
        name = "exec_command"
        details = {key: item[key] for key in ("process_id", "exit_code", "cwd") if key in item}
    elif kind == "FileChange":
        name = "apply_patch"
        arguments = item.get("changes", {})
        value = str(item.get("stdout") or "") + str(item.get("stderr") or "")
        details = {}
    elif kind == "McpToolCall":
        server, tool = item.get("server", ""), item.get("tool", "")
        name = str(tool) if server == "codex" else normalize_tool_name(f"mcp__{server}__{tool}")
        if tool in ("read_mcp_resource", "list_mcp_resources", "list_mcp_resource_templates"):
            name = str(tool)
        arguments = item.get("arguments", {})
        value = item.get("result", item.get("error", ""))
        details = {"server": server, "tool": tool}
    else:
        return None
    return {"name": name, "arguments": arguments, "value": value, "details": details, "item": item}


def matches_tool_name(completion: Dict[str, Any], name: str) -> bool:
    if normalize_tool_name(completion["name"]) == normalize_tool_name(name):
        return True
    if completion["item"].get("type") != "McpToolCall":
        return False
    parts = name.split("__")
    # Connector aliases can insert a namespace before the qualified tool name.
    # Keep the server and complete qualified name; do not match by method alone.
    return (
        len(parts) >= 3
        and parts[0] == "mcp"
        and normalize_tool_name(parts[1]) == normalize_tool_name(completion["details"]["server"])
        and normalize_tool_name(parts[-1]) == normalize_tool_name(completion["details"]["tool"])
    )


def matches_call(completion: Dict[str, Any], name: str, arguments: Any) -> bool:
    if not matches_tool_name(completion, name):
        return False
    if name == "exec_command":
        return isinstance(arguments, dict) and arguments.get("cmd") == completion["arguments"]["cmd"]
    if name == "apply_patch":
        if not isinstance(arguments, str):
            return bool(arguments == completion["arguments"])
        # Match paths, not arbitrary patch completion order.
        paths = []
        for line in arguments.splitlines():
            if line.startswith(("*** Update File: ", "*** Add File: ", "*** Delete File: ")):
                paths.append(line.split(": ", 1)[1])
        actual = completion["arguments"]
        return (
            bool(paths)
            and len(paths) == len(actual)
            and all(
                any(
                    path == changed or changed.replace("\\", "/").endswith("/" + path.replace("\\", "/"))
                    for changed in actual
                )
                for path in paths
            )
        )
    return bool(arguments == completion["arguments"])
