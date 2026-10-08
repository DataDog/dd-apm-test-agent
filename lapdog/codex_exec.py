"""Best-effort extraction of tool calls made inside Codex's JavaScript exec tool."""

import ast
import json
import os
import re
import shlex
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple

TOOL_DISPLAY_NAMES = {
    "write_stdin": "Ran",
    "apply_patch": "Apply patch",
    "web__run": "Web",
    "view_image": "View image",
    "image_gen__imagegen": "Generate image",
}

SHELL_COMMAND_DISPLAY_NAMES = {
    "cat": "Read",
    "curl": "Web",
    "sed": "Read",
    "find": "List",
    "ls": "List",
    "rg": "List",
}


def _shell_command_name(arguments: Any) -> str:
    if not isinstance(arguments, dict) or not isinstance(arguments.get("cmd"), str):
        return "Ran"
    try:
        lexer = shlex.shlex(arguments["cmd"], posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return "Ran"
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "cd":
            while index < len(tokens) and tokens[index] not in ("&&", ";"):
                index += 1
            index += 1
            continue
        if token in ("env", "command") or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", token):
            index += 1
            continue
        command = os.path.basename(token)
        return SHELL_COMMAND_DISPLAY_NAMES.get(command, "Ran")
    return "Ran"


def display_tool_name(name: str, arguments: Any = None) -> str:
    if name == "exec_command":
        return _shell_command_name(arguments)
    if name in TOOL_DISPLAY_NAMES:
        return TOOL_DISPLAY_NAMES[name]
    return name.rsplit("__", 1)[-1].replace("_", " ").strip().capitalize() or name


def _skip_quoted(source: str, index: int) -> int:
    quote = source[index]
    index += 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return index


def _skip_comment(source: str, index: int) -> int:
    if source.startswith("//", index):
        end = source.find("\n", index + 2)
        return len(source) if end < 0 else end + 1
    if source.startswith("/*", index):
        end = source.find("*/", index + 2)
        return len(source) if end < 0 else end + 2
    return index


def _call_arguments(source: str, open_paren: int) -> Optional[Tuple[str, int]]:
    stack = [")"]
    index = open_paren + 1
    closing = {"(": ")", "[": "]", "{": "}"}
    while index < len(source):
        char = source[index]
        if char in ("'", '"', "`"):
            index = _skip_quoted(source, index)
            continue
        skipped = _skip_comment(source, index)
        if skipped != index:
            index = skipped
            continue
        if char in closing:
            stack.append(closing[char])
        elif char in ")}]":
            if not stack or char != stack.pop():
                return None
            if not stack:
                return source[open_paren + 1 : index].strip(), index + 1
        index += 1
    return None


def _python_literal(source: str) -> Any:
    """Decode ordinary JavaScript object literals without executing JavaScript."""
    result: List[str] = []
    index = 0
    while index < len(source):
        char = source[index]
        if char in ("'", '"'):
            end = _skip_quoted(source, index)
            result.append(source[index:end])
            index = end
            continue
        if char == "`":
            raise ValueError("template literal")
        skipped = _skip_comment(source, index)
        if skipped != index:
            result.append(" ")
            index = skipped
            continue
        match = re.match(r"[A-Za-z_$][\w$]*", source[index:])
        if match:
            word = match.group(0)
            after = index + len(word)
            if word in ("true", "false", "null", "undefined"):
                result.append({"true": "True", "false": "False", "null": "None", "undefined": "None"}[word])
            elif re.match(r"\s*:", source[after:]):
                result.append(repr(word))
            else:
                result.append(word)
            index = after
            continue
        result.append(char)
        index += 1
    return ast.literal_eval("".join(result))


def _resolve_literal_binding(source: str, call_start: int, expression: str) -> Any:
    """Resolve a simple earlier ``const name = literal`` for tool input."""
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", expression):
        return expression
    pattern = re.compile(r"\b(?:const|let|var)\s+" + re.escape(expression) + r"\s*=\s*")
    matches = list(pattern.finditer(source, 0, call_start))
    if not matches:
        return expression
    start = matches[-1].end()
    if start >= len(source) or source[start] not in ("'", '"', "`"):
        return expression
    end = _skip_quoted(source, start)
    literal = source[start:end]
    if not literal or literal[-1] != source[start]:
        return expression
    if source[start] == "`":
        return literal[1:-1] if "${" not in literal else expression
    try:
        return ast.literal_eval(literal)
    except (ValueError, SyntaxError, TypeError):
        return expression


def extract_exec_calls(source: str) -> List[Dict[str, Any]]:
    """Return direct ``tools.method(...)`` calls in source order.

    Dynamic expressions stay as text. The caller can still show the relevant
    argument expression instead of the whole JavaScript program.
    """
    calls: List[Dict[str, Any]] = []
    index = 0
    while index < len(source):
        if source[index] in ("'", '"', "`"):
            index = _skip_quoted(source, index)
            continue
        skipped = _skip_comment(source, index)
        if skipped != index:
            index = skipped
            continue
        if source.startswith("tools.", index) and (
            index == 0 or not (source[index - 1].isalnum() or source[index - 1] in "_$")
        ):
            match = re.match(r"tools\.([A-Za-z_$][\w$]*)\s*\(", source[index:])
            if match:
                name = match.group(1)
                open_paren = index + match.end() - 1
                parsed = _call_arguments(source, open_paren)
                if parsed is not None:
                    raw, _ = parsed
                    try:
                        arguments = json.loads(raw)
                    except (ValueError, TypeError):
                        try:
                            arguments = _python_literal(raw)
                        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
                            arguments = _resolve_literal_binding(source, index, raw)
                    calls.append({"name": name, "arguments": arguments})
                    index = open_paren + 1
                    continue
        index += 1
    return calls


def _prints_calls_in_order(source: str, call_count: int) -> bool:
    """Accept only a sequence of direct text(await tools.method(...)) calls."""
    index = 0
    count = 0
    while index < len(source):
        if source[index].isspace() or source[index] == ";":
            index += 1
            continue
        skipped = _skip_comment(source, index)
        if skipped != index:
            index = skipped
            continue
        match = re.match(r"text\(\s*await\s+tools\.[A-Za-z_$][\w$]*\s*\(", source[index:])
        if not match:
            return False
        parsed = _call_arguments(source, index + match.end() - 1)
        if parsed is None:
            return False
        _, index = parsed
        closing = re.match(r"\s*\)", source[index:])
        if not closing:
            return False
        index += closing.end()
        count += 1
    return count == call_count


def _decode_exec_output(blocks: List[str]) -> Iterator[Any]:
    # New transcripts can combine several JSON results in one text block.
    decoder = json.JSONDecoder()
    for block in blocks:
        remaining = block.strip()
        if remaining.startswith("Warning: truncated output"):
            # Read intact labelled records independently; a damaged record
            # must not hide the valid results that follow it.
            for line in remaining.splitlines():
                try:
                    yield json.loads(line)
                except ValueError:
                    pass
            continue
        while remaining:
            try:
                parsed, end = decoder.raw_decode(remaining)
            except ValueError:
                break
            yield parsed
            remaining = remaining[end:].lstrip()


def _normalize_exec_result(parsed: Dict[str, Any]) -> Optional[Tuple[Any, Any, Dict[str, Any]]]:
    """Return the index/name label and result from the supported output forms."""
    if set(parsed) == {"current_time"} and isinstance(parsed["current_time"], str):
        return None, "clock__curr_time", {"value": parsed}
    if set(parsed) == {"goal", "remainingTokens", "completionBudgetReport"}:
        return None, "get_goal", {"value": parsed}
    # Tool descriptions have names too, but contain no result.
    if type(parsed.get("i")) is not int and not any(key in parsed for key in ("value", "result", "reason", "error")):
        return None
    value = parsed.get("value", parsed.get("result", parsed.get("reason", parsed.get("error", ""))))
    status = parsed.get("status")
    if "value" not in parsed and isinstance(value, dict) and value.get("status") in ("fulfilled", "rejected"):
        status = value["status"]
        value = value.get("value", value.get("reason"))
    if (
        isinstance(parsed.get("name"), str)
        and isinstance(value, dict)
        and value.get("name") == parsed["name"]
        and "result" in value
    ):
        value = value["result"]
    result = {"value": value}
    if status == "rejected":
        result["error"] = True
    return parsed.get("i"), parsed.get("name", parsed.get("tool")), result


def extract_exec_results(
    output: Any, call_count: int, source: str = "", calls: Optional[List[Dict[str, Any]]] = None
) -> Dict[int, Dict[str, Any]]:
    """Match indexed results, direct sequential prints, or a sole call's output.

    calls caches name matching; source is still required for sequential matching.
    """
    if call_count == 0:
        return {}
    if not isinstance(output, list):
        return {0: {"value": output}} if call_count == 1 else {}
    raw_blocks = [
        item.get("text")
        for item in output
        if isinstance(item, dict) and item.get("type") in ("input_text", "output_text")
    ]
    blocks: List[str] = [block for block in raw_blocks if isinstance(block, str)]
    failed = bool(blocks and blocks[0].startswith("Script failed\n"))
    if blocks and re.match(r"^Script (completed|failed|running)(?:\n|$)", blocks[0]):
        blocks = blocks[1:]
    indexed: Dict[int, Dict[str, Any]] = {}
    if calls is None:
        calls = extract_exec_calls(source)
    names: Dict[str, List[int]] = {}
    for index, call in enumerate(calls):
        name = call["name"]
        aliases = {name, name.replace("__", ".")}
        if name.startswith("mcp__"):
            aliases.add(name[len("mcp__") :].replace("__", "."))
        for alias in aliases:
            names.setdefault(alias, []).append(index)
    for parsed in _decode_exec_output(blocks):
        normalized = _normalize_exec_result(parsed) if isinstance(parsed, dict) else None
        if normalized is None:
            continue
        call_index, name, result = normalized
        if type(call_index) is not int:
            matches = names.get(name, []) if isinstance(name, str) else []
            if len(matches) != 1:
                continue
            call_index = matches[0]
        if 0 <= call_index < call_count and call_index not in indexed:
            indexed[call_index] = result
    if failed:
        # A direct sequence stops at its first exception. Later calls did not run.
        if (
            _prints_calls_in_order(source, call_count)
            and 0 < len(blocks) <= call_count
            and blocks[-1].startswith("Script error:")
        ):
            sequential = {index: {"value": block} for index, block in enumerate(blocks)}
            sequential[len(blocks) - 1]["error"] = True
            return {**sequential, **indexed}
        if indexed or call_count != 1:
            return indexed
        return {0: {"value": blocks[0] if len(blocks) == 1 else blocks, "error": True}}
    if _prints_calls_in_order(source, call_count):
        if len(blocks) == call_count:
            return {**{index: {"value": block} for index, block in enumerate(blocks)}, **indexed}
        if len(blocks) == 1:
            lines = blocks[0].splitlines()
            # A truncated combined block keeps its original line count. Match
            # intact JSON lines only when no lines have been removed.
            if lines and lines[0].startswith("Warning: truncated output"):
                if len(lines) < 4 or lines[1] != f"Total output lines: {call_count}" or lines[2]:
                    return indexed
                lines = lines[3:]
            if len(lines) == call_count:
                sequential = {}
                for index, line in enumerate(lines):
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    sequential[index] = {"value": value}
                return {**sequential, **indexed}
    if indexed:
        return indexed
    if call_count == 1:
        return {0: {"value": blocks if len(blocks) != 1 else blocks[0]}}
    return {}
