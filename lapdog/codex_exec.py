"""Best-effort extraction of tool calls made inside Codex's JavaScript exec tool."""

import ast
import json
import os
import re
import shlex
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from .codex_items import normalize_tool_name

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


def _complete_object_prefix(text: str) -> Dict[str, Any]:
    """Read complete top-level members before a truncated JSON value.

    Decode in order rather than searching for braces inside strings. Never
    manufacture the unfinished value or continue past the truncation point.
    """
    decoder = json.JSONDecoder()
    remaining = text.lstrip()
    members: Dict[str, Any] = {}
    if not remaining.startswith("{"):
        return members
    remaining = remaining[1:].lstrip()
    while remaining:
        try:
            key, end = decoder.raw_decode(remaining)
            remaining = remaining[end:].lstrip()
            if not isinstance(key, str) or not remaining.startswith(":"):
                break
            value, end = decoder.raw_decode(remaining[1:].lstrip())
            remaining = remaining[1:].lstrip()[end:].lstrip()
            if not remaining.startswith((",", "}")):
                break
            members[key] = value
            if remaining.startswith("}"):
                break
            remaining = remaining[1:].lstrip()
        except ValueError:
            break
    return members


def _native_result_name(value: Any) -> Optional[str]:
    if not isinstance(value, dict):
        return None
    if set(value) == {"current_time"} and isinstance(value["current_time"], str):
        return "clock__curr_time"
    if set(value) == {"goal", "remainingTokens", "completionBudgetReport"}:
        return "get_goal"
    return None


def extract_exec_results(
    output: Any, call_count: int, calls: Optional[List[Dict[str, Any]]] = None
) -> Dict[int, Dict[str, Any]]:
    """Match explicit indexes/names and unique native result schemas.

    ``calls`` enables name matching. Arbitrary user labels and parallel output
    order are not evidence of which tool produced a result.
    """
    if call_count == 0:
        return {}
    if not isinstance(output, list):
        blocks = [output] if isinstance(output, str) else []
    else:
        blocks = [
            item["text"]
            for item in output
            if isinstance(item, dict)
            and item.get("type") in ("input_text", "output_text")
            and isinstance(item.get("text"), str)
        ]
    if blocks and re.match(r"^Script (completed|failed|running)(?:\n|$)", blocks[0]):
        blocks = blocks[1:]
    names: Dict[str, List[int]] = {}
    for call_index, call in enumerate(calls or []):
        names.setdefault(normalize_tool_name(call["name"]), []).append(call_index)
    indexed: Dict[int, Dict[str, Any]] = {}
    ambiguous = set()
    for block in blocks:
        try:
            records = [json.loads(block)]
        except ValueError:
            if (
                re.search(r"citeturn[\w]+", block)
                and not block.lstrip().startswith(("{", "Warning: truncated output"))
                and not re.match(r'^\s*\[\s*[\[{"\d-]', block)
            ):
                # A web response can contain multiple citations. They belong to
                # one returned value, not separate results for the same call.
                records = [{"result": block}]
            else:
                records = []
            # Codex can combine text() calls into one block with a truncation
            # notice. Recover only complete JSON lines, never truncated fragments.
            for line in ([] if records else block.splitlines()):
                try:
                    records.append(json.loads(line))
                except ValueError:
                    # A plain web response can survive in a combined block even
                    # when a neighboring JSON result was truncated by Codex.
                    if line.startswith("cite"):
                        records.append({"result": line})
                    else:
                        prefix = _complete_object_prefix(line)
                        records.extend(value for value in prefix.values() if _native_result_name(value))
        # Recognize native results grouped under arbitrary object member names,
        # without interpreting JavaScript bindings such as {now, cal, mail}.
        nested = [
            value
            for record in records
            if isinstance(record, dict)
            and not any(key in record for key in ("i", "toolNumber", "result", "value", "error", "reason"))
            for value in record.values()
            if _native_result_name(value)
        ]
        records.extend(nested)
        for parsed in records:
            if not isinstance(parsed, dict):
                continue
            index = parsed.get("i")
            if index is None and type(parsed.get("toolNumber")) is int:
                index = parsed["toolNumber"] - 1
            explicit_index = type(index) is int
            if not explicit_index and not any(key in parsed for key in ("value", "result", "reason", "error")):
                value = parsed
            else:
                value = parsed.get("value", parsed.get("result", parsed.get("reason", parsed.get("error", ""))))
            rejected = parsed.get("status") == "rejected" or "error" in parsed
            if isinstance(value, dict) and value.get("status") in ("fulfilled", "rejected"):
                rejected = rejected or value["status"] == "rejected"
                value = value.get("value", value.get("reason", ""))
            if not explicit_index:
                # Tool descriptions also contain names; they are not results.
                label = parsed.get("tool", parsed.get("name"))
                matches = names.get(normalize_tool_name(label), []) if isinstance(label, str) else []
                if not any(key in parsed for key in ("value", "result", "reason", "error")):
                    matches = []
                if not matches and isinstance(value, dict):
                    native_name = _native_result_name(value)
                    if native_name:
                        matches = names.get(native_name, [])
                if not matches and isinstance(value, str) and re.search(r"citeturn[\w]+", value):
                    matches = names.get("web__run", [])
                if len(matches) != 1:
                    continue
                index = matches[0]
            if not isinstance(index, int) or not 0 <= index < call_count:
                continue
            if index in indexed:
                ambiguous.add(index)
                continue
            indexed[index] = {"value": value}
            if rejected:
                indexed[index]["error"] = True
    for index in ambiguous:
        indexed.pop(index, None)
    if indexed or ambiguous:
        return indexed
    if call_count == 1:
        if not isinstance(output, list):
            return {0: {"value": output}}
        return {0: {"value": blocks if len(blocks) != 1 else blocks[0]}}
    return {}
