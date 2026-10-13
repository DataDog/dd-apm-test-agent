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


def extract_exec_results(output: Any, call_count: int) -> Dict[int, Dict[str, Any]]:
    """Use only explicit result indexes, or the sole call's whole output."""
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
    if blocks and re.match(r"^Script (completed|failed|running)(?:\n|$)", blocks[0]):
        blocks = blocks[1:]
    indexed: Dict[int, Dict[str, Any]] = {}
    for block in blocks:
        try:
            parsed = json.loads(block)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, dict) or type(parsed.get("i")) is not int:
            continue
        call_index = parsed["i"]
        if not 0 <= call_index < call_count or call_index in indexed:
            continue
        indexed[call_index] = {"value": parsed.get("value", parsed.get("reason", ""))}
        if parsed.get("status") == "rejected":
            indexed[call_index]["error"] = True
    if indexed:
        return indexed
    if call_count == 1:
        return {0: {"value": blocks if len(blocks) != 1 else blocks[0]}}
    return {}
