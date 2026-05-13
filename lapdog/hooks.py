import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from typing_extensions import cast


_CLAUDE_CODE_EVENTS = [
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Notification",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
    "SessionStart",
    "SessionEnd",
    "PreCompact",
    "PermissionRequest",
]
_CLAUDE_CODE_HOOK: Dict[str, Any] = {
    "type": "command",
    "command": "curl -s --max-time 2 -X POST -H 'Content-Type: application/json' -d @- http://localhost:8126/claude/hooks >/dev/null 2>&1 || true",
    "async": True,
}
_CLAUDE_CODE_DEFAULT_MATCHER: Dict[str, Any] = {"matcher": "", "hooks": [_CLAUDE_CODE_HOOK]}


def write_claude_code_hooks(claude_settings_path: Path) -> None:
    try:
        with open(claude_settings_path, "r") as claude_settings:
            try:
                claude_code_settings = json.load(claude_settings)
            except json.JSONDecodeError:
                claude_code_settings = {"hooks": {}}
    except FileNotFoundError:
        claude_code_settings = {"hooks": {}}

    hooks = claude_code_settings.get("hooks", {})
    for event in _CLAUDE_CODE_EVENTS:
        existing_hooks = cast(Optional[List[Dict[str, Any]]], hooks.get(event, None))
        if existing_hooks is None:
            hooks[event] = [_CLAUDE_CODE_DEFAULT_MATCHER]
            continue

        star_matcher_hook = next(
            (hook_matcher for hook_matcher in existing_hooks if hook_matcher.get("matcher", None) == ""), None
        )
        if star_matcher_hook is None:
            existing_hooks.append(_CLAUDE_CODE_DEFAULT_MATCHER)
            continue

        all_hooks_for_star_matcher = cast(List[Dict[str, Any]], star_matcher_hook.get("hooks", []))
        if not any(hook == _CLAUDE_CODE_HOOK for hook in all_hooks_for_star_matcher):
            all_hooks_for_star_matcher.append(_CLAUDE_CODE_HOOK)

    claude_code_settings["hooks"] = hooks
    with open(claude_settings_path, "w") as claude_settings:
        json.dump(claude_code_settings, claude_settings, indent=2)


def remove_claude_code_hooks(claude_settings_path: Path) -> bool:
    """Inverse of ``write_claude_code_hooks``: strip lapdog's hook entries.

    The canonical ``_CLAUDE_CODE_HOOK`` is removed from every event. If
    removing it leaves a default ``matcher: ""`` entry with no remaining
    hooks, that entry is dropped too so the file stays tidy. Any
    non-lapdog hooks the user has configured are left untouched.

    Returns True if the file was modified (and rewritten), False otherwise
    (file missing, unparseable, or contained no lapdog hooks).
    """
    try:
        with open(claude_settings_path, "r") as f:
            settings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return False

    hooks = settings.get("hooks", None)
    if not isinstance(hooks, dict):
        return False

    changed = False
    for event in _CLAUDE_CODE_EVENTS:
        matchers = hooks.get(event)
        if not isinstance(matchers, list):
            continue
        new_matchers: List[Dict[str, Any]] = []
        for matcher in matchers:
            if not isinstance(matcher, dict):
                new_matchers.append(matcher)
                continue
            matcher_hooks = cast(List[Dict[str, Any]], matcher.get("hooks", []))
            if not isinstance(matcher_hooks, list):
                new_matchers.append(matcher)
                continue
            filtered = [h for h in matcher_hooks if h != _CLAUDE_CODE_HOOK]
            if len(filtered) == len(matcher_hooks):
                new_matchers.append(matcher)
                continue
            changed = True
            if not filtered and matcher.get("matcher", "") == "":
                # Drop the now-empty default-matcher entry lapdog wrote.
                continue
            matcher["hooks"] = filtered
            new_matchers.append(matcher)
        hooks[event] = new_matchers

    if not changed:
        return False

    settings["hooks"] = hooks
    with open(claude_settings_path, "w") as f:
        json.dump(settings, f, indent=2)
    return True
