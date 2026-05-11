import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import cast

from lapdog.hooks import _CLAUDE_CODE_DEFAULT_MATCHER as CLAUDE_CODE_DEFAULT_MATCHER
from lapdog.hooks import _CLAUDE_CODE_EVENTS as CLAUDE_CODE_EVENTS
from lapdog.hooks import _CLAUDE_CODE_HOOK as CLAUDE_CODE_HOOK
from lapdog.hooks import write_claude_code_hooks


def _read_settings(path: Path) -> Dict[str, Any]:
    with open(path, "r") as f:
        return cast(Dict[str, Any], json.load(f))


def _default_hooks_structure() -> Dict[str, Any]:
    return {event: [CLAUDE_CODE_DEFAULT_MATCHER] for event in CLAUDE_CODE_EVENTS}


class TestClaudeCodeHooksWriting:
    """Tests for write_claude_code_hooks merge behavior (only insert hooks if they do not exist)."""

    def test_original_hooks_file_is_empty(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        settings_path.write_text("")
        write_claude_code_hooks(settings_path)
        expected = {"hooks": _default_hooks_structure()}
        assert _read_settings(settings_path) == expected

    def test_original_hooks_file_is_empty_json(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        settings_path.write_text("{}")
        write_claude_code_hooks(settings_path)
        expected = {"hooks": _default_hooks_structure()}
        assert _read_settings(settings_path) == expected

    def test_original_hooks_file_has_no_hooks_entry(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        settings_path.write_text('{"other": "value", "nested": {"a": 1}}')
        write_claude_code_hooks(settings_path)
        expected = {"other": "value", "nested": {"a": 1}, "hooks": _default_hooks_structure()}
        assert _read_settings(settings_path) == expected

    def test_requested_hook_to_modify_not_in_hooks(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        only_pre_tool = {"hooks": {"PreToolUse": [CLAUDE_CODE_DEFAULT_MATCHER]}}
        settings_path.write_text(json.dumps(only_pre_tool, indent=2))
        write_claude_code_hooks(settings_path)
        expected = {"hooks": _default_hooks_structure()}
        assert _read_settings(settings_path) == expected

    def test_requested_matcher_empty_not_in_hooks(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        bash_only = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo bash"}]},
                ],
            },
        }
        settings_path.write_text(json.dumps(bash_only, indent=2))
        write_claude_code_hooks(settings_path)
        bash_matcher = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo bash"}]}
        expected = {
            "hooks": {
                **_default_hooks_structure(),
                "PreToolUse": [bash_matcher, CLAUDE_CODE_DEFAULT_MATCHER],
            },
        }
        assert _read_settings(settings_path) == expected

    def test_no_matching_default_hook_in_requested_matcher(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        empty_matcher_other_hook = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "other-cmd"}]},
                ],
            },
        }
        settings_path.write_text(json.dumps(empty_matcher_other_hook, indent=2))
        write_claude_code_hooks(settings_path)
        other_cmd_hook = {"type": "command", "command": "other-cmd"}
        expected = {
            "hooks": {
                **_default_hooks_structure(),
                "PreToolUse": [{"matcher": "", "hooks": [other_cmd_hook, CLAUDE_CODE_HOOK]}],
            },
        }
        assert _read_settings(settings_path) == expected

    def test_hook_already_present(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        already_has_default = {
            "hooks": {
                "PreToolUse": [{"matcher": "", "hooks": [CLAUDE_CODE_HOOK]}],
            },
        }
        settings_path.write_text(json.dumps(already_has_default, indent=2))
        write_claude_code_hooks(settings_path)
        expected = {
            "hooks": {
                **_default_hooks_structure(),
                "PreToolUse": [{"matcher": "", "hooks": [CLAUDE_CODE_HOOK]}],
            },
        }
        assert _read_settings(settings_path) == expected
