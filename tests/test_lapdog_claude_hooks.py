import json
from pathlib import Path
from typing import Any
from typing import Dict
from typing import cast

from lapdog.hooks import (
    _CLAUDE_CODE_DEFAULT_MATCHER as CLAUDE_CODE_DEFAULT_MATCHER,
    _CLAUDE_CODE_HOOK as CLAUDE_CODE_HOOK,
    _CLAUDE_CODE_EVENTS as CLAUDE_CODE_EVENTS,
    remove_claude_code_hooks,
    write_claude_code_hooks,
)


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


class TestClaudeCodeHooksRemoval:
    """Tests for ``remove_claude_code_hooks`` (inverse of write)."""

    def test_round_trip_clears_lapdog_hooks(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        settings_path.write_text("{}")
        write_claude_code_hooks(settings_path)
        changed = remove_claude_code_hooks(settings_path)
        assert changed is True
        # Every event's matcher list should be empty after removal — the
        # default-matcher entries lapdog wrote contained only its own hook.
        expected = {"hooks": {event: [] for event in CLAUDE_CODE_EVENTS}}
        assert _read_settings(settings_path) == expected

    def test_preserves_unrelated_user_hooks(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        user_hook = {"type": "command", "command": "echo bash"}
        starting = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [user_hook]},
                    {"matcher": "", "hooks": [CLAUDE_CODE_HOOK]},
                ],
                "Stop": [{"matcher": "", "hooks": [CLAUDE_CODE_HOOK, user_hook]}],
            },
            "other": "kept",
        }
        settings_path.write_text(json.dumps(starting, indent=2))
        changed = remove_claude_code_hooks(settings_path)
        assert changed is True
        # PreToolUse: the Bash matcher survives untouched; the default-matcher
        # entry that held only lapdog's hook is dropped entirely.
        # Stop: the default matcher keeps user_hook, just minus lapdog's.
        expected = {
            "hooks": {
                "PreToolUse": [{"matcher": "Bash", "hooks": [user_hook]}],
                "Stop": [{"matcher": "", "hooks": [user_hook]}],
            },
            "other": "kept",
        }
        assert _read_settings(settings_path) == expected

    def test_noop_when_file_missing(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        assert remove_claude_code_hooks(settings_path) is False
        assert not settings_path.exists()

    def test_noop_when_no_lapdog_hooks(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        other = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]}}
        settings_path.write_text(json.dumps(other, indent=2))
        assert remove_claude_code_hooks(settings_path) is False
        assert _read_settings(settings_path) == other

    def test_noop_when_unparseable(self, tmp_path: Path) -> None:
        settings_path = tmp_path / "settings.json"
        settings_path.write_text("not json {{")
        assert remove_claude_code_hooks(settings_path) is False
        # File contents unchanged.
        assert settings_path.read_text() == "not json {{"
