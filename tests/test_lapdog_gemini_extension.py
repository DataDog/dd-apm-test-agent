import json
import pkgutil

from lapdog.cli import _GEMINI_EXTENSION_TEMPLATE_FILES
from lapdog.cli import _write_gemini_extension

_GEMINI_EVENTS = [
    ("SessionStart", ""),
    ("BeforeAgent", ""),
    ("AfterModel", ""),
    ("BeforeTool", "*"),
    ("AfterTool", "*"),
    ("AfterAgent", ""),
    ("SessionEnd", ""),
    ("PreCompress", ""),
    ("Notification", ""),
]


def test_gemini_extension_templates_are_packaged():
    for resource_path in _GEMINI_EXTENSION_TEMPLATE_FILES:
        data = pkgutil.get_data("lapdog", resource_path)
        assert data is not None
        assert data

    hooks_template = pkgutil.get_data("lapdog", "gemini_extension/hooks/hooks.json.template")
    assert hooks_template is not None
    assert b"{{LAPDOG_URL}}" in hooks_template


def test_write_gemini_extension_generates_command_hooks(tmp_path):
    _write_gemini_extension(str(tmp_path), port=9123)

    extension = json.loads((tmp_path / "gemini-extension.json").read_text())
    hooks = json.loads((tmp_path / "hooks" / "hooks.json").read_text())
    context = (tmp_path / "plugin" / "lapdog-gemini" / "GEMINI.md").read_text()

    assert extension["name"] == "lapdog"
    assert extension["contextFileName"] == "plugin/lapdog-gemini/GEMINI.md"
    assert "Lapdog" in context

    for event, matcher in _GEMINI_EVENTS:
        hook_group = hooks["hooks"][event][0]
        hook = hook_group["hooks"][0]
        assert hook_group["matcher"] == matcher
        assert hook["type"] == "command"
        assert f"http://localhost:9123/gemini/hooks/{event}" in hook["command"]
        assert "{{LAPDOG_URL}}" not in hook["command"]
        assert hook["command"].endswith(">/dev/null 2>&1 || true")

    assert hooks["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"] == 15000
    assert hooks["hooks"]["BeforeAgent"][0]["hooks"][0]["timeout"] == 5000
