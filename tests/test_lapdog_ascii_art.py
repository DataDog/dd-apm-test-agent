from lapdog.cli.ascii_art import build_running_banner
from lapdog.cli.ascii_art import build_status_banner


def test_running_banner_can_warn_for_proxy_backed_sessions():
    banner = build_running_banner("coding session", warning_lines=["Keep Lapdog running"])

    assert "Keep Lapdog running" in banner
    assert "lapdog stop" not in banner


def test_running_banner_uses_default_stop_hint_without_warning():
    banner = build_running_banner("application")

    assert "lapdog stop" in banner


def test_status_banner_keeps_lines_beyond_art_height():
    banner = build_status_banner(port=8126, pid=1, logs_path="/tmp/lapdog.log", memory="~9MB retained, limit 20MB")

    assert "Logs: " in banner
    assert "~9MB retained, limit 20MB" in banner
