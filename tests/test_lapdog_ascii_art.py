from lapdog.lapdog_ascii_art import build_running_banner


def test_running_banner_can_warn_for_proxy_backed_sessions():
    banner = build_running_banner("coding session", warning_lines=["Keep Lapdog running"])

    assert "Keep Lapdog running" in banner
    assert "lapdog stop" not in banner


def test_running_banner_uses_default_stop_hint_without_warning():
    banner = build_running_banner("application")

    assert "lapdog stop" in banner
