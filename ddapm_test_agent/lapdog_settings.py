"""Persistent settings for lapdog stored in ~/.lapdog/settings.cfg."""
import configparser
import os
from typing import Optional
from typing import Tuple

_SETTINGS_PATH = os.path.expanduser("~/.lapdog/settings.cfg")
_SECTION = "lapdog"

_DD_API_KEY = "dd_api_key"
_DD_SITE = "dd_site"
_DATA_FORWARDING_ENABLED = "data_forwarding_enabled"


def load_settings() -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    """Return (dd_api_key, dd_site, data_forwarding_enabled) from ~/.lapdog/settings.cfg, or (None, None) if absent."""
    cfg = configparser.ConfigParser()
    if not cfg.read(_SETTINGS_PATH):
        return None, None, None
    if _SECTION not in cfg:
        return None, None, None
    section = cfg[_SECTION]
    return section.get(_DD_API_KEY), section.get(_DD_SITE), section.getboolean(_DATA_FORWARDING_ENABLED, fallback=None)


def save_settings(
    dd_api_key: Optional[str] = None,
    dd_site: Optional[str] = None,
    data_forwarding_enabled: Optional[bool] = None
) -> None:
    """Persist dd_api_key and dd_site to ~/.lapdog/settings.cfg."""
    os.makedirs(os.path.dirname(_SETTINGS_PATH), exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg.read(_SETTINGS_PATH)
    if _SECTION not in cfg:
        cfg[_SECTION] = {}

    if dd_api_key is not None:
        cfg[_SECTION][_DD_API_KEY] = dd_api_key
    if dd_site is not None:
        cfg[_SECTION][_DD_SITE] = dd_site
    if data_forwarding_enabled is not None:
        cfg[_SECTION][_DATA_FORWARDING_ENABLED] = str(data_forwarding_enabled)
    with open(_SETTINGS_PATH, "w") as f:
        cfg.write(f)
