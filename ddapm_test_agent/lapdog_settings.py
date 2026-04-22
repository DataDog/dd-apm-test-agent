"""Persistent settings for lapdog stored in ~/.lapdog/settings.cfg.

The DD API key is stored in the system keychain when available (via keyring),
falling back to the settings file with restricted permissions (0o600).
Non-sensitive settings (dd_site, data_forwarding_enabled) always go to the file.

Environment:
  LAPDOG_SKIP_KEYRING — If set to 1/true/yes, skip the keychain and read the API
    key only from ~/.lapdog/settings.cfg (avoids keyring backend issues).
  PYTHON_KEYRING_BACKEND — Optional keyring backend module path (see keyring docs).
"""
import configparser
import os
from typing import Optional
from typing import Tuple


_SETTINGS_PATH = os.path.expanduser("~/.lapdog/settings.cfg")
_SECTION = "lapdog"
_KEYRING_SERVICE = "lapdog"

_DD_API_KEY = "dd_api_key"
_DD_SITE = "dd_site"
_DATA_FORWARDING_ENABLED = "data_forwarding_enabled"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _keyring_get(key: str) -> Optional[str]:
    """Retrieve a value from the system keychain. Returns None if unavailable."""
    if _env_truthy("LAPDOG_SKIP_KEYRING"):
        return None
    try:
        import keyring  # type: ignore[import]

        return keyring.get_password(_KEYRING_SERVICE, key)  # type: ignore[no-any-return]
    except Exception:
        return None


def _keyring_set(key: str, value: str) -> bool:
    """Store a value in the system keychain. Returns True on success."""
    if _env_truthy("LAPDOG_SKIP_KEYRING"):
        return False
    try:
        import keyring  # type: ignore[import]

        keyring.set_password(_KEYRING_SERVICE, key, value)
        return True
    except Exception:
        return False


def load_settings() -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    """Return (dd_api_key, dd_site, data_forwarding_enabled) from keychain/settings file."""
    cfg = configparser.ConfigParser()
    cfg.read(_SETTINGS_PATH)
    section = cfg[_SECTION] if _SECTION in cfg else {}

    # API key: keyring first, fall back to plaintext file
    api_key = _keyring_get(_DD_API_KEY) or section.get(_DD_API_KEY)
    dd_site = section.get(_DD_SITE)
    data_forwarding_enabled = (
        cfg.getboolean(_SECTION, _DATA_FORWARDING_ENABLED, fallback=None) if _SECTION in cfg else None
    )

    return api_key, dd_site, data_forwarding_enabled


def save_settings(
    dd_api_key: Optional[str] = None,
    dd_site: Optional[str] = None,
    data_forwarding_enabled: Optional[bool] = None,
) -> None:
    """Persist settings. The API key goes to the system keychain when available,
    falling back to the settings file with owner-only permissions."""
    settings_dir = os.path.dirname(_SETTINGS_PATH)
    os.makedirs(settings_dir, exist_ok=True)
    os.chmod(settings_dir, 0o700)

    cfg = configparser.ConfigParser()
    cfg.read(_SETTINGS_PATH)
    if _SECTION not in cfg:
        cfg[_SECTION] = {}

    if dd_api_key is not None:
        if not _keyring_set(_DD_API_KEY, dd_api_key):
            # keyring unavailable — store in file as fallback
            cfg[_SECTION][_DD_API_KEY] = dd_api_key

    if dd_site is not None:
        cfg[_SECTION][_DD_SITE] = dd_site
    if data_forwarding_enabled is not None:
        cfg[_SECTION][_DATA_FORWARDING_ENABLED] = str(data_forwarding_enabled)

    with open(_SETTINGS_PATH, "w") as f:
        cfg.write(f)
    os.chmod(_SETTINGS_PATH, 0o600)
