"""Persistent Lapdog authentication and forwarding configuration."""

import json
import os
import tempfile
from typing import Any
from typing import Dict

import keyring
from keyring.errors import PasswordDeleteError

from .paths import CONFIG_FILE


KEYRING_SERVICE = "lapdog"
KEYRING_USERNAME = "dd_api_key"


def load_config() -> Dict[str, Any]:
    """Load non-secret Lapdog configuration, returning defaults on failure."""
    try:
        with open(CONFIG_FILE) as config_file:
            value = json.load(config_file)
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def save_config(dd_site: str, data_forwarding: bool) -> None:
    """Atomically persist non-secret Lapdog configuration."""
    config_dir = os.path.dirname(CONFIG_FILE)
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    fd, temporary_path = tempfile.mkstemp(prefix="config-", suffix=".json", dir=config_dir)
    try:
        with os.fdopen(fd, "w") as config_file:
            json.dump(
                {"dd_site": dd_site, "data_forwarding": data_forwarding},
                config_file,
                indent=2,
            )
            config_file.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, CONFIG_FILE)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise


def get_api_key() -> str:
    """Read Lapdog's API key from the system keyring."""
    return keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME) or ""


def set_api_key(api_key: str) -> None:
    """Store Lapdog's API key in the system keyring."""
    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)


def delete_api_key() -> None:
    """Delete Lapdog's API key, succeeding when it is already absent."""
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
    except PasswordDeleteError:
        pass
