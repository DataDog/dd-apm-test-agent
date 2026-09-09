import json
import os

from keyring.errors import PasswordDeleteError

from lapdog import config


def test_save_and_load_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(config_path))

    config.save_config("us3.datadoghq.com", data_forwarding=True)

    assert config.load_config() == {
        "dd_site": "us3.datadoghq.com",
        "data_forwarding": True,
    }
    assert json.loads(config_path.read_text())["dd_site"] == "us3.datadoghq.com"
    if os.name != "nt":
        assert config_path.stat().st_mode & 0o777 == 0o600


def test_load_config_ignores_invalid_json(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text("not json")
    monkeypatch.setattr(config, "CONFIG_FILE", str(config_path))

    assert config.load_config() == {}


def test_keyring_helpers(monkeypatch):
    monkeypatch.setattr(config.keyring, "get_password", lambda service, username: "secret")
    calls = []
    monkeypatch.setattr(config.keyring, "set_password", lambda *args: calls.append(("set", args)))
    monkeypatch.setattr(config.keyring, "delete_password", lambda *args: calls.append(("delete", args)))

    assert config.get_api_key() == "secret"
    config.set_api_key("new-secret")
    config.delete_api_key()

    expected_identity = (config.KEYRING_SERVICE, config.KEYRING_USERNAME)
    assert calls == [
        ("set", (*expected_identity, "new-secret")),
        ("delete", expected_identity),
    ]


def test_delete_api_key_ignores_missing_entry(monkeypatch):
    def missing(*args):
        raise PasswordDeleteError("missing")

    monkeypatch.setattr(config.keyring, "delete_password", missing)

    config.delete_api_key()
