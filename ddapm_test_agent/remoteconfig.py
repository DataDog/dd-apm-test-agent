import base64
import datetime
import hashlib
import json
from typing import Any
from typing import Dict


class RemoteConfigServer:
    _responses: Dict[str, Any] = {}

    def _update_response(self, token: str, data: Dict[str, Any]) -> None:
        if self._responses.get(token):
            self._responses[token].update(data)
        else:
            self._create_response(token, data)

    def _create_response(self, token: str, data: Dict[str, Any]) -> None:
        self._responses[token] = data

    async def _get_response(self, token: str) -> Dict[str, Any]:
        return self._responses.get(token, {})

    def update_config_response(self, token: str, data: Dict[str, Any]) -> None:
        self._update_response(token, data)

    @staticmethod
    def _build_config_path_response(path: str, msg: str) -> Dict[str, Any]:
        expires_date = datetime.datetime.strftime(
            datetime.datetime.now() + datetime.timedelta(days=1), "%Y-%m-%dT%H:%M:%SZ"
        )
        msg_enc = bytes(json.dumps(msg), encoding="utf-8")
        data = {
            "signatures": [{"keyid": "", "sig": ""}],
            "signed": {
                "_type": "targets",
                "custom": {"opaque_backend_state": ""},
                "expires": expires_date,
                "spec_version": "1.0.0",
                "targets": {
                    path: {
                        "custom": {"c": [""], "v": 0},
                        "hashes": {"sha256": hashlib.sha256(msg_enc).hexdigest()},
                        "length": len(msg_enc),
                    }
                },
                "version": 0,
            },
        }
        remote_config_payload = {
            "roots": [
                str(
                    base64.b64encode(
                        bytes(
                            json.dumps(
                                {
                                    "signatures": [],
                                    "signed": {
                                        "_type": "root",
                                        "consistent_snapshot": True,
                                        "expires": "1986-12-11T00:00:00Z",
                                        "keys": {},
                                        "roles": {},
                                        "spec_version": "1.0",
                                        "version": 2,
                                    },
                                }
                            ),
                            encoding="utf-8",
                        )
                    ),
                    encoding="utf-8",
                )
            ],
            "targets": str(base64.b64encode(bytes(json.dumps(data), encoding="utf-8")), encoding="utf-8"),
            "target_files": [
                {
                    "path": path,
                    "raw": str(base64.b64encode(msg_enc), encoding="utf-8"),
                }
            ],
            "client_configs": [path],
        }
        return remote_config_payload

    def create_config_path_response(self, token: str, path: str, msg: str) -> None:
        remote_config_payload = self._build_config_path_response(path, msg)
        self.create_config_response(token, remote_config_payload)

    def create_config_response(self, token: str, data: Dict[str, Any]) -> None:
        self._create_response(token, data)

    async def get_config_response(self, token: str) -> Dict[str, Any]:
        return await self._get_response(token)
