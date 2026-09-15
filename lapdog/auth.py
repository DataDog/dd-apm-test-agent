"""OAuth completion route owned by the Lapdog server."""

from datetime import datetime
from datetime import timezone
import getpass
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import cast

from aiohttp import ClientError
from aiohttp import ClientSession
from aiohttp import web
from aiohttp.web import Request

from ddapm_test_agent.cors import ALLOWED_ORIGIN_PATTERN
from ddapm_test_agent.cors import with_cors

from . import config

log = logging.getLogger(__name__)

# Sites offered by web-ui's Lapdog login dropdown: production/federal site
# regions whose status is currently "available".
SUPPORTED_DD_SITES: Set[str] = {
    "ap1.datadoghq.com",
    "ap2.datadoghq.com",
    "datadoghq.com",
    "datadoghq.eu",
    "ddog-gov.com",
    "uk1.datadoghq.com",
    "us3.datadoghq.com",
    "us4.datadoghq.com",
    "us5.datadoghq.com",
}


def _is_allowed_oauth_origin(origin: Optional[str]) -> bool:
    return bool(origin and ALLOWED_ORIGIN_PATTERN.fullmatch(origin))


def _api_key_name() -> str:
    timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    return f"Lapdog API Key created by {getpass.getuser()} on {timestamp}"


async def _create_api_key(access_token: str, site: str) -> Tuple[str, str]:
    """Create and return an API key and its resource ID."""
    url = f"https://api.{site}/api/v2/api_keys"
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "data": {
            "type": "api_keys",
            "attributes": {"name": _api_key_name()},
        }
    }
    try:
        async with ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, allow_redirects=False) as response:
                if response.status != 201:
                    log.warning("Datadog API key creation failed with status %s", response.status)
                    raise web.HTTPBadGateway(text="Datadog API key creation failed")
                try:
                    body = cast(Dict[str, Any], await response.json())
                    data = cast(Dict[str, Any], body["data"])
                    attributes = cast(Dict[str, Any], data["attributes"])
                    api_key = attributes["key"]
                    key_id = data.get("id", "")
                except (KeyError, TypeError, ValueError):
                    log.warning("Datadog API key creation returned an invalid response")
                    raise web.HTTPBadGateway(text="Datadog API key creation returned an invalid response")
    except ClientError:
        log.warning("Could not reach Datadog to create a Lapdog API key", exc_info=True)
        raise web.HTTPBadGateway(text="Could not reach Datadog to create an API key")
    if not isinstance(api_key, str) or not api_key:
        raise web.HTTPBadGateway(text="Datadog API key creation returned no key")
    return api_key, key_id if isinstance(key_id, str) else ""


class LapdogAuthAPI:
    """Handle browser OAuth completion for a running Lapdog process."""

    def __init__(self) -> None:
        self._app: Optional[web.Application] = None

    def set_app(self, app: web.Application) -> None:
        self._app = app

    async def handle_oauth_token(self, request: Request) -> web.Response:
        if not _is_allowed_oauth_origin(request.headers.get("Origin")):
            return web.HTTPForbidden(text="Unsupported OAuth origin")
        if request.content_type != "application/json":
            return web.HTTPUnsupportedMediaType(text="Expected application/json")

        try:
            body = await request.json()
        except (ValueError, TypeError):
            return web.HTTPBadRequest(text="Expected a JSON request body")

        if not isinstance(body, dict):
            return web.HTTPBadRequest(text="Expected a JSON object")
        access_token = body.get("access_token")
        site = body.get("site")
        if not isinstance(access_token, str) or not access_token:
            return web.HTTPBadRequest(text="access_token is required")
        if not isinstance(site, str) or site not in SUPPORTED_DD_SITES:
            return web.HTTPBadRequest(text="Unsupported Datadog site")

        try:
            api_key, _ = await _create_api_key(access_token, site)
        except web.HTTPException as error:
            return error
        try:
            config.set_api_key(api_key)
            config.write_config({"dd_site": site, "data_forwarding": True})
        except Exception:
            log.exception("Failed to persist Lapdog authentication")
            return web.HTTPInternalServerError(text="Failed to persist Lapdog authentication")

        app = self._app if self._app is not None else request.app
        overrides = app.get("lapdog_auth_overrides", {})
        if not overrides.get("dd_api_key", False):
            app["dd_api_key"] = api_key
        if not overrides.get("dd_site", False):
            app["dd_site"] = site
        if not overrides.get("forward", False):
            app["disable_llmobs_data_forwarding"] = False
        app["authenticated"] = True

        return web.json_response({"configured": True}, status=201)

    def get_routes(self) -> List[web.RouteDef]:
        handler = with_cors(self.handle_oauth_token)
        return [
            web.post("/lapdog/oauth/token", handler),
            web.options("/lapdog/oauth/token", handler),
        ]
