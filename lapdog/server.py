"""Lapdog server composed on top of the Datadog APM test-agent application."""

import gzip
import logging
import os
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from aiohttp import web
import msgpack

from ddapm_test_agent import agent as test_agent

from . import config
from .auth import LapdogAuthAPI
from .claude_hooks import ClaudeHooksAPI
from .claude_link_tracker import ClaudeLinkTracker
from .claude_proxy import ClaudeProxyAPI
from .codex_hooks import CodexHooksAPI
from .codex_proxy import CodexProxyAPI
from .llmobs_event_platform import LLMObsEventPlatformAPI
from .pi_hooks import PiHooksAPI


log = logging.getLogger(__name__)


def _has_option(args: List[str], option: str) -> bool:
    return option in args or any(arg.startswith(f"{option}=") for arg in args)


def _prepare_startup(
    args: List[str],
) -> Tuple[List[str], Dict[str, bool], Dict[str, str]]:
    """Apply persisted defaults without superseding inline configuration."""
    configured_args = list(args)
    persisted = config.load_config()
    environment_defaults: Dict[str, str] = {}
    forward_override = "--forward" in configured_args
    configured_args = [arg for arg in configured_args if arg != "--forward"]

    dd_api_key_override = bool(os.environ.get("DD_API_KEY")) or _has_option(configured_args, "--dd-api-key")
    dd_site_override = bool(os.environ.get("DD_SITE")) or _has_option(configured_args, "--dd-site")

    if not dd_api_key_override:
        try:
            api_key = config.get_api_key()
        except Exception:
            log.warning("Could not read the Lapdog API key from the system keyring", exc_info=True)
        else:
            if api_key:
                environment_defaults["DD_API_KEY"] = api_key

    persisted_site = persisted.get("dd_site")
    if not dd_site_override and isinstance(persisted_site, str) and persisted_site:
        environment_defaults["DD_SITE"] = persisted_site

    forwarding_disabled_inline = _has_option(configured_args, "--disable-llmobs-data-forwarding")
    forwarding_disabled_in_env = os.environ.get("DISABLE_LLMOBS_DATA_FORWARDING", "").lower() in (
        "true",
        "1",
        "yes",
    )
    if forward_override:
        configured_args = [arg for arg in configured_args if arg != "--disable-llmobs-data-forwarding"]
    elif not forwarding_disabled_inline and not forwarding_disabled_in_env:
        if persisted.get("data_forwarding") is not True:
            configured_args.append("--disable-llmobs-data-forwarding")

    return (
        configured_args,
        {
            "dd_api_key": dd_api_key_override,
            "dd_site": dd_site_override,
            "forward": forward_override,
        },
        environment_defaults,
    )


def _inject_lapdog_forwarded(data: bytes, content_encoding: str) -> bytes:
    """Add ``lapdog_forwarded:true`` to each forwarded LLMObs span."""
    try:
        is_gzipped = "gzip" in content_encoding.lower()
        if is_gzipped:
            data = gzip.decompress(data)
        payload = msgpack.unpackb(data, raw=False)
        if isinstance(payload, dict):
            ml_obs = payload.get("ml_obs")
            spans = (ml_obs.get("spans") if isinstance(ml_obs, dict) else None) or payload.get("spans") or []
            for span in spans:
                if not isinstance(span, dict):
                    continue
                tags = span.get("tags") or []
                if "lapdog_forwarded:true" not in tags:
                    span["tags"] = tags + ["lapdog_forwarded:true"]
        data = msgpack.packb(payload, use_bin_type=True)
        if is_gzipped:
            data = gzip.compress(data)
    except Exception:
        pass
    return data


def extend_app(app: web.Application) -> web.Application:
    """Add Lapdog routes, shared state, forwarding behavior, and cleanup hooks."""
    agent = app["agent"]

    llmobs_event_platform_api = LLMObsEventPlatformAPI(agent)
    claude_link_tracker = ClaudeLinkTracker()
    claude_hooks_api = ClaudeHooksAPI(link_tracker=claude_link_tracker)
    claude_hooks_api.set_app(app)
    llmobs_event_platform_api.set_claude_hooks_api(claude_hooks_api)

    claude_proxy_api = ClaudeProxyAPI(hooks_api=claude_hooks_api, link_tracker=claude_link_tracker)
    pi_hooks_api = PiHooksAPI(hooks_api=claude_hooks_api)
    codex_hooks_api = CodexHooksAPI(hooks_api=claude_hooks_api)
    codex_proxy_api = CodexProxyAPI(hooks_api=codex_hooks_api)
    auth_api = LapdogAuthAPI()
    auth_api.set_app(app)

    app.add_routes(llmobs_event_platform_api.get_routes())
    app.add_routes(claude_hooks_api.get_routes())
    app.add_routes(claude_proxy_api.get_routes())
    app.add_routes(pi_hooks_api.get_routes())
    app.add_routes(codex_hooks_api.get_routes())
    app.add_routes(codex_proxy_api.get_routes())
    app.add_routes(auth_api.get_routes())

    app["llmobs_event_platform_api"] = llmobs_event_platform_api
    agent.llmobs_payload_transform = _inject_lapdog_forwarded
    agent.llmobs_span_update_listener = llmobs_event_platform_api.update_spans

    async def cleanup_proxies(cleanup_app: web.Application) -> None:
        await claude_proxy_api.close()
        await codex_proxy_api.close()

    app.on_cleanup.append(cleanup_proxies)
    return app


def make_app(*args: Any, **kwargs: Any) -> web.Application:
    """Create the standard test-agent app and extend it with Lapdog behavior."""
    return extend_app(test_agent.make_app(*args, **kwargs))


def main(args: Optional[List[str]] = None) -> None:
    """Run the Lapdog server using the shared test-agent server lifecycle."""
    startup_args, overrides, environment_defaults = _prepare_startup(list(args if args is not None else sys.argv[1:]))
    os.environ.update(environment_defaults)

    def app_factory(*factory_args: Any, **factory_kwargs: Any) -> web.Application:
        app = make_app(*factory_args, **factory_kwargs)
        app["lapdog_auth_overrides"] = overrides
        return app

    test_agent.main(args=startup_args, app_factory=app_factory)


if __name__ == "__main__":
    main()
