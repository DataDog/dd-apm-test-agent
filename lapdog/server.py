"""Lapdog server composed on top of the Datadog APM test-agent application."""

import gzip
from typing import Any
from typing import List
from typing import Optional

from aiohttp import web
import msgpack

from ddapm_test_agent import agent as test_agent

from .claude_hooks import ClaudeHooksAPI
from .claude_link_tracker import ClaudeLinkTracker
from .claude_proxy import ClaudeProxyAPI
from .codex_hooks import CodexHooksAPI
from .codex_proxy import CodexProxyAPI
from .llmobs_event_platform import LLMObsEventPlatformAPI
from .pi_hooks import PiHooksAPI


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

    app.add_routes(llmobs_event_platform_api.get_routes())
    app.add_routes(claude_hooks_api.get_routes())
    app.add_routes(claude_proxy_api.get_routes())
    app.add_routes(pi_hooks_api.get_routes())
    app.add_routes(codex_hooks_api.get_routes())
    app.add_routes(codex_proxy_api.get_routes())

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
    test_agent.main(args=args, app_factory=make_app)


if __name__ == "__main__":
    main()
