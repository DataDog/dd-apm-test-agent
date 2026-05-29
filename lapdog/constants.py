"""Shared lapdog constants.

Kept separate from ``paths.py`` (filesystem paths) so both the CLI and the
Claude Code status line script can import the hosted dashboard URL without
duplicating it. The pi extension (TypeScript) keeps its own copy since it
can't import Python.
"""

from urllib.parse import quote

# Hosted lapdog dashboard. It reads directly from the local test agent on
# localhost, so the base URL is constant regardless of LAPDOG_URL / DD_SITE.
LAPDOG_DASHBOARD_URL = "https://lapdog.datadoghq.com"


def session_dashboard_url(session_id: str) -> str:
    """Build the lapdog dashboard deep-link for a coding-agent session."""
    return f"{LAPDOG_DASHBOARD_URL}/?sessionId={quote(session_id, safe='')}"
