"""Generic startup hook for ddapm-test-agent.

This module is loaded at Python interpreter startup via the ddapm-test-agent.pth file
installed in site-packages. Hook code is defined inline below and conditionally
executed based on the DDAPM_TEST_AGENT_HOOKS environment variable.

Hooks are specified as a comma-separated list of hook names::

    DDAPM_TEST_AGENT_HOOKS=hook1,hook2 python myapp.py
"""
import os

_enabled_hooks = {h.strip() for h in os.environ.get("DDAPM_TEST_AGENT_HOOKS", "").split(",") if h.strip()}


if "my_hook" in _enabled_hooks:                                                                                                                                                    
    ...
