"""Shared ml_app names for lapdog coding-agent integrations."""

import os

CLAUDE_CODE_ML_APP = os.environ.get("DD_CLAUDE_CODE_ML_APP", "claude-code")
PI_CODING_AGENT_ML_APP = os.environ.get("DD_PI_CODING_AGENT_ML_APP", "pi-coding-agent")
