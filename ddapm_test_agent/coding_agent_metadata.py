"""Project metadata helpers for coding-agent LLMObs traces."""

import dataclasses
from functools import lru_cache
import logging
import os
from pathlib import Path
import re
import subprocess
from typing import Any
from typing import Dict
from typing import List
from urllib.parse import urlparse


log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class CodingAgentProjectMetadata:
    project_name: str = ""
    git_repository_url: str = ""


def _strip_git_suffix(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def normalize_git_repository_url(url: Any) -> str:
    """Normalize a Git remote URL for Datadog's `git.repository_url` tag."""
    if not isinstance(url, str):
        return ""
    value = _strip_git_suffix(url)
    if not value:
        return ""

    parsed = urlparse(value)
    if parsed.scheme:
        if parsed.scheme == "file":
            return _strip_git_suffix(parsed.path)
        host = parsed.hostname or ""
        path = parsed.path.lstrip("/")
        return _strip_git_suffix(f"{host}/{path}" if host and path else host or path)

    scp_like = re.match(r"^(?:[^@/\s]+@)?([^:\s]+):/?(.+)$", value)
    if scp_like:
        host, path = scp_like.groups()
        return _strip_git_suffix(f"{host}/{path.lstrip('/')}")

    return _strip_git_suffix(value.lstrip("/"))


def project_name_from_git_repository_url(url: Any) -> str:
    normalized = normalize_git_repository_url(url)
    if not normalized:
        return ""
    return Path(normalized).name


def extract_agent_project_name(payload: Dict[str, Any]) -> str:
    """Feature-detect stable project/workspace fields without using session titles.

    Only matches the explicit ``*_name`` / ``*Name`` keys plus the nested
    ``{project,workspace}.name`` form — bare ``project`` / ``workspace`` string
    fields are intentionally not matched, since those names are too generic and
    would risk capturing unrelated payload fields.
    """
    for key in ("project_name", "projectName", "workspace_name", "workspaceName"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("project", "workspace"):
        value = payload.get(key)
        if isinstance(value, dict):
            name = value.get("name")
            if isinstance(name, str) and name.strip():
                return name.strip()
    return ""


def extract_git_repository_url(payload: Dict[str, Any]) -> str:
    for key in ("git_repository_url", "gitRepositoryUrl", "repository_url", "repositoryUrl"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    git_info = payload.get("git") or payload.get("git_info") or payload.get("gitInfo")
    if isinstance(git_info, dict):
        for key in ("repository_url", "repositoryUrl", "origin_url", "originUrl", "git_origin_url"):
            value = git_info.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def project_metadata_tags(metadata: CodingAgentProjectMetadata) -> List[str]:
    tags: List[str] = []
    if metadata.project_name:
        tags.append(f"project_name:{metadata.project_name}")
    if metadata.git_repository_url:
        tags.append(f"git.repository_url:{metadata.git_repository_url}")
    return tags


def apply_project_metadata_to_span(span: Dict[str, Any], metadata: CodingAgentProjectMetadata) -> None:
    if not metadata.project_name and not metadata.git_repository_url:
        return
    span_metadata = span.setdefault("meta", {}).setdefault("metadata", {})
    if metadata.project_name:
        span_metadata["project_name"] = metadata.project_name
    if metadata.git_repository_url:
        span_metadata["git_repository_url"] = metadata.git_repository_url


def resolve_project_metadata(
    *,
    cwd: str = "",
    project_name: str = "",
    git_repository_url: str = "",
) -> CodingAgentProjectMetadata:
    cwd = str(cwd or "").strip() or os.getcwd()
    project_name = str(project_name or "").strip()
    normalized_url = normalize_git_repository_url(git_repository_url)

    if not normalized_url:
        normalized_url = normalize_git_repository_url(os.environ.get("DD_GIT_REPOSITORY_URL", ""))

    if not normalized_url:
        local = _local_git_metadata(cwd)
        normalized_url = local.git_repository_url
        if not project_name:
            project_name = local.project_name

    if normalized_url and not project_name:
        project_name = project_name_from_git_repository_url(normalized_url)

    if not project_name:
        project_name = _cwd_basename(cwd)

    return CodingAgentProjectMetadata(project_name=project_name, git_repository_url=normalized_url)


# Cached by cwd path. We assume the remote URL is effectively immutable for the
# lifetime of a lapdog process; if a user re-points a remote mid-session they'll
# need to restart the test agent to pick up the new value.
@lru_cache(maxsize=256)
def _local_git_metadata(cwd: str) -> CodingAgentProjectMetadata:
    cwd = str(cwd or "").strip()
    if not cwd:
        return CodingAgentProjectMetadata()

    git_root = _run_git(cwd, "rev-parse", "--show-toplevel")
    repo_url = _run_git(cwd, "config", "--get", "remote.origin.url") or _run_git(
        cwd, "config", "--get", "remote.upstream.url"
    )
    normalized_url = normalize_git_repository_url(repo_url)

    project_name = project_name_from_git_repository_url(normalized_url)
    if not project_name and git_root:
        project_name = _cwd_basename(git_root)

    return CodingAgentProjectMetadata(project_name=project_name, git_repository_url=normalized_url)


def _run_git(cwd: str, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", cwd, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except subprocess.TimeoutExpired:
        log.debug("git %s in %s timed out", " ".join(args), cwd)
        return ""
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git %s in %s failed: %s", " ".join(args), cwd, exc)
        return ""
    if result.returncode != 0:
        log.debug(
            "git %s in %s exited %s: %s",
            " ".join(args),
            cwd,
            result.returncode,
            result.stderr.strip(),
        )
        return ""
    return result.stdout.strip()


def _cwd_basename(cwd: str) -> str:
    value = str(cwd or "").strip()
    if not value:
        return ""
    return Path(value).resolve().name
