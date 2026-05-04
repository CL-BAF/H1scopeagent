"""External tool detection for H1ScopeAgent.

Scans PATH for common recon/security tools and reports their availability,
version, and autonomy classification.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
    autonomous_allowed: bool = False
    requires_approval: bool = False


TOOL_DEFINITIONS: dict[str, dict[str, bool | str]] = {
    "curl": {"autonomous_allowed": True, "requires_approval": False},
    "dig": {"autonomous_allowed": True, "requires_approval": False},
    "nslookup": {"autonomous_allowed": True, "requires_approval": False},
    "host": {"autonomous_allowed": True, "requires_approval": False},
    "whois": {"autonomous_allowed": True, "requires_approval": False},
    "openssl": {"autonomous_allowed": True, "requires_approval": False},
    "jq": {"autonomous_allowed": True, "requires_approval": False},
    "git": {"autonomous_allowed": True, "requires_approval": False},
    "sqlite3": {"autonomous_allowed": True, "requires_approval": False},
    "nmap": {"autonomous_allowed": False, "requires_approval": True},
    "gobuster": {"autonomous_allowed": False, "requires_approval": True},
    "ffuf": {"autonomous_allowed": False, "requires_approval": True},
    "wfuzz": {"autonomous_allowed": False, "requires_approval": True},
    "dirsearch": {"autonomous_allowed": False, "requires_approval": True},
    "nikto": {"autonomous_allowed": False, "requires_approval": True},
    "nuclei": {"autonomous_allowed": False, "requires_approval": True},
    "httpx": {"autonomous_allowed": True, "requires_approval": False},
    "subfinder": {"autonomous_allowed": True, "requires_approval": False},
}


def _get_version(cmd: str) -> str | None:
    try:
        result = subprocess.run(
            [cmd, "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass

    try:
        result = subprocess.run(
            [cmd, "-v"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass

    try:
        result = subprocess.run(
            [cmd, "version"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[0]
    except Exception:
        pass

    return None


def scan_tools() -> list[ToolInfo]:
    results: list[ToolInfo] = []
    for name, config in TOOL_DEFINITIONS.items():
        found = shutil.which(name)
        info = ToolInfo(
            name=name,
            installed=bool(found),
            path=found,
            version=_get_version(name) if found else None,
            autonomous_allowed=bool(config.get("autonomous_allowed", False)),
            requires_approval=bool(config.get("requires_approval", False)),
        )
        results.append(info)
    return results


def tool_is_available(name: str) -> bool:
    return bool(shutil.which(name))
