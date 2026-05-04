"""Screenshot utility for browser scouting."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from h1scopeagent.config import SCREENSHOTS_DIR


def sanitize_filename(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    path_part = parsed.path.strip("/").replace("/", "_").replace("\\", "_")[:60]
    safe = host + ("_" + path_part if path_part else "")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe)
    return safe[:100]


def generate_screenshot_path(program_handle: str, url: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"{ts}_{sanitize_filename(url)}.png"
    path = SCREENSHOTS_DIR / program_handle / fname
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
