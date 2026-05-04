"""High-level browser scouting orchestration.

Coordinates ChromiumScout with scope validation, screenshot capture,
finding detection, and database persistence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from h1scopeagent.config import SCREENSHOTS_DIR, METADATA_DIR
from h1scopeagent.db.database import get_db, save_browser_scout
from h1scopeagent.logs.audit import AuditLogger


def _sanitize_filename(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or "unknown"
    path_part = parsed.path.strip("/").replace("/", "_").replace("\\", "_")[:60]
    safe = host + ("_" + path_part if path_part else "")
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe)
    return safe[:100]


def _generate_screenshot_path(program_handle: str, url: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"{ts}_{_sanitize_filename(url)}.png"
    path = SCREENSHOTS_DIR / program_handle / fname
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _generate_metadata_path(program_handle: str, url: str) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"{ts}_{_sanitize_filename(url)}.json"
    path = METADATA_DIR / program_handle / fname
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


async def scout_with_safety(
    chromium_scout,
    url: str,
    scope_validator,
    policy,
    program_handle: str,
) -> dict[str, Any]:
    """
    Scout a single URL with full safety checks, screenshot capture,
    metadata extraction, finding detection, and database persistence.
    """
    audit = AuditLogger()
    audit.log_browser_scout(url, "", True, False)
    audit.log_autonomous_decision("browser_scout_start", url, "scouting", "")

    sc = await chromium_scout.scout_url(url, scope_validator)

    if sc.get("error") and "Redirect to out-of-scope" in str(sc.get("error")):
        console_print = None
        try:
            from rich.console import Console
            console_print = Console().print
        except ImportError:
            console_print = print
        if console_print:
            console_print(f"  [yellow]Stopped: redirect to out-of-scope URL[/yellow]")
        audit.log_redirect_decision(url, sc.get("final_url", ""), False, sc.get("error", ""))
        return sc

    if sc.get("manual_review_required"):
        audit.log_autonomous_decision("manual_review_required", url, "stop", sc.get("error", ""))
        return sc

    # Take screenshot
    screenshot_path = _generate_screenshot_path(program_handle, url)
    try:
        page = chromium_scout._browser.contexts[-1].pages[-1] if (
            chromium_scout._browser and chromium_scout._browser.contexts
        ) else None
        if page:
            await chromium_scout.take_screenshot(page, str(screenshot_path))
        else:
            # Re-open for screenshot
            ctx = await chromium_scout._browser.new_context()
            pg = await ctx.new_page()
            await pg.goto(url, wait_until="domcontentloaded", timeout=30_000)
            try:
                await pg.wait_for_load_state("networkidle", timeout=10_000)
            except Exception:
                pass
            await chromium_scout.take_screenshot(pg, str(screenshot_path))
            await ctx.close()
        sc["screenshot_path"] = str(screenshot_path)
    except Exception as e:
        sc["screenshot_path"] = ""
        audit.log_error("screenshot", str(e))

    # Save metadata JSON
    metadata_path = _generate_metadata_path(program_handle, url)
    try:
        metadata = {
            "original_url": sc["original_url"],
            "final_url": sc["final_url"],
            "status_code": sc["status_code"],
            "title": sc["title"],
            "metadata": json.loads(sc.get("metadata_json", "{}")),
            "console_errors": json.loads(sc.get("console_errors_json", "[]")),
            "forms": json.loads(sc.get("forms_json", "[]")),
            "links": json.loads(sc.get("links_json", "[]")),
            "screenshot_path": sc.get("screenshot_path", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        metadata_path.write_text(json.dumps(metadata, default=str, indent=2), encoding="utf-8")
        sc["metadata_path"] = str(metadata_path)
    except Exception as e:
        sc["metadata_path"] = ""
        audit.log_error("metadata_write", str(e))

    # Save to database
    try:
        with get_db() as db:
            save_browser_scout(db, {
                "program_handle": program_handle,
                "original_url": sc["original_url"],
                "final_url": sc["final_url"],
                "in_scope": sc.get("in_scope", True),
                "status_code": sc.get("status_code", 0),
                "title": sc.get("title", ""),
                "screenshot_path": sc.get("screenshot_path", ""),
                "full_page_screenshot": "",
                "metadata_json": sc.get("metadata_json", "{}"),
                "console_errors_json": sc.get("console_errors_json", "[]"),
                "forms_json": sc.get("forms_json", "[]"),
                "links_json": sc.get("links_json", "[]"),
                "network_log_json": "{}",
                "dom_snapshot_path": "",
            })
    except Exception as e:
        audit.log_error("db_save_scout", str(e))

    # Run finding detectors
    findings_count = 0
    try:
        from h1scopeagent.findings.detector import FindingDetector
        detector = FindingDetector()
        results = detector.detect_all(program_handle, sc)

        for finding in results:
            try:
                with get_db() as db:
                    from h1scopeagent.db.database import save_candidate_finding
                    save_candidate_finding(db, finding)
            except Exception:
                pass
            findings_count += 1

        # Deduplicate
        if findings_count > 1:
            try:
                from h1scopeagent.findings.dedupe import FindingDeduplicator
                deduper = FindingDeduplicator()
                with get_db() as db:
                    from h1scopeagent.db.database import get_candidate_findings
                    all_finds = get_candidate_findings(db, program_handle)
                    deduper.deduplicate(db, program_handle, all_finds)
            except Exception:
                pass
    except Exception as e:
        audit.log_error("finding_detection", str(e))

    sc["findings_count"] = findings_count
    audit.log_finding_created("batch", "scout", f"{findings_count}")

    return sc
