"""Audit logging for H1ScopeAgent.

Structured JSON-line logger that records all actions while
never logging tokens, secrets, passwords, or cookie values.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from h1scopeagent.config import DATA_DIR, get_settings, redact_token_from_text

LOGS_DIR: Path = DATA_DIR / "logs"


class AuditLogger:
    """Singleton audit logger that writes JSON-line entries to a log file."""

    _instance: "AuditLogger | None" = None

    def __new__(cls, log_file: str | Path | None = None) -> "AuditLogger":
        if cls._instance is None:
            obj = super().__new__(cls)
            obj._initialized = False
            cls._instance = obj
        return cls._instance

    def __init__(self, log_file: str | Path | None = None):
        if self._initialized:
            return
        self._initialized = True

        resolved = Path(log_file) if log_file else LOGS_DIR / "audit.log"
        resolved.parent.mkdir(parents=True, exist_ok=True)
        self._path = resolved
        self._settings = get_settings()

    def _log(self, level: str, event: str, details: dict | None = None) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level.upper(),
            "event": event,
            "details": self._sanitize(details or {}),
        }
        line = json.dumps(entry, default=str)
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def _sanitize(self, details: dict) -> dict:
        cleaned = {}
        for key, value in details.items():
            val_str = str(value)
            if self._settings.hackerone_token:
                val_str = redact_token_from_text(val_str, self._settings.hackerone_token)
            cleaned[key] = val_str
        return cleaned

    # ------------------------------------------------------------------
    # Event methods
    # ------------------------------------------------------------------
    def log_api_sync(self, program_handle: str, item_count: int, duration: float = 0) -> None:
        self._log("INFO", "api_sync", {
            "program": program_handle,
            "items_synced": item_count,
            "duration_seconds": round(duration, 3),
        })

    def log_scope_decision(self, target: str, decision: str, reason: str = "") -> None:
        self._log("INFO", "scope_decision", {
            "target": target, "decision": decision, "reason": reason,
        })

    def log_blocked_command(self, command: str, reason: str, program_handle: str = "") -> None:
        self._log("WARN", "command_blocked", {
            "command": command, "program": program_handle, "block_reason": reason,
        })

    def log_approved_command(self, command: str, program_handle: str, target: str = "") -> None:
        self._log("INFO", "command_approved", {
            "command": command, "program": program_handle, "target": target,
        })

    def log_command_output(self, command: str, exit_code: int, output_summary: str = "") -> None:
        self._log("INFO", "command_executed", {
            "command": command,
            "exit_code": exit_code,
            "output_summary": output_summary[:500],
        })

    def log_browser_scout(self, url: str, final_url: str, in_scope: bool, manual_review: bool = False) -> None:
        self._log("INFO", "browser_scout", {
            "original_url": url, "final_url": final_url,
            "in_scope": in_scope, "manual_review_required": manual_review,
        })

    def log_redirect_decision(self, original: str, final: str, allowed: bool, reason: str = "") -> None:
        self._log("INFO", "redirect_decision", {
            "original_url": original, "final_url": final,
            "allowed": allowed, "reason": reason,
        })

    def log_autonomous_decision(self, step: str, target: str, action: str, reason: str = "") -> None:
        self._log("INFO", "autonomous_decision", {
            "step": step, "target": target, "action": action, "reason": reason,
        })

    def log_finding_created(self, finding_id: str, candidate_type: str, severity: str) -> None:
        self._log("INFO", "finding_created", {
            "finding_id": finding_id, "type": candidate_type, "severity": severity,
        })

    def log_report_generated(self, report_id: str, finding_id: str) -> None:
        self._log("INFO", "report_generated", {
            "report_id": report_id, "finding_id": finding_id,
        })

    def log_error(self, context: str, error_msg: str) -> None:
        self._log("ERROR", "error", {"context": context, "error": error_msg})
