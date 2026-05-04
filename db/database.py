"""SQLite database layer for H1ScopeAgent.

Uses standard library sqlite3 with context managers.
All operations are synchronous.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from h1scopeagent.config import DB_PATH, get_settings
from h1scopeagent.db import models


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handle TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '',
    offers_bounties INTEGER NOT NULL DEFAULT 0,
    last_synced_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    asset_identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL DEFAULT '',
    eligible_for_bounty INTEGER NOT NULL DEFAULT 0,
    eligible_for_submission INTEGER NOT NULL DEFAULT 0,
    max_severity TEXT NOT NULL DEFAULT '',
    instruction TEXT NOT NULL DEFAULT '',
    in_scope INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_handle);
CREATE INDEX IF NOT EXISTS idx_scopes_in_scope ON scopes(program_handle, in_scope);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL UNIQUE,
    raw_policy_text TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    allowed_testing TEXT NOT NULL DEFAULT '',
    forbidden_testing TEXT NOT NULL DEFAULT '',
    rate_limits TEXT NOT NULL DEFAULT '',
    disclosure_rules TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS recon_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    plan_markdown TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_recon_plans_program ON recon_plans(program_handle);

CREATE TABLE IF NOT EXISTS command_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    approved_by_user INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT NOT NULL DEFAULT '',
    output TEXT NOT NULL DEFAULT '',
    exit_code INTEGER NOT NULL DEFAULT -1,
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_command_logs_program ON command_logs(program_handle);

CREATE TABLE IF NOT EXISTS browser_scouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    original_url TEXT NOT NULL DEFAULT '',
    final_url TEXT NOT NULL DEFAULT '',
    in_scope INTEGER NOT NULL DEFAULT 1,
    manual_review_required INTEGER NOT NULL DEFAULT 0,
    status_code INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    console_errors_json TEXT NOT NULL DEFAULT '[]',
    forms_json TEXT NOT NULL DEFAULT '[]',
    links_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_browser_scouts_program ON browser_scouts(program_handle);

CREATE TABLE IF NOT EXISTS candidate_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    candidate_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    candidate_type TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'low',
    estimated_severity TEXT NOT NULL DEFAULT 'info',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    screenshot_path TEXT NOT NULL DEFAULT '',
    metadata_path TEXT NOT NULL DEFAULT '',
    safe_to_verify INTEGER NOT NULL DEFAULT 0,
    verification_requires_approval INTEGER NOT NULL DEFAULT 0,
    report_ready INTEGER NOT NULL DEFAULT 0,
    policy_notes TEXT NOT NULL DEFAULT '',
    recommended_next_step TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_program ON candidate_findings(program_handle);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON candidate_findings(program_handle, confidence);

CREATE TABLE IF NOT EXISTS report_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    markdown_body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reports_program ON report_drafts(program_handle);
"""


@contextmanager
def get_db(db_path: str | Path | None = None) -> Generator[sqlite3.Connection, None, None]:
    resolved = Path(db_path) if db_path else DB_PATH
    resolved.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(resolved))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | Path | None = None) -> None:
    with get_db(db_path) as db:
        db.executescript(SCHEMA_SQL)


def _boolval(v: Any) -> int:
    return 1 if v else 0


def _to_bool(v: Any) -> bool:
    return bool(v)


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------
def upsert_program(db: sqlite3.Connection, program: models.Program) -> None:
    now = _now_iso()
    db.execute(
        """
        INSERT INTO programs (handle, name, state, offers_bounties, last_synced_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(handle) DO UPDATE SET
            name=excluded.name,
            state=excluded.state,
            offers_bounties=excluded.offers_bounties,
            last_synced_at=excluded.last_synced_at
        """,
        (program.handle, program.name, program.state, _boolval(program.offers_bounties), now),
    )


def get_programs(db: sqlite3.Connection) -> list[models.Program]:
    rows = db.execute("SELECT * FROM programs ORDER BY name").fetchall()
    return [models.Program.from_row(dict(r)) for r in rows]


def get_program(db: sqlite3.Connection, handle: str) -> models.Program | None:
    row = db.execute("SELECT * FROM programs WHERE handle = ?", (handle,)).fetchone()
    return models.Program.from_row(dict(row)) if row else None


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------
def upsert_scopes(
    db: sqlite3.Connection,
    program_handle: str,
    entries: list[models.ScopeEntry],
) -> None:
    now = _now_iso()
    db.execute("DELETE FROM scopes WHERE program_handle = ?", (program_handle,))
    for e in entries:
        db.execute(
            """
            INSERT INTO scopes (
                program_handle, asset_identifier, asset_type,
                eligible_for_bounty, eligible_for_submission, max_severity,
                instruction, in_scope, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_handle,
                e.asset_identifier,
                e.asset_type,
                _boolval(e.eligible_for_bounty),
                _boolval(e.eligible_for_submission),
                e.max_severity,
                e.instruction,
                _boolval(e.in_scope),
                now,
                now,
            ),
        )


def get_scopes(
    db: sqlite3.Connection, program_handle: str
) -> tuple[list[models.ScopeEntry], list[models.ScopeEntry]]:
    in_rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? AND in_scope = 1 ORDER BY asset_identifier",
        (program_handle,),
    ).fetchall()
    out_rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? AND in_scope = 0 ORDER BY asset_identifier",
        (program_handle,),
    ).fetchall()
    return (
        [models.ScopeEntry.from_row(dict(r)) for r in in_rows],
        [models.ScopeEntry.from_row(dict(r)) for r in out_rows],
    )


def get_all_scope_entries(
    db: sqlite3.Connection, program_handle: str
) -> list[models.ScopeEntry]:
    rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? ORDER BY in_scope DESC, asset_identifier",
        (program_handle,),
    ).fetchall()
    return [models.ScopeEntry.from_row(dict(r)) for r in rows]


def get_in_scope_web_assets(
    db: sqlite3.Connection, program_handle: str
) -> list[models.ScopeEntry]:
    rows = db.execute(
        """
        SELECT * FROM scopes
        WHERE program_handle = ? AND in_scope = 1
          AND (asset_type = 'URL' OR asset_type = 'domain' OR asset_type = 'web')
          AND asset_identifier NOT LIKE '%.apk'
          AND asset_identifier NOT LIKE '%.ipa'
          AND asset_identifier NOT LIKE 'com.%'
        ORDER BY asset_identifier
        """,
        (program_handle,),
    ).fetchall()
    return [models.ScopeEntry.from_row(dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
def upsert_policy(
    db: sqlite3.Connection,
    program_handle: str,
    policy: models.PolicyRecord,
) -> None:
    now = _now_iso()
    db.execute(
        """
        INSERT INTO policies (
            program_handle, raw_policy_text, summary,
            allowed_testing, forbidden_testing, rate_limits,
            disclosure_rules, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(program_handle) DO UPDATE SET
            raw_policy_text=excluded.raw_policy_text,
            summary=excluded.summary,
            allowed_testing=excluded.allowed_testing,
            forbidden_testing=excluded.forbidden_testing,
            rate_limits=excluded.rate_limits,
            disclosure_rules=excluded.disclosure_rules,
            updated_at=excluded.updated_at
        """,
        (
            program_handle,
            policy.raw_policy_text,
            policy.summary,
            policy.allowed_testing,
            policy.forbidden_testing,
            policy.rate_limits,
            policy.disclosure_rules,
            now,
        ),
    )


def get_policy(
    db: sqlite3.Connection, program_handle: str
) -> models.PolicyRecord | None:
    row = db.execute(
        "SELECT * FROM policies WHERE program_handle = ?", (program_handle,)
    ).fetchone()
    return models.PolicyRecord.from_row(dict(row)) if row else None


# ---------------------------------------------------------------------------
# Recon Plans
# ---------------------------------------------------------------------------
def save_recon_plan(
    db: sqlite3.Connection,
    program_handle: str,
    plan_markdown: str,
) -> None:
    db.execute(
        "INSERT INTO recon_plans (program_handle, plan_markdown, created_at) VALUES (?, ?, ?)",
        (program_handle, plan_markdown, _now_iso()),
    )


def get_latest_recon_plan(
    db: sqlite3.Connection, program_handle: str
) -> models.ReconPlan | None:
    row = db.execute(
        "SELECT * FROM recon_plans WHERE program_handle = ? ORDER BY created_at DESC LIMIT 1",
        (program_handle,),
    ).fetchone()
    return models.ReconPlan.from_row(dict(row)) if row else None


# ---------------------------------------------------------------------------
# Command Logs
# ---------------------------------------------------------------------------
def save_command_log(
    db: sqlite3.Connection, entry: models.CommandLogEntry
) -> int:
    now = _now_iso()
    cur = db.execute(
        """
        INSERT INTO command_logs (
            program_handle, command, target, approved_by_user,
            blocked, block_reason, output, exit_code, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.program_handle,
            entry.command,
            entry.target,
            _boolval(entry.approved_by_user),
            _boolval(entry.blocked),
            entry.block_reason,
            entry.output,
            entry.exit_code,
            now,
        ),
    )
    return cur.lastrowid


def get_command_logs(
    db: sqlite3.Connection, program_handle: str, limit: int = 100
) -> list[models.CommandLogEntry]:
    rows = db.execute(
        "SELECT * FROM command_logs WHERE program_handle = ? ORDER BY created_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [models.CommandLogEntry.from_row(dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# Browser Scouts
# ---------------------------------------------------------------------------
def save_browser_scout(
    db: sqlite3.Connection, entry: models.BrowserScoutEntry
) -> int:
    now = _now_iso()
    cur = db.execute(
        """
        INSERT INTO browser_scouts (
            program_handle, original_url, final_url, in_scope,
            manual_review_required, status_code, title,
            screenshot_path, metadata_json, console_errors_json,
            forms_json, links_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.program_handle,
            entry.original_url,
            entry.final_url,
            _boolval(entry.in_scope),
            _boolval(entry.manual_review_required),
            entry.status_code,
            entry.title,
            entry.screenshot_path,
            entry.metadata_json,
            entry.console_errors_json,
            entry.forms_json,
            entry.links_json,
            now,
        ),
    )
    return cur.lastrowid


def get_browser_scouts(
    db: sqlite3.Connection, program_handle: str, limit: int = 50
) -> list[models.BrowserScoutEntry]:
    rows = db.execute(
        "SELECT * FROM browser_scouts WHERE program_handle = ? ORDER BY created_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [models.BrowserScoutEntry.from_row(dict(r)) for r in rows]


# ---------------------------------------------------------------------------
# Candidate Findings
# ---------------------------------------------------------------------------
def save_candidate_finding(
    db: sqlite3.Connection, finding: dict[str, Any]
) -> None:
    now = _now_iso()
    existing = db.execute(
        "SELECT id FROM candidate_findings WHERE candidate_id = ?",
        (finding["candidate_id"],),
    ).fetchone()

    if existing:
        db.execute(
            """
            UPDATE candidate_findings SET
                title=?, affected_asset=?, candidate_type=?,
                confidence=?, estimated_severity=?,
                evidence_json=?, screenshot_path=?, metadata_path=?,
                safe_to_verify=?, verification_requires_approval=?,
                report_ready=?, policy_notes=?, recommended_next_step=?,
                updated_at=?
            WHERE candidate_id=?
            """,
            (
                finding["title"],
                finding["affected_asset"],
                finding["candidate_type"],
                finding["confidence"],
                finding["estimated_severity"],
                json.dumps(finding.get("evidence", {})),
                finding.get("screenshot_path", ""),
                finding.get("metadata_path", ""),
                _boolval(finding.get("safe_to_verify", False)),
                _boolval(finding.get("verification_requires_approval", False)),
                _boolval(finding.get("report_ready", False)),
                finding.get("policy_notes", ""),
                finding.get("recommended_next_step", ""),
                now,
                finding["candidate_id"],
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO candidate_findings (
                program_handle, candidate_id, title, affected_asset,
                candidate_type, confidence, estimated_severity,
                evidence_json, screenshot_path, metadata_path,
                safe_to_verify, verification_requires_approval,
                report_ready, policy_notes, recommended_next_step,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.get("program_handle", ""),
                finding["candidate_id"],
                finding["title"],
                finding["affected_asset"],
                finding["candidate_type"],
                finding["confidence"],
                finding["estimated_severity"],
                json.dumps(finding.get("evidence", {})),
                finding.get("screenshot_path", ""),
                finding.get("metadata_path", ""),
                _boolval(finding.get("safe_to_verify", False)),
                _boolval(finding.get("verification_requires_approval", False)),
                _boolval(finding.get("report_ready", False)),
                finding.get("policy_notes", ""),
                finding.get("recommended_next_step", ""),
                now,
                now,
            ),
        )


def get_candidate_findings(
    db: sqlite3.Connection, program_handle: str
) -> list[dict[str, Any]]:
    rows = db.execute(
        """
        SELECT * FROM candidate_findings
        WHERE program_handle = ?
        ORDER BY
            CASE estimated_severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                WHEN 'info' THEN 5
            END,
            CASE confidence
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
            END
        """,
        (program_handle,),
    ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d.get("evidence_json", "{}"))
        d["safe_to_verify"] = _to_bool(d.get("safe_to_verify", 0))
        d["verification_requires_approval"] = _to_bool(d.get("verification_requires_approval", 0))
        d["report_ready"] = _to_bool(d.get("report_ready", 0))
        results.append(d)
    return results


def count_candidate_findings(
    db: sqlite3.Connection, program_handle: str
) -> int:
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM candidate_findings WHERE program_handle = ?",
        (program_handle,),
    ).fetchone()
    return row["cnt"] if row else 0


def finding_exists_by_hash(
    db: sqlite3.Connection, program_handle: str, hash_key: str
) -> bool:
    row = db.execute(
        "SELECT 1 FROM candidate_findings WHERE program_handle = ? AND candidate_id LIKE ?",
        (program_handle, f"%{hash_key}%"),
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Report Drafts
# ---------------------------------------------------------------------------
def save_report_draft(
    db: sqlite3.Connection, program_handle: str, report: dict[str, Any]
) -> None:
    now = _now_iso()
    db.execute(
        """
        INSERT INTO report_drafts (
            program_handle, finding_id, title, affected_asset,
            severity, markdown_body, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            program_handle,
            report.get("finding_id", ""),
            report.get("title", ""),
            report.get("affected_asset", ""),
            report.get("severity", "info"),
            report.get("markdown_body", ""),
            now,
            now,
        ),
    )


def get_report_drafts(
    db: sqlite3.Connection, program_handle: str
) -> list[dict[str, Any]]:
    rows = db.execute(
        "SELECT * FROM report_drafts WHERE program_handle = ? ORDER BY created_at DESC",
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]
