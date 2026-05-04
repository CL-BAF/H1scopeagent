"""SQLite database layer with migration support for H1ScopeAgent."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from h1scopeagent.config import DB_PATH, get_settings


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _boolval(v: Any) -> int:
    return 1 if v else 0


def _to_bool(v: Any) -> bool:
    return bool(v)


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


def init_db(db_path: str | Path | None = None) -> int:
    """Apply all pending migrations. Returns number applied."""
    with get_db(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                applied_at TEXT NOT NULL DEFAULT ''
            )
        """)
        current = db.execute("SELECT COALESCE(MAX(version), 0) as v FROM migrations").fetchone()["v"]

        migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
        applied = 0

        if migrations_dir.exists():
            for mf in sorted(migrations_dir.glob("[0-9]*.sql")):
                ver = int(mf.stem.split("_")[0])
                if ver > current:
                    sql = mf.read_text(encoding="utf-8")
                    db.executescript(sql)
                    applied += 1

        return applied


# ---------------------------------------------------------------------------
# Programs
# ---------------------------------------------------------------------------
def upsert_program(db: sqlite3.Connection, program: dict | object) -> None:
    if isinstance(program, dict):
        d = program
    else:
        d = program.__dict__
    now = _now_iso()
    db.execute(
        """
        INSERT INTO programs (handle, name, state, offers_bounties, currency, confidential, bookmarked, last_synced_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(handle) DO UPDATE SET
            name=excluded.name, state=excluded.state,
            offers_bounties=excluded.offers_bounties, currency=excluded.currency,
            confidential=excluded.confidential, bookmarked=excluded.bookmarked,
            last_synced_at=excluded.last_synced_at
        """,
        (
            d.get("handle", ""), d.get("name", ""), d.get("state", ""),
            _boolval(d.get("offers_bounties", False)), d.get("currency", ""),
            _boolval(d.get("confidential", False)), _boolval(d.get("bookmarked", False)),
            now,
        ),
    )


def get_programs(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute("SELECT * FROM programs ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def get_program(db: sqlite3.Connection, handle: str) -> dict | None:
    row = db.execute("SELECT * FROM programs WHERE handle = ?", (handle,)).fetchone()
    return dict(row) if row else None


def search_programs(db: sqlite3.Connection, query: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM programs WHERE handle LIKE ? OR name LIKE ? ORDER BY name",
        (f"%{query}%", f"%{query}%"),
    ).fetchall()
    return [dict(r) for r in rows]


def get_bookmarked_programs(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM programs WHERE bookmarked = 1 ORDER BY name"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------
def upsert_scopes(
    db: sqlite3.Connection,
    program_handle: str,
    entries: list[dict | object],
) -> None:
    now = _now_iso()
    db.execute("DELETE FROM scopes WHERE program_handle = ?", (program_handle,))
    for e in entries:
        d = e if isinstance(e, dict) else e.__dict__
        db.execute(
            """
            INSERT INTO scopes (
                program_handle, asset_identifier, asset_type,
                eligible_for_bounty, eligible_for_submission, max_severity,
                instruction, in_scope, notes, tags, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                program_handle,
                d.get("asset_identifier", ""), d.get("asset_type", ""),
                _boolval(d.get("eligible_for_bounty", False)),
                _boolval(d.get("eligible_for_submission", False)),
                d.get("max_severity", ""), d.get("instruction", ""),
                _boolval(d.get("in_scope", True)),
                d.get("notes", ""), d.get("tags", ""),
                now, now,
            ),
        )


def get_scopes(
    db: sqlite3.Connection, program_handle: str
) -> tuple[list[dict], list[dict]]:
    in_rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? AND in_scope = 1 ORDER BY asset_identifier",
        (program_handle,),
    ).fetchall()
    out_rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? AND in_scope = 0 ORDER BY asset_identifier",
        (program_handle,),
    ).fetchall()
    return ([dict(r) for r in in_rows], [dict(r) for r in out_rows])


def get_all_scope_entries(db: sqlite3.Connection, program_handle: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM scopes WHERE program_handle = ? ORDER BY in_scope DESC, asset_identifier",
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_in_scope_web_assets(
    db: sqlite3.Connection, program_handle: str
) -> list[dict]:
    rows = db.execute(
        """
        SELECT * FROM scopes
        WHERE program_handle = ? AND in_scope = 1
          AND (asset_type IN ('URL', 'domain', 'web', 'api', 'wildcard_domain'))
          AND asset_identifier NOT LIKE '%.apk'
          AND asset_identifier NOT LIKE '%.ipa'
          AND asset_identifier NOT LIKE 'com.%'
        ORDER BY asset_identifier
        """,
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Normalized Scopes
# ---------------------------------------------------------------------------
def upsert_normalized_scopes(
    db: sqlite3.Connection,
    program_handle: str,
    entries: list[dict],
) -> None:
    now = _now_iso()
    db.execute("DELETE FROM scopes_normalized WHERE program_handle = ?", (program_handle,))
    for e in entries:
        db.execute(
            """
            INSERT INTO scopes_normalized (
                scope_id, program_handle, normalized_asset, root_domain,
                asset_category, priority_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                e.get("scope_id"), program_handle,
                e.get("normalized_asset", ""), e.get("root_domain", ""),
                e.get("asset_category", "other"), e.get("priority_score", 0.0),
                now,
            ),
        )


def get_normalized_scopes(
    db: sqlite3.Connection, program_handle: str
) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM scopes_normalized WHERE program_handle = ? ORDER BY priority_score DESC",
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Scope History (diff tracking)
# ---------------------------------------------------------------------------
def log_scope_change(
    db: sqlite3.Connection,
    program_handle: str,
    asset_id: str,
    change_type: str,
    old_val: str,
    new_val: str,
) -> None:
    db.execute(
        """
        INSERT INTO scope_history (program_handle, asset_identifier, change_type, old_value, new_value, detected_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (program_handle, asset_id, change_type, old_val, new_val, _now_iso()),
    )


def get_scope_history(
    db: sqlite3.Connection, program_handle: str, limit: int = 100
) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM scope_history WHERE program_handle = ? ORDER BY detected_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
def upsert_policy(
    db: sqlite3.Connection, program_handle: str, policy: dict | object
) -> None:
    d = policy if isinstance(policy, dict) else policy.__dict__
    now = _now_iso()
    db.execute(
        """
        INSERT INTO policies (program_handle, raw_policy_text, summary,
            allowed_testing, forbidden_testing, rate_limits, disclosure_rules, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(program_handle) DO UPDATE SET
            raw_policy_text=excluded.raw_policy_text, summary=excluded.summary,
            allowed_testing=excluded.allowed_testing, forbidden_testing=excluded.forbidden_testing,
            rate_limits=excluded.rate_limits, disclosure_rules=excluded.disclosure_rules,
            updated_at=excluded.updated_at
        """,
        (
            program_handle,
            d.get("raw_policy_text", ""), d.get("summary", ""),
            d.get("allowed_testing", ""), d.get("forbidden_testing", ""),
            d.get("rate_limits", ""), d.get("disclosure_rules", ""),
            now,
        ),
    )


def get_policy(db: sqlite3.Connection, program_handle: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM policies WHERE program_handle = ?", (program_handle,)
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Bounty Tables
# ---------------------------------------------------------------------------
def upsert_bounty_tables(
    db: sqlite3.Connection, program_handle: str, entries: list[dict]
) -> None:
    now = _now_iso()
    db.execute("DELETE FROM bounty_tables WHERE program_handle = ?", (program_handle,))
    for e in entries:
        db.execute(
            """
            INSERT INTO bounty_tables (program_handle, severity, min_bounty, max_bounty, avg_bounty, currency, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (program_handle, e.get("severity", ""), e.get("min_bounty", 0.0),
             e.get("max_bounty", 0.0), e.get("avg_bounty", 0.0), e.get("currency", ""), now),
        )


def get_bounty_tables(db: sqlite3.Connection, program_handle: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM bounty_tables WHERE program_handle = ? ORDER BY avg_bounty DESC",
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Recon Plans
# ---------------------------------------------------------------------------
def save_recon_plan(db: sqlite3.Connection, program_handle: str, plan_md: str, profile: str = "") -> None:
    db.execute(
        "INSERT INTO recon_plans (program_handle, plan_markdown, profile_used, created_at) VALUES (?, ?, ?, ?)",
        (program_handle, plan_md, profile, _now_iso()),
    )


def get_latest_recon_plan(db: sqlite3.Connection, program_handle: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM recon_plans WHERE program_handle = ? ORDER BY created_at DESC LIMIT 1",
        (program_handle,),
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Scan Runs
# ---------------------------------------------------------------------------
def create_scan_run(
    db: sqlite3.Connection, program_handle: str, profile: str,
    modules: list[str], total: int
) -> int:
    now = _now_iso()
    cur = db.execute(
        """
        INSERT INTO scan_runs (program_handle, profile_used, modules_run, targets_total, status, started_at)
        VALUES (?, ?, ?, ?, 'running', ?)
        """,
        (program_handle, profile, json.dumps(modules), total, now),
    )
    return cur.lastrowid


def update_scan_run(
    db: sqlite3.Connection, run_id: int, processed: int, findings: int,
    status: str | None = None, error: str = "", checkpoint: dict | None = None,
) -> None:
    fields = ["targets_processed = ?", "findings_found = ?"]
    params: list[Any] = [processed, findings]
    if status:
        fields.append("status = ?")
        params.append(status)
        if status in ("completed", "failed", "cancelled"):
            fields.append("finished_at = ?")
            params.append(_now_iso())
    if error:
        fields.append("error_message = ?")
        params.append(error)
    if checkpoint:
        fields.append("checkpoint_data = ?")
        params.append(json.dumps(checkpoint))
    params.append(run_id)
    db.execute(f"UPDATE scan_runs SET {', '.join(fields)} WHERE id = ?", params)


def get_scan_runs(db: sqlite3.Connection, program_handle: str, limit: int = 20) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM scan_runs WHERE program_handle = ? ORDER BY started_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def get_active_scan_runs(db: sqlite3.Connection) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM scan_runs WHERE status = 'running'"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
def upsert_endpoint(db: sqlite3.Connection, ep: dict) -> None:
    db.execute(
        """
        INSERT OR REPLACE INTO endpoints (program_handle, url, method, parameters, source, status_code, content_type, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ep.get("program_handle", ""), ep.get("url", ""),
            ep.get("method", "GET"), json.dumps(ep.get("parameters", [])),
            ep.get("source", "unknown"), ep.get("status_code", 0),
            ep.get("content_type", ""), _now_iso(),
        ),
    )


def get_endpoints(db: sqlite3.Connection, program_handle: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM endpoints WHERE program_handle = ? ORDER BY last_seen DESC",
        (program_handle,),
    ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["parameters"] = json.loads(d.get("parameters", "[]"))
        results.append(d)
    return results


# ---------------------------------------------------------------------------
# Command Logs
# ---------------------------------------------------------------------------
def save_command_log(db: sqlite3.Connection, entry: dict) -> int:
    cur = db.execute(
        """
        INSERT INTO command_logs (program_handle, command, target, exit_code, output, scan_run_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("program_handle", ""), entry["command"], entry.get("target", ""),
            entry.get("exit_code", -1), entry.get("output", "")[:20000],
            entry.get("scan_run_id"), _now_iso(),
        ),
    )
    return cur.lastrowid


def get_command_logs(db: sqlite3.Connection, program_handle: str, limit: int = 100) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM command_logs WHERE program_handle = ? ORDER BY created_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Browser Scouts
# ---------------------------------------------------------------------------
def save_browser_scout(db: sqlite3.Connection, entry: dict) -> int:
    cur = db.execute(
        """
        INSERT INTO browser_scouts (
            program_handle, original_url, final_url, in_scope, status_code, title,
            screenshot_path, full_page_screenshot, metadata_json, console_errors_json,
            forms_json, links_json, network_log_json, dom_snapshot_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("program_handle", ""), entry["original_url"], entry.get("final_url", ""),
            _boolval(entry.get("in_scope", True)), entry.get("status_code", 0),
            entry.get("title", ""), entry.get("screenshot_path", ""),
            entry.get("full_page_screenshot", ""),
            entry.get("metadata_json", "{}"), entry.get("console_errors_json", "[]"),
            entry.get("forms_json", "[]"), entry.get("links_json", "[]"),
            entry.get("network_log_json", "{}"), entry.get("dom_snapshot_path", ""),
            _now_iso(),
        ),
    )
    return cur.lastrowid


def get_browser_scouts(db: sqlite3.Connection, program_handle: str, limit: int = 50) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM browser_scouts WHERE program_handle = ? ORDER BY created_at DESC LIMIT ?",
        (program_handle, limit),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Browser Profiles
# ---------------------------------------------------------------------------
def save_browser_profile(db: sqlite3.Connection, entry: dict) -> None:
    now = _now_iso()
    db.execute(
        """
        INSERT INTO browser_profiles (program_handle, name, user_data_dir, cookies_json, local_storage_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(program_handle) DO UPDATE SET
            name=excluded.name, user_data_dir=excluded.user_data_dir,
            cookies_json=excluded.cookies_json, local_storage_json=excluded.local_storage_json,
            updated_at=excluded.updated_at
        """,
        (
            entry.get("program_handle", ""), entry.get("name", "default"),
            entry.get("user_data_dir", ""), entry.get("cookies_json", "{}"),
            entry.get("local_storage_json", "{}"), now, now,
        ),
    )


def get_browser_profile(db: sqlite3.Connection, program_handle: str) -> dict | None:
    row = db.execute(
        "SELECT * FROM browser_profiles WHERE program_handle = ?", (program_handle,)
    ).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Candidate Findings
# ---------------------------------------------------------------------------
def save_candidate_finding(db: sqlite3.Connection, finding: dict) -> None:
    now = _now_iso()
    existing = db.execute(
        "SELECT id FROM candidate_findings WHERE candidate_id = ?",
        (finding["candidate_id"],),
    ).fetchone()

    if existing:
        db.execute(
            """
            UPDATE candidate_findings SET
                title=?, affected_asset=?, candidate_type=?, status=?,
                confidence=?, estimated_severity=?, cvss_score=?, cvss_vector=?,
                evidence_json=?, reproduction_steps=?, impact=?, tags=?,
                raw_request=?, raw_response=?,
                screenshot_path=?, metadata_path=?, report_ready=?,
                h1_report_id=?, h1_report_state=?, updated_at=?
            WHERE candidate_id=?
            """,
            (
                finding.get("title", ""), finding.get("affected_asset", ""),
                finding.get("candidate_type", ""),
                finding.get("status", "candidate"),
                finding.get("confidence", "low"), finding.get("estimated_severity", "info"),
                finding.get("cvss_score", 0.0), finding.get("cvss_vector", ""),
                json.dumps(finding.get("evidence", {})),
                json.dumps(finding.get("reproduction_steps", [])),
                finding.get("impact", ""), finding.get("tags", ""),
                finding.get("raw_request", ""), finding.get("raw_response", ""),
                finding.get("screenshot_path", ""), finding.get("metadata_path", ""),
                _boolval(finding.get("report_ready", False)),
                finding.get("h1_report_id", ""), finding.get("h1_report_state", ""),
                now, finding["candidate_id"],
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO candidate_findings (
                program_handle, candidate_id, title, affected_asset,
                candidate_type, status, confidence, estimated_severity,
                cvss_score, cvss_vector, evidence_json, reproduction_steps,
                impact, tags, raw_request, raw_response,
                screenshot_path, metadata_path, report_ready,
                h1_report_id, h1_report_state, scan_run_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.get("program_handle", ""), finding["candidate_id"],
                finding.get("title", ""), finding.get("affected_asset", ""),
                finding.get("candidate_type", ""),
                finding.get("status", "candidate"),
                finding.get("confidence", "low"), finding.get("estimated_severity", "info"),
                finding.get("cvss_score", 0.0), finding.get("cvss_vector", ""),
                json.dumps(finding.get("evidence", {})),
                json.dumps(finding.get("reproduction_steps", [])),
                finding.get("impact", ""), finding.get("tags", ""),
                finding.get("raw_request", ""), finding.get("raw_response", ""),
                finding.get("screenshot_path", ""), finding.get("metadata_path", ""),
                _boolval(finding.get("report_ready", False)),
                finding.get("h1_report_id", ""), finding.get("h1_report_state", ""),
                finding.get("scan_run_id"), now, now,
            ),
        )


def get_candidate_findings(
    db: sqlite3.Connection, program_handle: str,
    status: str | None = None, severity: str | None = None,
    confidence: str | None = None, search: str | None = None,
    tag: str | None = None,
) -> list[dict]:
    query = """SELECT * FROM candidate_findings WHERE program_handle = ?"""
    params: list[Any] = [program_handle]

    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND estimated_severity = ?"
        params.append(severity)
    if confidence:
        query += " AND confidence = ?"
        params.append(confidence)
    if search:
        query += " AND (title LIKE ? OR affected_asset LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])
    if tag:
        query += " AND tags LIKE ?"
        params.append(f"%{tag}%")

    query += """
        ORDER BY CASE estimated_severity
            WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 END,
        CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END
    """

    rows = db.execute(query, params).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d.get("evidence_json", "{}"))
        d["reproduction_steps"] = json.loads(d.get("reproduction_steps", "[]"))
        d["report_ready"] = _to_bool(d.get("report_ready", 0))
        results.append(d)
    return results


def count_candidate_findings(db: sqlite3.Connection, program_handle: str) -> int:
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM candidate_findings WHERE program_handle = ?",
        (program_handle,),
    ).fetchone()
    return row["cnt"] if row else 0


# ---------------------------------------------------------------------------
# Finding Timeline
# ---------------------------------------------------------------------------
def add_timeline_event(
    db: sqlite3.Connection, finding_id: str, event: str, details: str
) -> None:
    db.execute(
        "INSERT INTO finding_timeline (finding_id, event, details, timestamp) VALUES (?, ?, ?, ?)",
        (finding_id, event, details, _now_iso()),
    )


def get_finding_timeline(db: sqlite3.Connection, finding_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM finding_timeline WHERE finding_id = ? ORDER BY timestamp",
        (finding_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
def save_evidence(db: sqlite3.Connection, entry: dict) -> int:
    cur = db.execute(
        """
        INSERT INTO evidence (finding_id, evidence_type, file_path, content_hash, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("finding_id", ""), entry.get("evidence_type", ""),
            entry.get("file_path", ""), entry.get("content_hash", ""),
            json.dumps(entry.get("metadata_json", {})), _now_iso(),
        ),
    )
    return cur.lastrowid


def get_evidence(db: sqlite3.Connection, finding_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at",
        (finding_id,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Report Drafts
# ---------------------------------------------------------------------------
def save_report_draft(db: sqlite3.Connection, program_handle: str, report: dict) -> None:
    now = _now_iso()
    db.execute(
        """
        INSERT INTO report_drafts (
            program_handle, finding_id, title, affected_asset, severity,
            markdown_body, html_body, pdf_path, template_used,
            submitted, h1_report_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            program_handle,
            report.get("finding_id", ""), report.get("title", ""),
            report.get("affected_asset", ""), report.get("severity", "info"),
            report.get("markdown_body", ""), report.get("html_body", ""),
            report.get("pdf_path", ""), report.get("template_used", ""),
            _boolval(report.get("submitted", False)),
            report.get("h1_report_id", ""), now, now,
        ),
    )


def get_report_drafts(db: sqlite3.Connection, program_handle: str) -> list[dict]:
    rows = db.execute(
        "SELECT * FROM report_drafts WHERE program_handle = ? ORDER BY created_at DESC",
        (program_handle,),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def set_config(db: sqlite3.Connection, key: str, value: str) -> None:
    db.execute(
        "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)",
        (key, value, _now_iso()),
    )


def get_config(db: sqlite3.Connection, key: str) -> str | None:
    row = db.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None
