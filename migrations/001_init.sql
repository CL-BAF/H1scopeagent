-- v001: Initial schema
CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    applied_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    handle TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT '',
    offers_bounties INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT '',
    confidential INTEGER NOT NULL DEFAULT 0,
    bookmarked INTEGER NOT NULL DEFAULT 0,
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
    notes TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scopes_program ON scopes(program_handle);
CREATE INDEX IF NOT EXISTS idx_scopes_in_scope ON scopes(program_handle, in_scope);

CREATE TABLE IF NOT EXISTS scopes_normalized (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER REFERENCES scopes(id),
    program_handle TEXT NOT NULL,
    normalized_asset TEXT NOT NULL,
    root_domain TEXT NOT NULL DEFAULT '',
    asset_category TEXT NOT NULL DEFAULT 'other',
    priority_score REAL NOT NULL DEFAULT 0.0,
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scopes_norm_program ON scopes_normalized(program_handle);
CREATE INDEX IF NOT EXISTS idx_scopes_norm_root ON scopes_normalized(root_domain);

CREATE TABLE IF NOT EXISTS scope_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    asset_identifier TEXT NOT NULL,
    change_type TEXT NOT NULL DEFAULT '',
    old_value TEXT NOT NULL DEFAULT '',
    new_value TEXT NOT NULL DEFAULT '',
    detected_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scope_history_program ON scope_history(program_handle);

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

CREATE TABLE IF NOT EXISTS bounty_tables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    min_bounty REAL NOT NULL DEFAULT 0.0,
    max_bounty REAL NOT NULL DEFAULT 0.0,
    avg_bounty REAL NOT NULL DEFAULT 0.0,
    currency TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_bounty_program ON bounty_tables(program_handle);

CREATE TABLE IF NOT EXISTS recon_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    plan_markdown TEXT NOT NULL DEFAULT '',
    profile_used TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_recon_plans_program ON recon_plans(program_handle);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    profile_used TEXT NOT NULL DEFAULT '',
    modules_run TEXT NOT NULL DEFAULT '[]',
    targets_total INTEGER NOT NULL DEFAULT 0,
    targets_processed INTEGER NOT NULL DEFAULT 0,
    findings_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    checkpoint_data TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_program ON scan_runs(program_handle);
CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    parameters TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'unknown',
    status_code INTEGER NOT NULL DEFAULT 0,
    content_type TEXT NOT NULL DEFAULT '',
    last_seen TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_endpoints_program ON endpoints(program_handle);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

CREATE TABLE IF NOT EXISTS command_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    exit_code INTEGER NOT NULL DEFAULT -1,
    output TEXT NOT NULL DEFAULT '',
    scan_run_id INTEGER REFERENCES scan_runs(id),
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_command_logs_program ON command_logs(program_handle);

CREATE TABLE IF NOT EXISTS browser_scouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    original_url TEXT NOT NULL DEFAULT '',
    final_url TEXT NOT NULL DEFAULT '',
    in_scope INTEGER NOT NULL DEFAULT 1,
    status_code INTEGER NOT NULL DEFAULT 0,
    title TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    full_page_screenshot TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    console_errors_json TEXT NOT NULL DEFAULT '[]',
    forms_json TEXT NOT NULL DEFAULT '[]',
    links_json TEXT NOT NULL DEFAULT '[]',
    network_log_json TEXT NOT NULL DEFAULT '{}',
    dom_snapshot_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_browser_scouts_program ON browser_scouts(program_handle);

CREATE TABLE IF NOT EXISTS browser_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    user_data_dir TEXT NOT NULL DEFAULT '',
    cookies_json TEXT NOT NULL DEFAULT '{}',
    local_storage_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_browser_profiles_program ON browser_profiles(program_handle);

CREATE TABLE IF NOT EXISTS candidate_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    candidate_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    candidate_type TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'candidate',
    confidence TEXT NOT NULL DEFAULT 'low',
    estimated_severity TEXT NOT NULL DEFAULT 'info',
    cvss_score REAL NOT NULL DEFAULT 0.0,
    cvss_vector TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    reproduction_steps TEXT NOT NULL DEFAULT '[]',
    impact TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '',
    raw_request TEXT NOT NULL DEFAULT '',
    raw_response TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    metadata_path TEXT NOT NULL DEFAULT '',
    report_ready INTEGER NOT NULL DEFAULT 0,
    h1_report_id TEXT NOT NULL DEFAULT '',
    h1_report_state TEXT NOT NULL DEFAULT '',
    scan_run_id INTEGER REFERENCES scan_runs(id),
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_program ON candidate_findings(program_handle);
CREATE INDEX IF NOT EXISTS idx_findings_status ON candidate_findings(program_handle, status);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON candidate_findings(estimated_severity);

CREATE TABLE IF NOT EXISTS finding_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    event TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_timeline_finding ON finding_timeline(finding_id);

CREATE TABLE IF NOT EXISTS report_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_handle TEXT NOT NULL DEFAULT '',
    finding_id TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    affected_asset TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    markdown_body TEXT NOT NULL DEFAULT '',
    html_body TEXT NOT NULL DEFAULT '',
    pdf_path TEXT NOT NULL DEFAULT '',
    template_used TEXT NOT NULL DEFAULT '',
    submitted INTEGER NOT NULL DEFAULT 0,
    h1_report_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_reports_program ON report_drafts(program_handle);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO migrations (version, description, applied_at)
VALUES (1, 'Initial schema with all tables', datetime('now'));
