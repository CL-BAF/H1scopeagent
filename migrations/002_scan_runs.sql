-- v002: Add scan_runs status tracking improvements
ALTER TABLE scan_runs ADD COLUMN error_message TEXT NOT NULL DEFAULT '';
ALTER TABLE scan_runs ADD COLUMN worker_id TEXT NOT NULL DEFAULT '';

INSERT OR IGNORE INTO migrations (version, description, applied_at)
VALUES (2, 'Add scan_runs status fields', datetime('now'));
