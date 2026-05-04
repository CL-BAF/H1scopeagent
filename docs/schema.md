# H1ScopeAgent Database Schema

## Tables

### `programs`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| handle | TEXT UNIQUE | HackerOne program handle |
| name | TEXT | Program display name |
| state | TEXT | open/pausable/closed |
| offers_bounties | INTEGER | Boolean |
| currency | TEXT | Bounty currency |
| confidential | INTEGER | Private program flag |
| bookmarked | INTEGER | User bookmarked flag |
| last_synced_at | TEXT ISO | Last sync timestamp |

### `scopes`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| program_handle | TEXT FK | References programs.handle |
| asset_identifier | TEXT | Raw H1 asset string |
| asset_type | TEXT | H1 type classification |
| eligible_for_bounty | INTEGER | Boolean |
| eligible_for_submission | INTEGER | Boolean |
| max_severity | TEXT | Max severity for submissions |
| instruction | TEXT | H1 instructions |
| in_scope | INTEGER | Boolean (1=in, 0=out) |
| notes | TEXT | User notes |
| tags | TEXT | Comma-separated tags |
| created_at | TEXT ISO | First seen |
| updated_at | TEXT ISO | Last updated |

### `scopes_normalized`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| program_handle | TEXT FK | References programs.handle |
| normalized_asset | TEXT | Cleaned asset string |
| root_domain | TEXT | Extracted TLD+1 |
| asset_category | TEXT | domain/wildcard/url/android/ios/api/cidr/github_org/github_repo/other |
| priority_score | REAL | Computed priority |
| created_at | TEXT ISO | |

### `scope_history`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment ID |
| program_handle | TEXT FK | |
| asset_identifier | TEXT | Asset that changed |
| change_type | TEXT | added/removed/modified |
| old_value | TEXT | Previous value |
| new_value | TEXT | New value |
| detected_at | TEXT ISO | |

### `policies`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT UNIQUE FK | |
| raw_policy_text | TEXT | Full policy |
| summary | TEXT | Generated summary |
| allowed_testing | TEXT | Extracted allowed items |
| forbidden_testing | TEXT | Extracted forbidden items |
| rate_limits | TEXT | Rate limit info |
| disclosure_rules | TEXT | Disclosure rules |
| updated_at | TEXT ISO | |

### `bounty_tables`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| severity | TEXT | critical/high/medium/low |
| min_bounty | REAL | Minimum payout |
| max_bounty | REAL | Maximum payout |
| avg_bounty | REAL | Average payout |
| currency | TEXT | |
| updated_at | TEXT ISO | |

### `recon_plans`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| plan_markdown | TEXT | Generated plan |
| profile_used | TEXT | Config profile name |
| created_at | TEXT ISO | |

### `scan_runs`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| profile_used | TEXT | |
| modules_run | TEXT | JSON array of modules |
| targets_total | INTEGER | |
| targets_processed | INTEGER | |
| findings_found | INTEGER | |
| status | TEXT | running/completed/failed/cancelled |
| started_at | TEXT ISO | |
| finished_at | TEXT ISO | |
| checkpoint_data | TEXT JSON | Resumable state |

### `endpoints`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| url | TEXT | Full URL |
| method | TEXT | GET/POST/etc |
| parameters | TEXT JSON | Discovered params |
| source | TEXT | crawler/js/api_docs/manual |
| status_code | INTEGER | Last observed status |
| content_type | TEXT | |
| last_seen | TEXT ISO | |

### `command_logs`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| command | TEXT | Full command |
| target | TEXT | Extracted target |
| exit_code | INTEGER | |
| output | TEXT | Truncated output |
| scan_run_id | INTEGER FK | References scan_runs.id |
| created_at | TEXT ISO | |

### `browser_scouts`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| original_url | TEXT | |
| final_url | TEXT | After redirects |
| in_scope | INTEGER | Boolean |
| status_code | INTEGER | |
| title | TEXT | Page title |
| screenshot_path | TEXT | |
| full_page_screenshot | TEXT | |
| metadata_json | TEXT JSON | Full metadata |
| console_errors_json | TEXT JSON | |
| forms_json | TEXT JSON | |
| links_json | TEXT JSON | |
| network_log_json | TEXT JSON | HAR-style |
| dom_snapshot_path | TEXT | |
| created_at | TEXT ISO | |

### `browser_profiles`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| name | TEXT | Profile name |
| user_data_dir | TEXT | Chromium data dir path |
| cookies_json | TEXT JSON | Saved cookies |
| local_storage_json | TEXT JSON | |
| created_at | TEXT ISO | |
| updated_at | TEXT ISO | |

### `candidate_findings`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| candidate_id | TEXT UNIQUE | FND-XXXXXXXX |
| title | TEXT | Finding title |
| affected_asset | TEXT | Affected URL/domain |
| candidate_type | TEXT | Detector type |
| status | TEXT | candidate/needs-review/confirmed/duplicate-risk/reported/resolved/closed |
| confidence | TEXT | low/medium/high |
| estimated_severity | TEXT | info/low/medium/high/critical |
| cvss_score | REAL | CVSS 3.1 score |
| cvss_vector | TEXT | CVSS vector string |
| evidence_json | TEXT JSON | |
| reproduction_steps | TEXT JSON | |
| impact | TEXT | Impact assessment |
| tags | TEXT | Comma-separated |
| raw_request | TEXT | Raw HTTP request |
| raw_response | TEXT | Raw HTTP response |
| screenshot_path | TEXT | |
| metadata_path | TEXT | |
| report_ready | INTEGER | Boolean |
| h1_report_id | TEXT | HackerOne report ID (after submission) |
| h1_report_state | TEXT | HackerOne report state |
| scan_run_id | INTEGER FK | |
| created_at | TEXT ISO | |
| updated_at | TEXT ISO | |

### `finding_timeline`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| finding_id | TEXT FK | References candidate_findings.candidate_id |
| event | TEXT | created/verified/attacked/reported/resolved |
| details | TEXT | |
| timestamp | TEXT ISO | |

### `report_drafts`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| program_handle | TEXT FK | |
| finding_id | TEXT FK | |
| title | TEXT | |
| affected_asset | TEXT | |
| severity | TEXT | |
| markdown_body | TEXT | |
| html_body | TEXT | |
| pdf_path | TEXT | |
| template_used | TEXT | |
| submitted | INTEGER | Boolean |
| h1_report_id | TEXT | H1 report ID if submitted |
| created_at | TEXT ISO | |
| updated_at | TEXT ISO | |

### `evidence`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | |
| finding_id | TEXT FK | |
| evidence_type | TEXT | screenshot/http_log/dom_snapshot/file |
| file_path | TEXT | |
| content_hash | TEXT SHA256 | |
| metadata_json | TEXT JSON | |
| created_at | TEXT ISO | |

### `config`
| Column | Type | Description |
|--------|------|-------------|
| key | TEXT PK | Config key |
| value | TEXT | Config value |
| updated_at | TEXT ISO | |

### `migrations`
| Column | Type | Description |
|--------|------|-------------|
| version | INTEGER PK | Migration version number |
| description | TEXT | |
| applied_at | TEXT ISO | |

## Indexes

- `idx_scopes_program` ON scopes(program_handle)
- `idx_scopes_in_scope` ON scopes(program_handle, in_scope)
- `idx_scopes_normalized_program` ON scopes_normalized(program_handle)
- `idx_findings_program` ON candidate_findings(program_handle)
- `idx_findings_status` ON candidate_findings(program_handle, status)
- `idx_findings_confidence` ON candidate_findings(program_handle, confidence)
- `idx_findings_severity` ON candidate_findings(estimated_severity)
- `idx_endpoints_program` ON endpoints(program_handle)
- `idx_scan_runs_program` ON scan_runs(program_handle)
- `idx_evidence_finding` ON evidence(finding_id)
- `idx_timeline_finding` ON finding_timeline(finding_id)
- `idx_browser_scouts_program` ON browser_scouts(program_handle)
- `idx_reports_program` ON report_drafts(program_handle)
- `idx_command_logs_program` ON command_logs(program_handle)
