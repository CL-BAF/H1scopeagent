# H1ScopeAgent Architecture

## System Overview

H1ScopeAgent is a fully autonomous HackerOne bug bounty assistant that handles the complete pipeline from program discovery to report submission.

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI / TUI (h1scope)                    │
├─────────────────────────────────────────────────────────────┤
│  main.py: init, doctor, sync, programs, scope, policy,     │
│  plan, recon, crawl, scout, findings, report, submit,      │
│  export, backup, restore, daemon, dashboard                │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│ api/     │ scope/   │ recon/   │ browser/ │ reports/       │
│ H1 API   │ validator│ subdomain│ chromium │ generator      │
│ Programs │ parser   │ dns      │ profiles │ templates      │
│ Scopes   │ diff     │ http     │ sessions │ exporter       │
│ Reports  │ export   │ crawler  │ network  │ quality        │
│ Submit   │ normalize│ js       │ crawler  │ checker        │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│                    findings/ + db/ + logs/                  │
│  detector → scorer → dedupe → status → timeline → audit   │
├─────────────────────────────────────────────────────────────┤
│                     daemon.py + tools/                      │
│  scheduler → worker pool → scan queues → tool installer   │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Sync**: HackerOne API → SQLite (programs, scopes, policies, bounty tables)
2. **Plan**: Scope + Policy → Recon Strategy (profile-driven)
3. **Recon**: Scope assets → Discovery pipeline → Assets + Endpoints
4. **Crawl**: Live URLs → Browser/JS analysis → Parameters + Routes
5. **Detect**: Page data → Finding detectors → Scored candidates
6. **Attack**: High-confidence findings → Auto-verify → Active testing
7. **Report**: Confirmed findings → Template rendering → Markdown/HTML/PDF
8. **Submit**: Report drafts → HackerOne API → Tracked submissions
9. **Daemon**: Continuous loop through steps 1-8 on all programs

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `api/` | HackerOne GraphQL + REST client, auth, pagination |
| `scope/` | Asset validation, wildcard expansion, diffing, export |
| `recon/` | All discovery: subdomains, DNS, HTTP, JS, history, leaks |
| `browser/` | Chromium automation, sessions, crawls, evidence capture |
| `findings/` | Detection, scoring, deduplication, status management |
| `reports/` | Template-based report generation, multi-format export |
| `db/` | SQLite schema, migrations, CRUD, backup/restore |
| `logs/` | Structured JSON audit logging, scan logs |
| `tools/` | External tool detection, auto-install, execution |
| `daemon.py` | Continuous autonomous loop, scheduling, workers |
