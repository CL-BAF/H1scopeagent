# Command-Line Reference

## Core Commands

### `h1scope init`
Initialize H1ScopeAgent. Creates `.env` template, profile files, and database.

### `h1scope doctor`
System readiness check. Validates Python, packages, credentials, API auth, database, Playwright, Chromium, and external tools. Shows install guidance for missing tools.

### `h1scope sync`
Download program data from HackerOne. Handles pagination, rate limits, and delta updates.
```
--program <handle>     Sync a single program only
--force                Full re-sync even if unchanged
```

### `h1scope programs`
List synced programs with details.
```
--search <term>        Filter by name or handle
--bookmarked           Show only bookmarked programs
--private              Include private programs
--json                 Output as JSON
```

### `h1scope scope <handle>`
Display in-scope and out-of-scope assets.
```
export                  Export scope to file
  --format json|csv     Output format
diff                    Show scope changes since last sync
```

### `h1scope policy <handle>`
Show summarized program policy: allowed testing, forbidden testing, rate limits, disclosure rules.

### `h1scope plan <handle>`
Generate a recon strategy plan.
```
--profile <name>       Use specific profile (default, fast, deep, passive-only)
```

### `h1scope recon <handle>`
Run all recon modules against a program.
```
--profile <name>       Profile to use
--modules <list>       Comma-separated module list (subdomains,dns,http,js,crawl)
--target <asset>       Target a specific asset only
--resume               Resume from last checkpoint
```

### `h1scope crawl <handle>`
URL crawling and JavaScript analysis.
```
--url <url>            Start from a specific URL
--depth <n>            Crawl depth (default: 3)
--js-only              Only collect JavaScript files
```

### `h1scope scout <handle> [URL]`
Browser-based scouting of a URL or all in-scope web assets.
```
--headed               Visible browser window
--slowmo <ms>          Slow motion for debugging
--no-screenshots       Skip screenshot capture
--full-page            Full-page screenshots
--json                 JSON output
```

### `h1scope findings <handle>`
Show detected findings.
```
--search <term>        Search findings
--severity <level>     Filter by severity
--confidence <level>   Filter by confidence
--status <status>      Filter by status
--tag <tag>            Filter by tag
--json                 JSON output
```

### `h1scope report <handle>`
Generate report drafts for findings.
```
--template <name>      Use specific template (xss, idor, ssrf, csrf, sqli, default)
--format md|html|pdf   Output format (default: md)
--brief                Short report mode
--detailed             Detailed report mode
--submit               Auto-submit after generation
--risk aggressive       Required for auto-submit
--dry-run              Preview without submitting
```

### `h1scope submit <handle>`
Submit report drafts to HackerOne.
```
--risk aggressive      Required for auto-submit
--dry-run              Preview without submitting
--json                 JSON output
```

### `h1scope export <handle>`
Export data.
```
--type scope|findings|reports|assets    What to export
--format json|csv|md                    Output format
--output <path>                         Output file path
```

### `h1scope backup`
Create a database backup.
```
--output <path>        Custom backup path
```

### `h1scope restore <file>`
Restore from a database backup.

### `h1scope daemon`
Run the continuous autonomous bot loop.
```
--risk <level>         Risk level: safe, verified, aggressive
--profile <name>       Recon profile
--interval <seconds>   Loop interval (default: 3600)
--cron "<expr>"        Cron expression scheduling
--max-iters <n>        Max iterations (0=unlimited)
--workers <n>          Concurrent workers
```

### `h1scope dashboard`
Launch the Rich TUI dashboard showing programs, scope, scan runs, findings, reports, and logs.
```
--refresh <seconds>    Dashboard refresh rate
```
