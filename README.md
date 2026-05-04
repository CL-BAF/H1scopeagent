# H1ScopeAgent

**Authorized HackerOne Bug Bounty Assistant** — Autonomous non-invasive reconnaissance and Chromium-based scouting for in-scope assets.

---

## What H1ScopeAgent Does

- Connects to the **HackerOne Hacker API** (GraphQL + REST) to fetch program data
- Retrieves **structured scopes** (in-scope and out-of-scope assets)
- Parses program **policies** into structured allowed/forbidden testing rules
- Performs **autonomous non-invasive reconnaissance** on confirmed in-scope assets
- Runs **Chromium browser scouting** via Playwright for visual reconnaissance
- Captures **screenshots** and extracts **page metadata** without storing secrets
- Detects **candidate vulnerability findings** using 17+ non-invasive detectors
- **Scores, ranks, and deduplicates** findings by confidence and severity
- Generates **HackerOne-style report drafts** for report-ready candidates
- **Logs every action** with a comprehensive audit trail

## What H1ScopeAgent Does NOT Do

- **NO autonomous exploitation** — zero active exploits without human approval
- **NO denial-of-service testing** — blocked at the command guard level
- **NO brute force or credential stuffing** — permanently blocked
- **NO authentication bypass attempts** — never tries to log in
- **NO form submission** — forms are recorded but never submitted
- **NO destructive browser actions** — dangerous buttons are never clicked
- **NO data exfiltration** — only passive observation
- **NO out-of-scope targeting** — all targets validated before access
- **NO secret storage** — API tokens, passwords, and secrets are redacted
- **NO phishing, malware, or social engineering** — blocked by design
- **NO lateral movement or persistence** — never attempted

## Ethical Usage Warning

> **This tool must only be used on programs where you are an authorized participant.**
> H1ScopeAgent operates under the HackerOne program policies you have agreed to.
> Using this tool on unauthorized targets is illegal and against HackerOne Terms of Service.
> The tool enforces safety boundaries, but ultimate responsibility rests with the user.

---

## System Requirements

- **Windows 10/11** with WSL 2 enabled
- **WSL Linux distribution** (Ubuntu 22.04+, Debian 12+, or Kali)
- **Python 3.11+**
- **No Docker required**
- **No container setup needed**

## WSL Setup Commands

```bash
# Update system packages
sudo apt update
sudo apt upgrade -y

# Install Python and essential tools
sudo apt install -y python3 python3-venv python3-pip curl git sqlite3 dnsutils whois openssl jq

# Verify Python version
python3 --version  # Should be 3.11+
```

## Installation

### 1. Clone or copy the project
```bash
# Project should be at ~/hackerone or similar WSL-accessible path
cd ~/hackerone
```

### 2. Create Python virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Install Playwright Chromium
```bash
python -m playwright install chromium

# If extra system dependencies are needed:
python -m playwright install-deps chromium
```

### 5. Configure API credentials
```bash
cp .env.example .env
```

Edit `.env` and add your HackerOne API credentials:
```
HACKERONE_USERNAME=your_hackerone_username
HACKERONE_TOKEN=your_api_token_here
```

You can obtain your API token from: https://hackerone.com/settings/api_tokens

Required token scopes:
- `report:read` — Read report data
- `program:read` — Read program information
- `scope:read` — Read structured scopes

### 6. Verify installation
```bash
h1scope doctor
```

---

## Optional External Tools

Install any optional tools you want available (the CLI works without them):

```bash
# Network scanning (requires approval to use)
sudo apt install -y nmap

# Directory brute forcing (requires approval to use)
sudo apt install -y gobuster
```

The `h1scope tools` command shows which tools are detected.

---

## Quick Start Workflow

```bash
# 1. Check everything is ready
h1scope doctor

# 2. See available tools
h1scope tools

# 3. Verify browser scouting works
h1scope browser-check

# 4. Sync HackerOne program data
h1scope sync

# 5. List available programs
h1scope programs

# 6. View scope for a program
h1scope scope example-program

# 7. View program policy
h1scope policy example-program

# 8. Generate a recon plan
h1scope plan example-program

# 9. Run autonomous mode (targets 5 candidate findings)
h1scope auto example-program --finding-limit 5

# 10. Review findings
h1scope findings example-program

# 11. Generate reports
h1scope report example-program
```

---

## CLI Commands Reference

### `h1scope doctor`
Check system readiness. Verifies Python, packages, environment variables, API auth, database, Playwright, Chromium, and optional tools.

### `h1scope tools`
List external tools with their availability, version, and autonomy classification.

### `h1scope browser-check`
Test Chromium browser scouting. Launches a headless browser, navigates to about:blank, reports success/failure.

### `h1scope sync`
Download program data from HackerOne and store locally. Handles pagination, rate limits, and temporary API failures.

### `h1scope programs`
Show all synced programs with handle, name, state, bounty status, and last sync time.

### `h1scope scope <handle>`
Display in-scope and out-of-scope assets for a program with bounty eligibility and instructions.

### `h1scope policy <handle>`
Show summarized policy: allowed testing, forbidden testing, rate limits, and disclosure rules.

### `h1scope plan <handle>`
Generate a safe recon plan with categorized steps (safe, approval-required, forbidden), rate limit notes, and risk estimation.

### `h1scope suggest <handle> <asset>`
Suggest safe commands and browser scouting steps for a specific in-scope asset. Refuses ambiguous or out-of-scope targets.

### `h1scope scout <handle> <url>`
Browser-scout a single URL using Chromium. Validates scope, captures screenshots, extracts metadata, and runs finding detectors.

Options: `--headed`, `--slowmo`, `--no-screenshots`, `--json`

### `h1scope scout-batch <handle>`
Batch-scout multiple in-scope web assets with configurable limits and delays.

Options: `--limit 5`, `--delay 3`, `--headed`, `--no-screenshots`, `--json`

### `h1scope auto <handle>`
**Autonomous non-invasive mode.** Scouts in-scope assets until the finding limit is reached or safe targets are exhausted.

Options:
- `--finding-limit 5` (default, overrideable)
- `--asset-limit 20` (max assets to process)
- `--delay 3` (seconds between requests)
- `--headless`/`--headed` (browser visibility)
- `--passive-only` (skip browser scouting)
- `--browser-only` (skip passive recon)
- `--no-browser` (no Chromium at all)
- `--json` (JSON output)
- `--stop-on-manual-review` (halt on any ambiguity)

### `h1scope findings <handle>`
Display candidate findings sorted by severity and confidence.

### `h1scope report <handle>`
Generate HackerOne-style markdown report drafts for all report-ready findings.

### `h1scope run <handle> "<command>"`
Execute a terminal command after safety checks. Blocks dangerous commands, requires approval for active scanning, and validates targets against scope.

---

## Safety Model

### Blocked Commands (never executed)
- `hydra`, `medusa`, `patator` — brute force tools
- `sqlmap --dump`, `--os-shell`, `--file-read`, `--file-write`
- `masscan`, `hping3`, `slowloris` — DoS/scanning abuse
- `metasploit`, `msfconsole` — exploitation frameworks
- `nc -e`, `bash -i`, `/dev/tcp` — reverse shells
- `rm -rf /` — destructive commands
- Any command targeting out-of-scope assets
- Any command where the target is ambiguous or unverified

### Approval Required (user must confirm)
- `nmap -sV`, `nmap -A`, `nmap --script`
- `nikto`, `gobuster`, `dirsearch`, `ffuf`, `wfuzz`, `nuclei`
- Any `curl -X POST/PUT/PATCH/DELETE`
- Any command with `--data` or `--data-binary`
- Any command targeting authenticated resources

### Allowed Autonomous (scope-validated)
- `dig`, `nslookup`, `host`, `whois`
- `curl -I`, `curl --head`
- `curl .../robots.txt`, `.../security.txt`, `.../sitemap.xml`
- `openssl s_client -connect`
- Passive browser scouting (no interaction, no forms)

---

## Autonomy Model

| Action | Autonomous | Needs Approval | Forbidden |
|--------|-----------|----------------|-----------|
| Fetch program/scope data | Yes | - | - |
| DNS lookups | Yes | - | - |
| WHOIS queries | Yes | - | - |
| HTTP header checks | Yes | - | - |
| TLS cert inspection | Yes | - | - |
| robots.txt/security.txt fetch | Yes | - | - |
| Chromium page load + screenshot | Yes | - | - |
| Metadata extraction | Yes | - | - |
| Form discovery | Yes | - | - |
| Link collection | Yes | - | - |
| Security header analysis | Yes | - | - |
| Finding detection + scoring | Yes | - | - |
| nmap -sV scan | - | Yes | - |
| Directory brute force | - | Yes | - |
| POST/PUT/DELETE requests | - | Yes | - |
| Form submission | - | Yes | - |
| SQL injection | - | - | Yes |
| XSS exploitation | - | - | Yes |
| Brute force | - | - | Yes |
| DoS testing | - | - | Yes |
| Reverse shells | - | - | Yes |
| Data exfiltration | - | - | Yes |

---

## Finding Types Detected

| # | Finding | Severity | Auto-Verify |
|---|---------|----------|-------------|
| 1 | Missing HSTS | Low | Yes |
| 2 | Missing CSP | Medium | Yes |
| 3 | Weak CSP (unsafe-inline) | Medium | Yes |
| 4 | Missing X-Frame-Options | Medium | Yes |
| 5 | Missing X-Content-Type-Options | Low | Yes |
| 6 | Insecure Cookies | Medium | Yes |
| 7 | Exposed Source Maps | Low | Yes |
| 8 | Console Errors with Stacks | Low | Yes |
| 9 | Exposed Swagger/OpenAPI | Low | Yes |
| 10 | Public GraphQL Endpoint | Info | No |
| 11 | Public Admin Panels | Info | Yes |
| 12 | Open Redirect Parameters | Low | No |
| 13 | CORS Misconfiguration | Medium | No |
| 14 | Secret Leakage | High | No |
| 15 | Outdated Technology | Medium | Yes |
| 16 | Exposed Robots.txt Paths | Info | Yes |

---

## Storage Locations

All data is stored under `./data/` in the project directory:

```
data/
├── h1scopeagent.db              # SQLite database
├── screenshots/
│   └── <program_handle>/
│       └── 20240504_143022_example_com.png
├── scouts/
│   └── <program_handle>/
│       └── 20240504_143022_example_com.json
├── reports/
│   └── <program_handle>/
│       └── FND-abc12345.md
└── logs/
    └── audit.log                # JSON-line audit trail
```

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run all tests
pytest tests/ -v

# Run specific test files
pytest tests/test_scope_validator.py -v
pytest tests/test_command_guard.py -v
pytest tests/test_finding_scoring.py -v
```

---

## Troubleshooting

### "No token configured" error
- Ensure `.env` file exists with correct credentials
- Check token has required scopes (`program:read`, `scope:read`)
- Run `h1scope doctor` to validate auth

### Playwright/Chromium not found
```bash
python -m playwright install chromium
python -m playwright install-deps chromium
h1scope browser-check
```

### Database errors
```bash
# Reset database if corrupted
rm -f data/h1scopeagent.db
h1scope sync
```

### "No programs synced" message
- Run `h1scope sync` first to download program data
- Verify your API token has the correct scopes
- Check your internet connection

### WSL-specific issues
- Ensure project is on the WSL filesystem (not `/mnt/c/...`)
- `sudo apt install -y python3-venv` if venv creation fails
- Browser scouting works best with GUI-enabled WSL (WSLg)

## Project Structure

```
h1scopeagent/
├── __init__.py          # Package init, version
├── main.py              # CLI entry point (all 15 commands)
├── config.py            # Settings, safety constants, patterns
├── api/
│   ├── __init__.py
│   └── hackerone.py     # GraphQL + REST API client
├── db/
│   ├── __init__.py
│   ├── database.py      # SQLite schema, CRUD operations
│   └── models.py        # Dataclass models
├── scope/
│   ├── __init__.py
│   ├── validator.py     # Scope matching engine
│   └── parser.py        # Asset normalization
├── policy/
│   ├── __init__.py
│   └── summarizer.py    # Policy text → structured rules
├── recon/
│   ├── __init__.py
│   ├── planner.py       # Recon plan generator
│   ├── passive.py       # Passive recon operations
│   ├── command_guard.py # Command safety blocker
│   ├── runner.py        # Safe command execution
│   └── tools.py         # External tool detection
├── browser/
│   ├── __init__.py
│   ├── chromium.py      # ChromiumScout (Playwright async)
│   ├── scout.py         # Scout orchestration
│   ├── screenshot.py    # Screenshot path management
│   └── metadata.py      # Page metadata extraction
├── findings/
│   ├── __init__.py
│   ├── detector.py      # 17+ non-invasive detectors
│   ├── scorer.py        # Confidence & severity scoring
│   ├── dedupe.py        # Deduplication logic
│   └── models.py        # Finding dataclasses
├── reports/
│   ├── __init__.py
│   └── generator.py     # HackerOne-style report drafts
├── logs/
│   ├── __init__.py
│   └── audit.py         # Structured audit logger
tests/
├── test_scope_validator.py    # 20 tests — scope matching
├── test_command_guard.py      # 23 tests — command safety
├── test_policy_parser.py      # 11 tests — policy parsing
├── test_browser_scout.py      # 9 tests — browser safety
├── test_finding_scoring.py    # 18 tests — scoring & dedup
└── test_autonomous_safety.py  # 16 tests — autonomy safety
```

## License

MIT License — See LICENSE file for details.
