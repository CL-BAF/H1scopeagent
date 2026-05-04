# Environment Variables

## Required Credentials

| Variable | Required | Description |
|----------|----------|-------------|
| `HACKERONE_USERNAME` | Yes | Your HackerOne username/email |
| `HACKERONE_TOKEN` | Yes | HackerOne API token from https://hackerone.com/settings/api_tokens |

## Token Scopes

Your API token must have these scopes:
- `program:read` — Read program information
- `scope:read` — Read structured scopes
- `report:read` — Read existing reports
- `report:write` — Submit new reports (for auto-submit)

## Profile Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `H1_PROFILE` | `default` | Active config profile |
| `H1_RISK_LEVEL` | `verified` | Risk level (safe/verified/aggressive) |
| `H1_CONCURRENCY` | `3` | Max concurrent operations |
| `H1_DELAY` | `3` | Delay between requests (seconds) |
| `H1_TIMEOUT` | `30` | Request timeout (seconds) |
| `H1_BROWSER_HEADLESS` | `true` | Run browser headless |
| `H1_FINDING_LIMIT` | `10` | Max findings per program |
| `H1_ASSET_LIMIT` | `50` | Max assets to process |
| `H1_DAEMON_INTERVAL` | `3600` | Daemon loop interval |
| `H1_AUTO_INSTALL_TOOLS` | `true` | Auto-install missing tools |
| `H1_LOG_LEVEL` | `info` | Logging level |

## Directory Paths

| Variable | Default | Description |
|----------|---------|-------------|
| `H1_DATA_DIR` | `./data` | Data storage directory |
| `H1_DB_PATH` | `./data/h1scopeagent.db` | SQLite database path |

## .env File Example

```
HACKERONE_USERNAME=your_username
HACKERONE_TOKEN=your_api_token_here
H1_PROFILE=fast
H1_RISK_LEVEL=verified
```
