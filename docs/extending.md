# Extending H1ScopeAgent

## Adding a New Recon Module

1. Create a new file in `h1scopeagent/recon/`, e.g. `my_module.py`
2. Implement a class with `run(program_handle: str, targets: list[str], config: dict) -> dict`:

```python
class MyReconModule:
    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def run(self, program_handle: str, targets: list[str]) -> dict:
        results = {"module": "my_module", "findings": []}
        for target in targets:
            # Your recon logic here
            results["findings"].append({
                "target": target,
                "data": "...",
            })
        return results
```

3. Register the module in `recon/__init__.py`:

```python
from h1scopeagent.recon.my_module import MyReconModule

RECON_MODULES = {
    "subdomains": SubdomainDiscovery,
    "dns": DNSRecordCollector,
    "my_module": MyReconModule,  # Add here
}
```

## Adding a Finding Detector

1. In `findings/detector.py`, add a new method to `FindingDetector`:

```python
def check_my_vuln(self, url: str, headers: dict, scout: dict) -> dict | None:
    if some_condition:
        return self._make_finding(
            "check_my_vuln",
            "Candidate: My Vulnerability",
            domain,
            confidence="medium",
            estimated_severity="high",
            evidence={"detail": "..."},
            recommended_next_step="...",
        )
    return None
```

2. Register it in `detect_all()` method's `detectors` list:

```python
("check_my_vuln", self.check_my_vuln(url, headers, scout_result)),
```

## Adding a Report Template

1. Create `reports/templates/my_template.md`:

```markdown
# {{title}}

## Summary
{{summary}}

## Affected Asset
- **Asset**: {{affected_asset}}
- **Severity**: {{severity}}
- **Confidence**: {{confidence}}

## Description
{{description}}

## Impact
{{impact}}

## Evidence
{{evidence}}

## Remediation
{{remediation}}
```

2. Register in `reports/generator.py` template registry:

```python
TEMPLATE_REGISTRY = {
    "xss": "templates/xss.md",
    "idor": "templates/idor.md",
    "my_template": "templates/my_template.md",
}
```

## Adding a CLI Command

1. In `main.py`, add a new command function:

```python
@app.command()
def my_command(
    program_handle: str = typer.Argument(..., help="Program handle"),
):
    """Description of my command."""
    ...
```

## Adding a Daemon Task

1. In `daemon.py`, add a new method to `DaemonController`:

```python
async def _my_task(self, handle: str):
    ...
```

2. Call it from `_run_iteration()`.

## Database Migrations

1. Create `migrations/NNN_description.sql`
2. Add `INSERT INTO migrations (version, description) VALUES (NNN, 'description')`
3. Run `h1scope init` to apply

## Tool Integration

1. Add tool definition in `tools/installer.py`:

```python
TOOL_DEFINITIONS["my_tool"] = {
    "check_cmd": "my_tool --version",
    "install": {
        "apt": "my-tool",
        "pip": "my-tool-py",
        "go": "github.com/author/my-tool@latest",
    },
    "install_priority": ["go", "apt", "pip"],
}
```
