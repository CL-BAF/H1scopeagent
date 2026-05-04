# Testing H1ScopeAgent

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-timeout

# Run all tests
pytest tests/ -v

# Run with coverage
pip install pytest-cov
pytest tests/ -v --cov=h1scopeagent --cov-report=html

# Run specific test file
pytest tests/test_config.py -v
pytest tests/test_scope.py -v

# Run tests matching pattern
pytest tests/ -v -k "scope"
```

## Test Structure

| Test File | What It Tests |
|-----------|---------------|
| `test_config.py` | Profile loading, settings validation, env var parsing |
| `test_scope_validator.py` | Asset matching, wildcards, out-of-scope, IP ranges |
| `test_scope_storage.py` | Normalized scope, wildcard expansion, classification |
| `test_api_parsing.py` | H1 API response parsing, pagination, errors |
| `test_command_guard.py` | Command execution, safety boundaries |
| `test_policy_parser.py` | Policy text summarization, category detection |
| `test_recon_modules.py` | Each recon module's output format |
| `test_browser_scout.py` | Browser scouting behavior, privacy |
| `test_finding_scoring.py` | Severity/confidence scoring, dedup |
| `test_autonomous_safety.py` | Stop conditions, limits, boundaries |
| `test_report_templates.py` | Template rendering, quality checks |
| `test_db_migrations.py` | Migration application and rollback |
| `test_cli_integration.py` | End-to-end CLI command tests |
| `test_tool_installer.py` | Tool detection and install logic |

## Writing New Tests

```python
import pytest
from h1scopeagent.recon.my_module import MyReconModule

class TestMyModule:
    def test_basic_run(self):
        module = MyReconModule({})
        results = module.run("test-program", ["example.com"])
        assert results["module"] == "my_module"
        assert len(results["findings"]) > 0

    def test_empty_targets(self):
        module = MyReconModule({})
        results = module.run("test-program", [])
        assert results["findings"] == []

    def test_config_override(self):
        module = MyReconModule({"timeout": 5})
        assert module.config["timeout"] == 5
```

## Test Patterns

- **Unit tests**: Test individual functions/classes in isolation
- **Integration tests**: Test module interaction (e.g., detector + DB)
- **CLI tests**: Use `typer.testing.CliRunner` for command testing
- **Mock tests**: Mock H1 API responses with `pytest.monkeypatch` or `unittest.mock`
- **Snapshot tests**: Compare report output against golden files

## Fixtures

Common fixtures available in `tests/conftest.py`:
- `sample_program` — Populated Program dataclass
- `sample_scope` — In-scope + out-of-scope ScopeEntry lists
- `sample_finding` — CandidateFinding dict
- `temp_db` — Temporary in-memory SQLite database
- `mock_h1_client` — Mocked HackerOneClient
