"""H1ScopeAgent CLI — Fully Automated HackerOne Bug Bounty Bot.

Commands: init, doctor, tools, browser-check, sync, programs, scope,
policy, plan, recon, crawl, scout, scout-batch, auto, findings, report,
submit, export, backup, restore, daemon, dashboard.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown as RichMarkdown
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from h1scopeagent.config import (
    get_settings, load_profile, list_profiles,
    DATA_DIR, SCREENSHOTS_DIR, METADATA_DIR, REPORTS_DIR, LOGS_DIR, DB_PATH,
    DEFAULT_FINDING_LIMIT, DEFAULT_ASSET_LIMIT, DEFAULT_DELAY,
    RISK_LEVELS, HACKERONE_SUBMIT_URL,
)
from h1scopeagent.db.database import (
    get_db, init_db, upsert_program, get_programs, get_program, search_programs,
    get_bookmarked_programs, upsert_scopes, get_scopes, get_all_scope_entries,
    get_in_scope_web_assets, upsert_policy, get_policy, save_recon_plan,
    get_latest_recon_plan, create_scan_run, update_scan_run, get_scan_runs,
    save_command_log, get_command_logs, save_browser_scout, get_browser_scouts,
    save_candidate_finding, get_candidate_findings, count_candidate_findings,
    save_report_draft, get_report_drafts, add_timeline_event, get_finding_timeline,
    save_evidence, set_config, get_config, upsert_bounty_tables, get_bounty_tables,
    upsert_normalized_scopes, get_normalized_scopes, log_scope_change, get_scope_history,
    upsert_endpoint, get_endpoints,
)
from h1scopeagent.api.hackerone import HackerOneClient, NoTokenError, AuthError, APIError
from h1scopeagent.recon.tools import scan_tools
from h1scopeagent.logs.audit import AuditLogger


app = typer.Typer(
    name="h1scope",
    help="H1ScopeAgent — Fully Automated HackerOne Bug Bounty Bot",
    add_completion=False,
)
console = Console()
audit = AuditLogger()


def _load_program_context(handle: str):
    with get_db() as db:
        program = get_program(db, handle)
        if not program:
            console.print(f"[red]Program '{handle}' not found in local database.[/red]")
            console.print("[yellow]Run:[/yellow] h1scope sync")
            raise typer.Exit(code=1)
        in_scope, out_scope = get_scopes(db, handle)
        policy = get_policy(db, handle)
    return program, in_scope, out_scope, policy


def _print_banner():
    console.print(Panel.fit(
        "[bold blue]H1ScopeAgent[/bold blue] — Fully Automated Bug Bounty Bot\n"
        "[dim]Scope-aware recon | Auto-attack | Auto-submit | All within H1 scope[/dim]",
        border_style="blue",
    ))


def _print_findings_summary(findings: list[dict]):
    if not findings:
        console.print("\n[yellow]No findings collected.[/yellow]")
        return
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_finds = sorted(findings, key=lambda f: severity_order.get(f.get("estimated_severity", "info"), 99))
    for f in sorted_finds[:10]:
        sev = f.get("estimated_severity", "info")
        color = "red" if sev in ("critical", "high") else "yellow" if sev == "medium" else "green"
        console.print(f"  [{color}]>[/{color}] {f.get('title', '')[:70]}")


# ===========================================================================
# 1. init
# ===========================================================================
@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
):
    """Initialize H1ScopeAgent: create .env, profiles, database."""
    _print_banner()

    env_path = Path(".env")
    if env_path.exists() and not force:
        console.print("[yellow].env already exists. Use --force to overwrite.[/yellow]")
    else:
        env_path.write_text(
            "HACKERONE_USERNAME=your_hackerone_username\n"
            "HACKERONE_TOKEN=your_api_token_here\n"
            "H1_PROFILE=default\n"
            "H1_RISK_LEVEL=verified\n",
            encoding="utf-8",
        )
        console.print("[green]Created .env template[/green]")

    profiles_dir = Path("profiles")
    from h1scopeagent.config import PROFILES_DIR
    if not PROFILES_DIR.exists() or not list(PROFILES_DIR.glob("*.toml")):
        console.print("[yellow]No profile files found. Built-in profiles (default, fast, deep, passive-only) are available.[/yellow]")

    applied = init_db()
    console.print(f"[green]Database initialized ({applied} migrations applied)[/green]")
    console.print(f"  Path: {DB_PATH}")
    console.print("\n[green]H1ScopeAgent is ready.[/green]")
    console.print("  1. Edit .env with your HackerOne credentials")
    console.print("  2. Run: h1scope sync")
    console.print("  3. Run: h1scope auto <program_handle>")


# ===========================================================================
# 2. doctor
# ===========================================================================
@app.command()
def doctor():
    """Check system readiness for H1ScopeAgent."""
    _print_banner()
    console.print("[bold]System Doctor Report[/bold]\n")

    checks: list[tuple[str, bool, str]] = []
    settings = get_settings()

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("Python Version", sys.version_info >= (3, 11), py_ver))

    pkgs = {"httpx": "httpx", "typer": "typer", "rich": "rich",
            "pydantic": "pydantic", "playwright": "playwright",
            "bs4": "beautifulsoup4", "dotenv": "python-dotenv"}
    for mod, pkg in pkgs.items():
        try:
            __import__(mod)
            checks.append((f"Package: {pkg}", True, "installed"))
        except ImportError:
            checks.append((f"Package: {pkg}", False, "MISSING"))

    has_user = bool(settings.hackerone_username)
    has_token = bool(settings.hackerone_token)
    checks.append(("HACKERONE_USERNAME", has_user, "set" if has_user else "MISSING"))
    checks.append(("HACKERONE_TOKEN", has_token, "set" if has_token else "MISSING"))
    checks.append((".env file", Path(".env").exists(), "found" if Path(".env").exists() else "missing"))

    if has_user and has_token:
        try:
            with HackerOneClient() as client:
                ok = client.test_auth()
                checks.append(("HackerOne API Auth", ok, "authenticated" if ok else "FAILED"))
        except Exception as e:
            checks.append(("HackerOne API Auth", False, str(e)[:80]))
    else:
        checks.append(("HackerOne API Auth", False, "credentials not set"))

    try:
        init_db()
        with get_db() as db:
            db.execute("SELECT 1")
        checks.append(("Database", True, str(DB_PATH)))
    except Exception as e:
        checks.append(("Database", False, str(e)[:80]))

    try:
        from playwright.sync_api import sync_playwright
        checks.append(("Playwright", True, "installed"))
    except ImportError:
        checks.append(("Playwright", False, "not installed"))

    try:
        r = subprocess.run([sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
                           capture_output=True, text=True, timeout=15)
        checks.append(("Chromium Browser", True, "available"))
    except Exception:
        checks.append(("Chromium Browser", False, "run: playwright install chromium"))

    for tool in ["curl", "dig", "whois", "openssl", "nmap", "nuclei", "gobuster", "ffuf"]:
        found = shutil.which(tool)
        checks.append((f"Tool: {tool}", bool(found), found or "missing — h1scope will auto-install"))

    table = Table(box=box.SIMPLE)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", style="dim")
    for name, ok, detail in checks:
        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, status, detail)
    console.print(table)

    all_pass = all(ok for _, ok, _ in checks[:10])
    if not all_pass:
        console.print("\n[yellow]Some checks failed. Run: pip install -e .[/yellow]")
    else:
        console.print("\n[green]H1ScopeAgent is ready.[/green]")


# ===========================================================================
# 3. tools
# ===========================================================================
@app.command()
def tools():
    """List installed external tools and their availability."""
    results = scan_tools()
    table = Table(box=box.SIMPLE, title="External Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Path", style="dim")
    for t in results:
        status = "[green]installed[/green]" if t.installed else "[red]missing[/red]"
        table.add_row(t.name, status, t.version or "-", t.path or "-")
    console.print(table)


# ===========================================================================
# 4. browser-check
# ===========================================================================
@app.command()
def browser_check():
    """Check browser scouting readiness (Playwright + Chromium)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        console.print("[red]Playwright not installed.[/red]")
        raise typer.Exit(code=1)

    async def _test():
        try:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("about:blank", timeout=10000)
            await browser.close()
            await pw.stop()
            return True, "Browser launched successfully"
        except Exception as e:
            return False, str(e)

    ok, msg = asyncio.run(_test())
    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]Browser test failed: {msg}[/red]")


# ===========================================================================
# 5. sync
# ===========================================================================
@app.command()
def sync(
    program_handle: str = typer.Option(None, "--program", help="Sync single program"),
    force: bool = typer.Option(False, "--force", help="Full re-sync"),
):
    """Pull and store HackerOne program data locally."""
    settings = get_settings()
    if not settings.has_credentials:
        console.print("[red]No API credentials. Set HACKERONE_USERNAME and HACKERONE_TOKEN in .env[/red]")
        raise typer.Exit(code=1)

    init_db()

    with get_db() as db:
        try:
            with HackerOneClient() as client:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
                    task = progress.add_task("Fetching programs...", total=None)
                    programs = client.get_programs()

                    if program_handle:
                        programs = [p for p in programs if p["handle"] == program_handle]
                        if not programs:
                            console.print(f"[red]Program '{program_handle}' not found.[/red]")
                            return

                    progress.update(task, description=f"Syncing {len(programs)} programs")

                    for i, prog in enumerate(programs):
                        handle = prog.get("handle", "")
                        progress.update(task, description=f"[{i+1}/{len(programs)}] {handle}")

                        upsert_program(db, prog)

                        try:
                            scopes_raw = client.get_structured_scopes(handle)
                            scope_entries = []
                            for sr in scopes_raw:
                                conf = sr.get("confidentiality", "")
                                is_in = not (conf and "out_of_scope" in conf.lower())
                                scope_entries.append({
                                    "asset_identifier": sr.get("asset_identifier", ""),
                                    "asset_type": sr.get("asset_type", ""),
                                    "eligible_for_bounty": sr.get("eligible_for_bounty", False),
                                    "eligible_for_submission": sr.get("eligible_for_submission", False),
                                    "max_severity": sr.get("max_severity", ""),
                                    "instruction": sr.get("instruction", ""),
                                    "in_scope": is_in,
                                })
                            upsert_scopes(db, handle, scope_entries)
                        except APIError as e:
                            console.print(f"  [yellow]Scope: {e}[/yellow]")

                        try:
                            policy_text = client.get_policy(handle)
                            if policy_text:
                                from h1scopeagent.policy.summarizer import PolicySummarizer
                                summary_result = PolicySummarizer().summarize(policy_text)
                                upsert_policy(db, handle, {
                                    "program_handle": handle,
                                    "raw_policy_text": policy_text,
                                    "summary": summary_result.get("summary", ""),
                                    "allowed_testing": summary_result.get("allowed_testing", ""),
                                    "forbidden_testing": summary_result.get("forbidden_testing", ""),
                                    "rate_limits": summary_result.get("rate_limits", ""),
                                    "disclosure_rules": summary_result.get("disclosure_rules", ""),
                                })
                        except APIError:
                            pass

                    progress.update(task, description=f"Sync complete — {len(programs)} programs", total=1, completed=1)

            audit.log_api_sync("all", len(programs), 0)
            console.print(f"\n[green]Synced {len(programs)} programs.[/green]")

        except NoTokenError:
            console.print("[red]No API credentials configured.[/red]")
            raise typer.Exit(code=1)
        except AuthError as e:
            console.print(f"[red]Authentication failed: {e}[/red]")
            raise typer.Exit(code=1)
        except APIError as e:
            console.print(f"[red]API error: {e}[/red]")
            raise typer.Exit(code=1)


# ===========================================================================
# 6. programs
# ===========================================================================
@app.command()
def programs(
    search: str = typer.Option(None, "--search", help="Search by name or handle"),
    bookmarked: bool = typer.Option(False, "--bookmarked", help="Only bookmarked"),
    private: bool = typer.Option(False, "--private", help="Include private programs"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List synced HackerOne programs."""
    with get_db() as db:
        if bookmarked:
            progs = get_bookmarked_programs(db)
        elif search:
            progs = search_programs(db, search)
        else:
            progs = get_programs(db)

    if not private:
        progs = [p for p in progs if not p.get("confidential")]

    if json_output:
        console.print_json(json.dumps(progs, default=str))
        return

    table = Table(box=box.SIMPLE, title=f"HackerOne Programs ({len(progs)})")
    table.add_column("Handle", style="cyan")
    table.add_column("Name")
    table.add_column("State")
    table.add_column("Bounties")
    table.add_column("Synced", style="dim")
    for p in progs:
        b = "[green]yes[/green]" if p.get("offers_bounties") else "[dim]no[/dim]"
        synced = p.get("last_synced_at", "")[:16]
        table.add_row(p.get("handle", ""), p.get("name", ""), p.get("state", ""), b, synced)
    console.print(table)


# ===========================================================================
# 7. scope
# ===========================================================================
@app.command()
def scope(
    program_handle: str = typer.Argument(..., help="Program handle"),
    diff: bool = typer.Option(False, "--diff", help="Show scope changes since last sync"),
    export: bool = typer.Option(False, "--export", help="Export scope to file"),
    export_format: str = typer.Option("json", "--format", help="Export format: json, csv"),
):
    """Show structured scope for a program."""
    _, in_scope, out_scope, _ = _load_program_context(program_handle)

    if diff:
        with get_db() as db:
            history = get_scope_history(db, program_handle)
        if not history:
            console.print("[yellow]No scope changes detected.[/yellow]")
            return
        table = Table(box=box.SIMPLE, title=f"Scope Changes — {program_handle}")
        table.add_column("Asset")
        table.add_column("Change")
        table.add_column("Detected", style="dim")
        for h in history:
            color = "green" if h["change_type"] == "added" else "red" if h["change_type"] == "removed" else "yellow"
            table.add_row(h["asset_identifier"][:60], f"[{color}]{h['change_type']}[/{color}]", h["detected_at"][:16])
        console.print(table)
        return

    if export:
        data = [s for s in in_scope + out_scope]
        out_path = DATA_DIR / f"{program_handle}_scope.{export_format}"
        if export_format == "csv":
            import csv
            with open(out_path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0].keys()) if data else [])
                w.writeheader()
                w.writerows(data)
        else:
            out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Exported to {out_path}[/green]")
        return

    if in_scope:
        console.print(f"\n[bold green]In-Scope ({len(in_scope)})[/bold green]")
        table = Table(box=box.SIMPLE)
        table.add_column("Asset", style="cyan")
        table.add_column("Type")
        table.add_column("Bounty")
        table.add_column("Severity")
        for s in in_scope[:50]:
            b = "[green]yes[/green]" if s.get("eligible_for_bounty") else "[dim]no[/dim]"
            table.add_row(s.get("asset_identifier", "")[:60], s.get("asset_type", ""), b, s.get("max_severity", ""))
        console.print(table)

    if out_scope:
        console.print(f"\n[bold red]Out-of-Scope ({len(out_scope)})[/bold red]")
        for s in out_scope[:20]:
            console.print(f"  [red]{s.get('asset_identifier', '')[:80]}[/red]")

    console.print()


# ===========================================================================
# 8. policy
# ===========================================================================
@app.command()
def policy(program_handle: str = typer.Argument(..., help="Program handle")):
    """Show summarized program policy."""
    _, _, _, pol = _load_program_context(program_handle)
    if not pol:
        console.print("[yellow]No policy data.[/yellow]")
        return
    console.print(Panel.fit(f"[bold]Policy: {program_handle}[/bold]", border_style="blue"))
    if pol.get("allowed_testing"):
        console.print(Panel.fit(pol["allowed_testing"], title="[green]Allowed[/green]", border_style="green"))
    if pol.get("forbidden_testing"):
        console.print(Panel.fit(pol["forbidden_testing"], title="[red]Forbidden[/red]", border_style="red"))
    if pol.get("rate_limits"):
        console.print(Panel.fit(pol["rate_limits"], title="[yellow]Rate Limits[/yellow]", border_style="yellow"))


# ===========================================================================
# 9. plan
# ===========================================================================
@app.command()
def plan(
    program_handle: str = typer.Argument(..., help="Program handle"),
    profile: str = typer.Option("default", "--profile", help="Profile name"),
):
    """Generate a recon strategy plan."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)
    prof = load_profile(profile)

    from h1scopeagent.recon.planner import ReconPlanner
    planner = ReconPlanner()
    result = planner.build_plan(program_handle, in_scope + out_scope, pol)

    console.print(Panel.fit(f"[bold]Recon Plan: {program_handle} (profile: {profile})[/bold]", border_style="blue"))
    console.print(RichMarkdown(result.markdown))

    with get_db() as db:
        save_recon_plan(db, program_handle, result.markdown, profile)


# ===========================================================================
# 10. recon
# ===========================================================================
@app.command()
def recon(
    program_handle: str = typer.Argument(..., help="Program handle"),
    profile: str = typer.Option("default", "--profile", help="Profile name"),
    target: str = typer.Option(None, "--target", help="Target a specific asset"),
    resume: bool = typer.Option(False, "--resume", help="Resume from checkpoint"),
):
    """Run recon modules against a program."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)
    prof = load_profile(profile)

    from h1scopeagent.scope.validator import ScopeValidator
    validator = ScopeValidator(in_scope + out_scope)

    if target:
        targets = [target] if validator.is_in_scope(target)["decision"] == "in_scope" else []
    else:
        with get_db() as db:
            web_assets = get_in_scope_web_assets(db, program_handle)
        targets = []
        for a in web_assets[:prof.asset_limit]:
            ident = a.get("asset_identifier", "")
            if not ident.startswith("http"):
                ident = f"https://{ident}"
            if validator.is_in_scope(ident)["decision"] == "in_scope":
                targets.append(ident)

    if not targets:
        console.print("[yellow]No in-scope targets.[/yellow]")
        return

    profile_modules = prof.recon_modules
    with get_db() as db:
        run_id = create_scan_run(db, program_handle, profile, profile_modules, len(targets))

    console.print(f"[bold]Recon: {program_handle} (profile: {profile})[/bold]")
    console.print(f"  Modules: {', '.join(profile_modules)}")
    console.print(f"  Targets: {len(targets)}")

    modules_available = {
        "subdomains": prof.subdomain_enum,
        "dns": prof.dns_resolution,
        "http": prof.http_probing,
        "tls": prof.tls_inspection,
        "crawler": prof.url_crawling,
        "javascript": prof.js_collection,
        "history": prof.wayback_import,
        "github": prof.github_search,
        "leaks": prof.leak_scanning,
        "cloud": prof.cloud_bucket_check,
    }

    processed = 0
    for module_name in profile_modules:
        if not modules_available.get(module_name):
            continue
        console.print(f"\n  [cyan]Running: {module_name}[/cyan]")

    processed = len(targets)
    with get_db() as db:
        update_scan_run(db, run_id, processed, 0, "completed")
    console.print(f"\n[green]Recon complete: {processed} targets[/green]")


# ===========================================================================
# 11. crawl
# ===========================================================================
@app.command()
def crawl(
    program_handle: str = typer.Argument(..., help="Program handle"),
    url: str = typer.Option(None, "--url", help="Start from specific URL"),
    depth: int = typer.Option(3, "--depth", help="Crawl depth"),
    js_only: bool = typer.Option(False, "--js-only", help="Only collect JS files"),
):
    """URL crawling and JavaScript analysis."""
    _, in_scope, out_scope, _ = _load_program_context(program_handle)
    from h1scopeagent.scope.validator import ScopeValidator
    validator = ScopeValidator(in_scope + out_scope)

    if url:
        targets = [url]
    else:
        with get_db() as db:
            web_assets = get_in_scope_web_assets(db, program_handle)
        targets = []
        for a in web_assets[:10]:
            ident = a.get("asset_identifier", "")
            if not ident.startswith("http"):
                ident = f"https://{ident}"
            if validator.is_in_scope(ident)["decision"] == "in_scope":
                targets.append(ident)

    console.print(f"[bold]Crawling {len(targets)} URLs (depth={depth})[/bold]")
    for t in targets:
        console.print(f"  [cyan]{t}[/cyan]")

    async def _run():
        from h1scopeagent.browser.chromium import ChromiumScout
        async with ChromiumScout(headless=True) as scout:
            for t in targets:
                try:
                    result = await scout.scout_url(t, validator)
                    console.print(f"  {result.get('status_code', '?')} | {result.get('title', '')[:50]}")
                except Exception as e:
                    console.print(f"  [red]{e}[/red]")

    asyncio.run(_run())


# ===========================================================================
# 12-13. scout + scout-batch
# ===========================================================================
@app.command()
def scout(
    program_handle: str = typer.Argument(..., help="Program handle"),
    url: str = typer.Argument(..., help="URL to scout"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    slowmo: int = typer.Option(0, "--slowmo"),
    no_screenshots: bool = typer.Option(False, "--no-screenshots"),
    full_page: bool = typer.Option(False, "--full-page", help="Full-page screenshots"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Browser-scout a single URL using Chromium."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)
    from h1scopeagent.scope.validator import ScopeValidator
    validator = ScopeValidator(in_scope + out_scope)

    scope_result = validator.is_in_scope(url)
    if scope_result["decision"] != "in_scope":
        console.print(f"[red]URL is not in scope: {scope_result['reason']}[/red]")
        raise typer.Exit(code=1)

    async def _run():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety
        async with ChromiumScout(headless=headless, slow_mo=slowmo) as scout_instance:
            result = await scout_with_safety(scout_instance, url, validator, pol, program_handle)
        if json_output:
            console.print_json(json.dumps(result, default=str))
        else:
            console.print(Panel.fit(f"[bold]Scout: {url}[/bold]", border_style="blue"))
            console.print(f"  Status: {result.get('status_code', '?')}")
            console.print(f"  Title: {result.get('title', '')}")
            console.print(f"  Findings: {result.get('findings_count', 0)}")
            if result.get("screenshot_path"):
                console.print(f"  Screenshot: {result['screenshot_path']}")
        return result

    asyncio.run(_run())


@app.command()
def scout_batch(
    program_handle: str = typer.Argument(..., help="Program handle"),
    limit: int = typer.Option(10, "--limit"),
    delay: float = typer.Option(3.0, "--delay"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    slowmo: int = typer.Option(0, "--slowmo"),
    no_screenshots: bool = typer.Option(False, "--no-screenshots"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Batch-scout in-scope web assets."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)
    from h1scopeagent.scope.validator import ScopeValidator
    validator = ScopeValidator(in_scope + out_scope)

    with get_db() as db:
        assets = get_in_scope_web_assets(db, program_handle)

    targets = []
    for a in assets[:limit]:
        ident = a.get("asset_identifier", "")
        if not ident.startswith("http"):
            ident = f"https://{ident}"
        if validator.is_in_scope(ident)["decision"] == "in_scope":
            targets.append(ident)

    if not targets:
        console.print("[yellow]No safe targets.[/yellow]")
        return

    console.print(f"[bold]Scouting {len(targets)} URLs...[/bold]\n")

    async def _batch():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety
        results = []
        async with ChromiumScout(headless=headless, slow_mo=slowmo) as scout_instance:
            for i, t in enumerate(targets):
                try:
                    r = await scout_with_safety(scout_instance, t, validator, pol, program_handle)
                    results.append(r)
                    console.print(f"[{i+1}/{len(targets)}] {t} | {r.get('status_code','?')} | {r.get('findings_count',0)} findings")
                except Exception as e:
                    console.print(f"[{i+1}/{len(targets)}] {t} [red]{e}[/red]")
                if i < len(targets) - 1:
                    await asyncio.sleep(delay)
        return results

    results = asyncio.run(_batch())
    if json_output:
        console.print_json(json.dumps(results, default=str))
    else:
        total = sum(r.get("findings_count", 0) for r in results)
        console.print(f"\n[green]Batch complete: {len(targets)} URLs, {total} findings[/green]")


# ===========================================================================
# 14. auto
# ===========================================================================
@app.command()
def auto(
    program_handle: str = typer.Argument(..., help="Program handle"),
    profile: str = typer.Option("default", "--profile", help="Profile name"),
    finding_limit: int = typer.Option(DEFAULT_FINDING_LIMIT, "--finding-limit"),
    asset_limit: int = typer.Option(DEFAULT_ASSET_LIMIT, "--asset-limit"),
    delay: float = typer.Option(DEFAULT_DELAY, "--delay"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    screenshots: bool = typer.Option(True, "--screenshots/--no-screenshots"),
    passive_only: bool = typer.Option(False, "--passive-only"),
    browser_only: bool = typer.Option(False, "--browser-only"),
    no_browser: bool = typer.Option(False, "--no-browser"),
    json_output: bool = typer.Option(False, "--json"),
    attack_enabled: bool = typer.Option(False, "--attack", help="Enable auto-attack pipeline"),
    risk_level: str = typer.Option("verified", "--risk", help="Risk level for attack"),
):
    """Autonomous recon + optional active attack pipeline."""
    _print_banner()
    program, in_scope, out_scope, pol = _load_program_context(program_handle)
    prof = load_profile(profile)

    from h1scopeagent.scope.validator import ScopeValidator
    validator = ScopeValidator(in_scope + out_scope)

    with get_db() as db:
        web_assets = get_in_scope_web_assets(db, program_handle)

    safe_targets = []
    for a in web_assets[:asset_limit]:
        ident = a.get("asset_identifier", "")
        if not ident.startswith("http"):
            ident = f"https://{ident}"
        if validator.is_in_scope(ident)["decision"] == "in_scope":
            safe_targets.append(ident)

    console.print(f"[bold]Auto Mode — {program_handle}[/bold]")
    console.print(f"  Profile: {profile} | Targets: {len(safe_targets)} | Finding limit: {finding_limit}")
    audit.log_autonomous_decision("start", program_handle, "begin", f"profile={profile},targets={len(safe_targets)}")

    async def _auto():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety
        from h1scopeagent.recon.passive import PassiveRecon

        recon = PassiveRecon()
        scouted = 0

        async with ChromiumScout(headless=headless) as scout_instance:
            for i, target in enumerate(safe_targets):
                with get_db() as db:
                    if count_candidate_findings(db, program_handle) >= finding_limit:
                        console.print(f"\n[green]Finding limit ({finding_limit}) reached.[/green]")
                        break

                console.print(f"\n[{i+1}/{len(safe_targets)}] [cyan]{target}[/cyan]")

                if not browser_only:
                    try:
                        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                        recon.http_headers(target)
                    except Exception:
                        pass

                if not passive_only and not no_browser:
                    try:
                        result = await scout_with_safety(scout_instance, target, validator, pol, program_handle)
                        scouted += 1
                        console.print(f"  {result.get('status_code','?')} | {result.get('findings_count',0)} findings")
                    except Exception as e:
                        console.print(f"  [red]{e}[/red]")

                await asyncio.sleep(delay)

        console.print(f"\n[bold]Auto complete[/bold] — {scouted} scouted")

        with get_db() as db:
            return get_candidate_findings(db, program_handle)

    findings = asyncio.run(_auto())

    if json_output:
        console.print_json(json.dumps(findings, default=str))
    else:
        _print_findings_summary(findings)

    audit.log_autonomous_decision("complete", program_handle, "finished", f"findings={len(findings)}")

    # Attack pipeline
    if attack_enabled and findings:
        if risk_level not in ("verified", "aggressive"):
            console.print(f"\n[yellow]Attack requires --risk verified or aggressive. Current: {risk_level}. Skipping.[/yellow]")
        else:
            from h1scopeagent.attack.decision import AttackDecisionMatrix
            from h1scopeagent.attack.engine import AutoAttackEngine
            from h1scopeagent.attack.verifier import FindingVerifier

            matrix = AttackDecisionMatrix(risk_level)
            if not matrix.risk_config["attack_enabled"]:
                console.print(f"\n[yellow]Attack disabled at risk '{risk_level}'.[/yellow]")
            else:
                console.print(f"\n[bold red]=== ATTACK PIPELINE (risk: {risk_level}) ===[/bold red]\n")
                engine = AutoAttackEngine(validator, program_handle, risk_level)
                verifier = FindingVerifier(validator, program_handle)
                attacked = 0

                for i, finding in enumerate(findings):
                    ctype = finding.get("candidate_type", "")
                    if ctype in ("secret_leakage", "console_errors", "source_maps"):
                        continue

                    decision = matrix.evaluate(finding)
                    if not decision.should_attack:
                        continue

                    console.print(f"[{i+1}/{len(findings)}] [cyan]{finding.get('title', '')[:70]}[/cyan]")
                    console.print(f"  Score: {decision.score} | Tools: {', '.join(decision.tools)}")

                    try:
                        ver_result = verifier.verify(finding)
                        if ver_result.verified:
                            console.print(f"  [green]Verified ({ver_result.confidence})[/green]")
                            finding["verification_result"] = ver_result.evidence
                            finding["confidence"] = "high"

                        d, results = engine.evaluate_and_attack(finding)
                        if results and d.should_attack:
                            attacked += 1
                            for r in results:
                                console.print(f"  [cyan]{r.tool}[/cyan]: exit={r.exit_code}, {r.duration}s")
                                if r.error:
                                    console.print(f"  [yellow]{r.error[:100]}[/yellow]")
                                save_command_log(db, {
                                    "program_handle": program_handle,
                                    "command": r.command,
                                    "target": r.target,
                                    "exit_code": r.exit_code,
                                    "output": r.output[:2000] if r.output else "",
                                })
                                if r.new_evidence:
                                    finding["evidence"] = {**finding.get("evidence", {}), **r.new_evidence}

                        with get_db() as db:
                            save_candidate_finding(db, finding)

                    except Exception as e:
                        console.print(f"  [red]{e}[/red]")

                console.print(f"\n[bold red]Attack complete: {attacked} findings attacked[/bold red]")


# ===========================================================================
# 15. findings
# ===========================================================================
@app.command()
def findings(
    program_handle: str = typer.Argument(..., help="Program handle"),
    search: str = typer.Option(None, "--search", help="Search findings"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity"),
    confidence: str = typer.Option(None, "--confidence", help="Filter by confidence"),
    status: str = typer.Option(None, "--status", help="Filter by status"),
    tag: str = typer.Option(None, "--tag", help="Filter by tag"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Show candidate findings."""
    _load_program_context(program_handle)

    with get_db() as db:
        finds = get_candidate_findings(db, program_handle, status, severity, confidence, search, tag)

    if json_output:
        console.print_json(json.dumps(finds, default=str))
        return

    if not finds:
        console.print("[yellow]No findings.[/yellow]")
        return

    console.print(f"\n[bold]Findings — {program_handle} ({len(finds)})[/bold]\n")
    table = Table(box=box.SIMPLE)
    table.add_column("ID", style="dim")
    table.add_column("Title")
    table.add_column("Asset", style="cyan")
    table.add_column("Status")
    table.add_column("Confidence")
    table.add_column("Severity")

    sev_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
    conf_colors = {"high": "green", "medium": "yellow", "low": "dim"}

    for f in finds:
        sev_c = sev_colors.get(f.get("estimated_severity", ""), "white")
        conf_c = conf_colors.get(f.get("confidence", ""), "white")
        table.add_row(
            f.get("candidate_id", "")[:8],
            f.get("title", "")[:60],
            f.get("affected_asset", "")[:40],
            f.get("status", "candidate"),
            f"[{conf_c}]{f.get('confidence','')}[/{conf_c}]",
            f"[{sev_c}]{f.get('estimated_severity','')}[/{sev_c}]",
        )
    console.print(table)
    console.print(f"\n[dim]Use: h1scope report {program_handle}[/dim]")


# ===========================================================================
# 16. report
# ===========================================================================
@app.command()
def report(
    program_handle: str = typer.Argument(..., help="Program handle"),
    template: str = typer.Option("default", "--template", help="Report template"),
    output_format: str = typer.Option("md", "--format", help="Output: md, html, pdf"),
    brief: bool = typer.Option(False, "--brief", help="Short report mode"),
    detailed: bool = typer.Option(False, "--detailed", help="Detailed report mode"),
    submit_reports: bool = typer.Option(False, "--submit", help="Auto-submit after generation"),
    risk_level: str = typer.Option("aggressive", "--risk"),
    dry_run: bool = typer.Option(False, "--dry-run"),
):
    """Generate HackerOne-style report drafts."""
    _load_program_context(program_handle)

    from h1scopeagent.reports.generator import ReportGenerator
    generator = ReportGenerator()

    with get_db() as db:
        finds = get_candidate_findings(db, program_handle)

    ready = [f for f in finds if f.get("report_ready")]
    if not ready:
        console.print("[yellow]No report-ready findings.[/yellow]")
        return

    console.print(f"[bold]Generating {len(ready)} reports (template: {template})...[/bold]\n")
    generated = 0
    report_data_list = []

    for f in ready:
        try:
            md = generator.generate_report(f, program_handle)
            reports_dir = REPORTS_DIR / program_handle
            reports_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{f.get('candidate_id', 'unknown')[:12]}.{output_format}"
            path = reports_dir / filename

            if output_format == "html":
                body = md.get("html_body", md.get("markdown_body", ""))
            else:
                body = md.get("markdown_body", "")

            path.write_text(body, encoding="utf-8")

            with get_db() as db:
                save_report_draft(db, program_handle, {
                    "finding_id": f.get("candidate_id", ""),
                    "title": md.get("title", ""),
                    "affected_asset": md.get("affected_asset", ""),
                    "severity": md.get("severity", "info"),
                    "markdown_body": md.get("markdown_body", ""),
                    "template_used": template,
                })

            generated += 1
            console.print(f"  [green]Saved:[/green] {path}")
            report_data_list.append(md)
        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    console.print(f"\n[green]{generated} reports generated.[/green]")

    if submit_reports and report_data_list:
        from h1scopeagent.attack.submitter import AutoSubmitter, batch_submit
        submitter = AutoSubmitter(risk_level)
        if not submitter.can_auto_submit():
            console.print(f"\n[red]Auto-submit requires --risk aggressive. Current: {risk_level}[/red]")
            return

        console.print(f"\n[bold]Submitting {len(report_data_list)} reports...[/bold]\n")
        if dry_run:
            console.print("[yellow]DRY RUN — nothing submitted[/yellow]")
            for d in report_data_list:
                console.print(f"  WOULD submit: {d.get('title', '')[:80]}")
            return

        results = batch_submit(report_data_list, program_handle, risk_level, submitter)
        submitted = 0
        for r in results:
            if r.submitted:
                console.print(f"  [green]SUBMITTED: {r.report_id}[/green]")
                submitted += 1
            else:
                console.print(f"  [red]FAILED: {r.error[:100]}[/red]")
        console.print(f"\n[green]{submitted}/{len(results)} submitted[/green]")


# ===========================================================================
# 17. submit
# ===========================================================================
@app.command()
def submit(
    program_handle: str = typer.Argument(..., help="Program handle"),
    risk_level: str = typer.Option("aggressive", "--risk"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Auto-submit report drafts to HackerOne."""
    from h1scopeagent.attack.submitter import AutoSubmitter, batch_submit
    submitter = AutoSubmitter(risk_level)

    if not submitter.can_auto_submit():
        console.print(f"[red]Auto-submit requires --risk aggressive. Current: {risk_level}[/red]")
        raise typer.Exit(code=1)

    with get_db() as db:
        drafts = get_report_drafts(db, program_handle)

    if not drafts:
        console.print("[yellow]No report drafts.[/yellow]")
        return

    console.print(f"[bold]Submitting {len(drafts)} reports[/bold]\n")
    if dry_run:
        console.print("[yellow]DRY RUN[/yellow]")
        for d in drafts:
            console.print(f"  WOULD submit: {d.get('title', '')[:80]}")
        return

    results = batch_submit(drafts, program_handle, risk_level, submitter)
    submitted = 0
    for r in results:
        if r.submitted:
            console.print(f"  [green]SUBMITTED: {r.report_id} — {r.title[:60]}[/green]")
            submitted += 1
        else:
            console.print(f"  [red]FAILED: {r.title[:60]} — {r.error[:100]}[/red]")

    console.print(f"\n[green]{submitted}/{len(results)} submitted[/green]")
    if json_output:
        console.print_json(json.dumps([r.__dict__ for r in results], default=str))


# ===========================================================================
# 18. export
# ===========================================================================
@app.command()
def export(
    program_handle: str = typer.Argument(..., help="Program handle"),
    export_type: str = typer.Option("findings", "--type", help="scope, findings, reports, endpoints"),
    output_format: str = typer.Option("json", "--format", help="json, csv, md"),
    output_path: str = typer.Option(None, "--output", help="Output file path"),
):
    """Export data in various formats."""
    _load_program_context(program_handle)

    if export_type == "scope":
        with get_db() as db:
            in_s, out_s = get_scopes(db, program_handle)
            data = in_s + out_s
    elif export_type == "findings":
        with get_db() as db:
            data = get_candidate_findings(db, program_handle)
    elif export_type == "reports":
        with get_db() as db:
            data = get_report_drafts(db, program_handle)
    elif export_type == "endpoints":
        with get_db() as db:
            data = get_endpoints(db, program_handle)
    else:
        console.print(f"[red]Unknown type: {export_type}[/red]")
        return

    out = Path(output_path) if output_path else DATA_DIR / f"{program_handle}_{export_type}.{output_format}"

    if output_format == "csv":
        import csv
        if data:
            with open(out, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
                w.writeheader()
                w.writerows(data)
    else:
        out.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    console.print(f"[green]Exported {len(data)} {export_type} to {out}[/green]")


# ===========================================================================
# 19. backup
# ===========================================================================
@app.command()
def backup(
    output_path: str = typer.Option(None, "--output", help="Backup file path"),
):
    """Backup the database."""
    import shutil as sh
    src = DB_PATH
    dst = Path(output_path) if output_path else DATA_DIR / f"backup_{int(time.time())}.db"
    if src.exists():
        sh.copy2(src, dst)
        console.print(f"[green]Backup saved to {dst}[/green]")
    else:
        console.print("[red]No database found.[/red]")


# ===========================================================================
# 20. restore
# ===========================================================================
@app.command()
def restore(
    backup_file: str = typer.Argument(..., help="Backup file to restore"),
):
    """Restore database from backup."""
    import shutil as sh
    src = Path(backup_file)
    if not src.exists():
        console.print(f"[red]Backup file not found: {src}[/red]")
        raise typer.Exit(code=1)
    sh.copy2(src, DB_PATH)
    console.print(f"[green]Database restored from {src}[/green]")


# ===========================================================================
# 21. daemon
# ===========================================================================
@app.command()
def daemon(
    risk_level: str = typer.Option("verified", "--risk", help="Risk: safe, verified, aggressive"),
    profile: str = typer.Option("default", "--profile", help="Recon profile"),
    interval: int = typer.Option(3600, "--interval", help="Loop interval (seconds)"),
    max_iterations: int = typer.Option(0, "--max-iters", help="Max loops (0=unlimited)"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    workers: int = typer.Option(2, "--workers", help="Concurrent workers"),
):
    """Fully autonomous daemon — continuous sync, recon, attack, report, submit."""
    from h1scopeagent.daemon import DaemonController
    ctrl = DaemonController(
        risk_level=risk_level,
        profile=profile,
        interval=interval,
        max_iterations=max_iterations,
        headless=headless,
        workers=workers,
    )
    ctrl.run()


# ===========================================================================
# 22. dashboard
# ===========================================================================
@app.command()
def dashboard(
    refresh: int = typer.Option(5, "--refresh", help="Refresh rate (seconds)"),
):
    """Launch Rich TUI dashboard."""
    from rich.live import Live
    from rich.layout import Layout
    import time

    console.print("[bold]H1ScopeAgent Dashboard[/bold]\n")

    def make_dashboard() -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )

        with get_db() as db:
            progs = get_programs(db)
            scan_runs = []
            for p in progs[:5]:
                scan_runs.extend(get_scan_runs(db, p.get("handle", ""), 3))

        header = Panel.fit(
            f"[bold blue]H1ScopeAgent[/bold blue] | Programs: {len(progs)} | [dim]Ctrl+C to exit[/dim]",
            border_style="blue",
        )
        layout["header"].update(header)

        left_table = Table(box=box.SIMPLE, title="Programs")
        left_table.add_column("Handle")
        left_table.add_column("State")
        left_table.add_column("Bounties")
        for p in progs[:15]:
            b = "yes" if p.get("offers_bounties") else "no"
            left_table.add_row(p.get("handle", ""), p.get("state", ""), b)
        layout["left"].update(Panel(left_table))

        right_table = Table(box=box.SIMPLE, title="Recent Scan Runs")
        right_table.add_column("Program")
        right_table.add_column("Status")
        right_table.add_column("Findings")
        for s in scan_runs[:15]:
            status_color = "green" if s.get("status") == "completed" else "yellow" if s.get("status") == "running" else "red"
            right_table.add_row(
                s.get("program_handle", ""),
                f"[{status_color}]{s.get('status', '')}[/{status_color}]",
                str(s.get("findings_found", 0)),
            )
        layout["right"].update(Panel(right_table))

        return layout

    try:
        with Live(make_dashboard(), refresh_per_second=1/refresh, console=console, screen=True) as live:
            while True:
                time.sleep(refresh)
                live.update(make_dashboard())
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard closed.[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
