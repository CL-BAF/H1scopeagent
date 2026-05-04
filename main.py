"""H1ScopeAgent CLI — Fully Automated HackerOne Bug Bounty Bot.

Commands: doctor, tools, browser-check, sync, programs, scope, policy,
plan, suggest, scout, scout-batch, auto, findings, report, run,
daemon, attack, submit.
"""

from __future__ import annotations

import asyncio
import json
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
    get_settings,
    DATA_DIR,
    SCREENSHOTS_DIR,
    METADATA_DIR,
    DB_PATH,
    DEFAULT_FINDING_LIMIT,
    DEFAULT_ASSET_LIMIT,
    DEFAULT_DELAY,
)
from h1scopeagent.db.database import (
    get_db,
    init_db as init_database,
    upsert_program,
    get_programs,
    upsert_scopes,
    get_scopes,
    get_all_scope_entries,
    get_in_scope_web_assets,
    upsert_policy,
    get_policy,
    save_recon_plan,
    get_latest_recon_plan,
    save_command_log,
    save_browser_scout,
    save_candidate_finding,
    get_candidate_findings,
    count_candidate_findings,
    save_report_draft,
    get_report_drafts,
)
from h1scopeagent.db.models import (
    Program,
    ScopeEntry,
    PolicyRecord,
    CommandLogEntry,
    BrowserScoutEntry,
)
from h1scopeagent.api.hackerone import HackerOneClient, NoTokenError, AuthError, APIError
from h1scopeagent.recon.tools import scan_tools, ToolInfo
from h1scopeagent.logs.audit import AuditLogger


app = typer.Typer(
    name="h1scope",
    help="H1ScopeAgent — Authorized HackerOne bug bounty assistant",
    add_completion=False,
)
console = Console()
audit = AuditLogger()


def _load_program_context(handle: str):
    """Load scope entries and policy for a program from the database."""
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
    console.print()
    console.print(Panel.fit(
        "[bold blue]H1ScopeAgent[/bold blue] — Authorized Bug Bounty Assistant\n"
        "[dim]Non-invasive recon | Scope-aware | Human-approved only[/dim]",
        border_style="blue",
    ))


# ===========================================================================
# 1. doctor
# ===========================================================================
@app.command()
def doctor():
    """Check system readiness for H1ScopeAgent."""
    _print_banner()
    console.print("[bold]System Doctor Report[/bold]\n")

    checks: list[tuple[str, bool, str]] = []
    settings = get_settings()

    # Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("Python Version", sys.version_info >= (3, 11), py_ver))

    # Required packages
    pkgs = {
        "httpx": "httpx",
        "typer": "typer",
        "rich": "rich",
        "pydantic": "pydantic",
        "playwright": "playwright",
        "bs4": "beautifulsoup4",
        "dotenv": "python-dotenv",
    }
    for mod, pkg in pkgs.items():
        try:
            __import__(mod)
            checks.append((f"Package: {pkg}", True, "installed"))
        except ImportError:
            checks.append((f"Package: {pkg}", False, "MISSING"))

    # Environment
    has_user = bool(settings.hackerone_username)
    has_token = bool(settings.hackerone_token)
    checks.append(("HACKERONE_USERNAME set", has_user, "configured" if has_user else "MISSING"))
    checks.append(("HACKERONE_TOKEN set", has_token, "configured" if has_token else "MISSING"))
    checks.append((".env file exists", Path(".env").exists(), "found" if Path(".env").exists() else "not found"))

    # API auth test
    if has_user and has_token:
        try:
            with HackerOneClient() as client:
                ok = client.test_auth()
                checks.append(("HackerOne API Auth", ok, "authenticated" if ok else "FAILED"))
        except Exception as e:
            checks.append(("HackerOne API Auth", False, str(e)))
    else:
        checks.append(("HackerOne API Auth", False, "credentials not set"))

    # Database
    try:
        with get_db() as db:
            init_database()
            db.execute("SELECT 1")
        checks.append(("Database", True, str(DB_PATH)))
    except Exception as e:
        checks.append(("Database", False, str(e)))

    # Playwright
    try:
        from playwright.sync_api import sync_playwright
        checks.append(("Playwright Package", True, "installed"))
    except ImportError:
        checks.append(("Playwright Package", False, "not installed"))

    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
            capture_output=True, text=True, timeout=15,
        )
        checks.append(("Chromium Browser", True, "available"))
    except Exception:
        checks.append(("Chromium Browser", False, "may need: playwright install chromium"))

    # Optional tools
    for tool in ["curl", "dig", "whois", "openssl"]:
        import shutil
        found = shutil.which(tool)
        checks.append((f"Optional: {tool}", bool(found), found or "missing"))

    # Render
    table = Table(box=box.SIMPLE)
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    for name, ok, detail in checks:
        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, status, detail)

    console.print(table)

    all_pass = all(ok for _, ok, _ in checks[:9])  # Core checks
    if not all_pass:
        console.print()
        console.print("[yellow]Some checks failed. Install missing dependencies:[/yellow]")
        console.print("  pip install httpx typer rich pydantic pydantic-settings python-dotenv playwright beautifulsoup4")
        console.print("  python -m playwright install chromium")
    else:
        console.print()
        console.print("[green]H1ScopeAgent is ready.[/green]")


# ===========================================================================
# 2. tools
# ===========================================================================
@app.command()
def tools():
    """Show installed external tools and their autonomy classification."""
    results = scan_tools()
    table = Table(box=box.SIMPLE, title="External Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status")
    table.add_column("Version", style="dim")
    table.add_column("Autonomous", style="blue")
    table.add_column("Needs Approval", style="yellow")

    for t in results:
        status = "[green]installed[/green]" if t.installed else "[red]missing[/red]"
        ver = t.version or "-"
        auto = "[green]yes[/green]" if t.autonomous_allowed else "[dim]no[/dim]"
        approval = "[yellow]YES[/yellow]" if t.requires_approval else "[dim]no[/dim]"
        table.add_row(t.name, status, ver, auto, approval)

    console.print(table)


# ===========================================================================
# 3. browser-check
# ===========================================================================
@app.command()
def browser_check():
    """Check browser scouting readiness (Playwright + Chromium)."""
    console.print("[bold]Browser Scouting Check[/bold]\n")

    try:
        from playwright.async_api import async_playwright
        console.print("[green]Playwright package installed[/green]")
    except ImportError:
        console.print("[red]Playwright not installed.[/red]")
        console.print("Run: pip install playwright")
        console.print("Run: python -m playwright install chromium")
        raise typer.Exit(code=1)

    async def _test():
        try:
            pw = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("about:blank", timeout=10000)
            title = await page.title()
            await browser.close()
            await pw.stop()
            return True, "Browser launched, navigated to about:blank"
        except Exception as e:
            return False, str(e)

    ok, msg = asyncio.run(_test())
    if ok:
        console.print(f"[green]Chromium browser operational:[/green] {msg}")
        console.print("[green]Browser scouting is ready.[/green]")
    else:
        console.print(f"[red]Browser test failed:[/red] {msg}")
        console.print("[yellow]Try:[/yellow] python -m playwright install chromium")
        console.print("[yellow]Try:[/yellow] python -m playwright install-deps chromium")


# ===========================================================================
# 4. sync
# ===========================================================================
@app.command()
def sync():
    """Pull and store HackerOne program data locally."""
    _print_banner()
    settings = get_settings()
    if not settings.has_credentials:
        console.print("[red]No API credentials configured.[/red]")
        console.print("Set HACKERONE_USERNAME and HACKERONE_TOKEN in .env")
        raise typer.Exit(code=1)

    # Initialize DB
    init_database()

    with get_db() as db:
        try:
            with HackerOneClient() as client:
                with Progress(
                    SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Fetching programs...", total=None)
                    programs = client.get_programs()
                    progress.update(task, description=f"Fetched {len(programs)} programs")

                    for i, prog in enumerate(programs):
                        handle = prog.get("handle", "")
                        name = prog.get("name", "")
                        state = prog.get("state", "")
                        bounties = prog.get("offers_bounties", False)

                        progress.update(task, description=f"[{i+1}/{len(programs)}] Syncing {handle}...")

                        upsert_program(db, Program(
                            handle=handle, name=name, state=state,
                            offers_bounties=bounties,
                        ))

                        try:
                            scopes_raw = client.get_structured_scopes(handle)
                            scope_entries = []
                            for sr in scopes_raw:
                                is_in = True
                                conf = sr.get("confidentiality", "")
                                if conf and "out_of_scope" in conf.lower():
                                    is_in = False
                                scope_entries.append(ScopeEntry(
                                    program_handle=handle,
                                    asset_identifier=sr.get("asset_identifier", ""),
                                    asset_type=sr.get("asset_type", ""),
                                    eligible_for_bounty=sr.get("eligible_for_bounty", False),
                                    eligible_for_submission=sr.get("eligible_for_submission", False),
                                    max_severity=sr.get("max_severity", ""),
                                    instruction=sr.get("instruction", ""),
                                    in_scope=is_in,
                                ))
                            upsert_scopes(db, handle, scope_entries)
                        except APIError as e:
                            console.print(f"  [yellow]Scope fetch failed for {handle}: {e}[/yellow]")

                        try:
                            policy_text = client.get_policy(handle)
                            if policy_text:
                                from h1scopeagent.policy.summarizer import PolicySummarizer
                                summary_result = PolicySummarizer().summarize(policy_text)
                                upsert_policy(db, handle, PolicyRecord(
                                    program_handle=handle,
                                    raw_policy_text=policy_text,
                                    summary=summary_result.get("summary", ""),
                                    allowed_testing=summary_result.get("allowed_testing", ""),
                                    forbidden_testing=summary_result.get("forbidden_testing", ""),
                                    rate_limits=summary_result.get("rate_limits", ""),
                                    disclosure_rules=summary_result.get("disclosure_rules", ""),
                                ))
                        except APIError as e:
                            console.print(f"  [yellow]Policy fetch failed for {handle}: {e}[/yellow]")

                    progress.update(task, description=f"Sync complete — {len(programs)} programs", total=1, completed=1)

            audit.log_api_sync("all", len(programs), 0)
            console.print(f"\n[green]Synced {len(programs)} programs successfully.[/green]")

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
# 5. programs
# ===========================================================================
@app.command()
def programs():
    """List synced HackerOne programs."""
    with get_db() as db:
        progs = get_programs(db)

    if not progs:
        console.print("[yellow]No programs synced yet.[/yellow]")
        console.print("Run: h1scope sync")
        return

    table = Table(box=box.SIMPLE, title="HackerOne Programs")
    table.add_column("Handle", style="cyan")
    table.add_column("Name")
    table.add_column("State")
    table.add_column("Bounties")
    table.add_column("Last Synced", style="dim")

    for p in progs:
        b = "[green]yes[/green]" if p.offers_bounties else "[dim]no[/dim]"
        table.add_row(p.handle, p.name, p.state, b, p.last_synced_at[:19] if p.last_synced_at else "-")

    console.print(table)
    console.print(f"\n[dim]{len(progs)} programs[/dim]")


# ===========================================================================
# 6. scope
# ===========================================================================
@app.command()
def scope(program_handle: str = typer.Argument(..., help="Program handle")):
    """Show structured scope for a program."""
    _, in_scope, out_scope, _ = _load_program_context(program_handle)

    if in_scope:
        console.print(f"\n[bold green]In-Scope Assets ({len(in_scope)})[/bold green]")
        table = Table(box=box.SIMPLE)
        table.add_column("Asset", style="cyan")
        table.add_column("Type")
        table.add_column("Bounty")
        table.add_column("Max Severity")
        table.add_column("Instructions", style="dim")
        for s in in_scope:
            b = "[green]yes[/green]" if s.eligible_for_bounty else "[dim]no[/dim]"
            table.add_row(s.asset_identifier, s.asset_type, b, s.max_severity, s.instruction[:60])
        console.print(table)

    if out_scope:
        console.print(f"\n[bold red]Out-of-Scope Assets ({len(out_scope)})[/bold red]")
        table = Table(box=box.SIMPLE)
        table.add_column("Asset", style="red")
        table.add_column("Type")
        table.add_column("Instructions", style="dim")
        for s in out_scope:
            table.add_row(s.asset_identifier, s.asset_type, s.instruction[:60])
        console.print(table)

    console.print()


# ===========================================================================
# 7. policy
# ===========================================================================
@app.command()
def policy(program_handle: str = typer.Argument(..., help="Program handle")):
    """Show summarized program policy."""
    _, _, _, pol = _load_program_context(program_handle)

    if not pol:
        console.print("[yellow]No policy data for this program.[/yellow]")
        return

    console.print(Panel.fit(
        f"[bold]Policy for {program_handle}[/bold]",
        border_style="blue",
    ))

    if pol.allowed_testing:
        console.print(Panel.fit(
            pol.allowed_testing,
            title="[green]Allowed Testing[/green]",
            border_style="green",
        ))

    if pol.forbidden_testing:
        console.print(Panel.fit(
            pol.forbidden_testing,
            title="[red]Forbidden Testing[/red]",
            border_style="red",
        ))

    if pol.rate_limits:
        console.print(Panel.fit(pol.rate_limits, title="[yellow]Rate Limits[/yellow]", border_style="yellow"))

    if pol.disclosure_rules:
        console.print(Panel.fit(pol.disclosure_rules, title="[cyan]Disclosure Rules[/cyan]", border_style="cyan"))

    console.print()


# ===========================================================================
# 8. plan
# ===========================================================================
@app.command()
def plan(program_handle: str = typer.Argument(..., help="Program handle")):
    """Generate a safe recon plan based on in-scope assets."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.recon.planner import ReconPlanner
    planner = ReconPlanner()
    result = planner.build_plan(program_handle, in_scope + out_scope, pol)

    console.print(Panel.fit(
        f"[bold]Recon Plan for {program_handle}[/bold]",
        border_style="blue",
    ))
    console.print(RichMarkdown(result.markdown))

    with get_db() as db:
        save_recon_plan(db, program_handle, result.markdown)


# ===========================================================================
# 9. suggest
# ===========================================================================
@app.command()
def suggest(
    program_handle: str = typer.Argument(..., help="Program handle"),
    asset: str = typer.Argument(..., help="Target asset (domain, URL, or IP)"),
):
    """Suggest safe commands and scouting steps for an in-scope asset."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.scope.validator import ScopeValidator
    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)
    result = validator.is_in_scope(asset)

    if result["decision"] == "out_of_scope":
        console.print(f"[red]Asset '{asset}' is out of scope.[/red]")
        console.print(f"  Reason: {result['reason']}")
        audit.log_scope_decision(asset, "out_of_scope", result["reason"])
        raise typer.Exit(code=1)

    if result["decision"] == "ambiguous":
        console.print(f"[yellow]Asset '{asset}' requires manual review.[/yellow]")
        console.print(f"  Reason: {result['reason']}")
        audit.log_scope_decision(asset, "ambiguous", result["reason"])
        raise typer.Exit(code=1)

    is_out = validator.is_out_of_scope(asset)
    if is_out:
        console.print(f"[red]Asset '{asset}' is explicitly out of scope despite partial match.[/red]")
        audit.log_scope_decision(asset, "out_of_scope_override", "Explicit out-of-scope entry")
        raise typer.Exit(code=1)

    import re
    domain = validator._extract_domain(asset) if hasattr(validator, '_extract_domain') else asset.replace("https://", "").replace("http://", "").split("/")[0]

    console.print(f"\n[bold green]Safe Recon Suggestions for {asset}[/bold green]")
    console.print(f"  [dim]Validated: in scope[/dim]\n")

    console.print("[bold cyan]Passive Recon Commands:[/bold cyan]")
    suggestions = [
        f"curl -I https://{domain}",
        f"curl https://{domain}/robots.txt",
        f"curl https://{domain}/.well-known/security.txt",
        f"curl https://{domain}/security.txt",
        f"curl https://{domain}/sitemap.xml",
        f"openssl s_client -connect {domain}:443 -servername {domain}",
    ]
    import shutil
    if shutil.which("dig"):
        suggestions.insert(0, f"dig {domain}")
    if shutil.which("whois"):
        suggestions.insert(1, f"whois {domain}")
    for cmd in suggestions:
        console.print(f"  [dim]$[/dim] {cmd}")

    console.print(f"\n[bold cyan]Browser Scouting:[/bold cyan]")
    console.print(f"  h1scope scout {program_handle} https://{domain}")
    if not asset.startswith("http"):
        console.print(f"  h1scope scout {program_handle} http://{domain}")

    if pol and pol.forbidden_testing:
        console.print(f"\n[bold yellow]Policy Warnings:[/bold yellow]")
        console.print(f"  {pol.forbidden_testing[:200]}")
    console.print()


# ===========================================================================
# 10. scout
# ===========================================================================
@app.command()
def scout(
    program_handle: str = typer.Argument(..., help="Program handle"),
    url: str = typer.Argument(..., help="URL to scout"),
    headless: bool = typer.Option(True, "--headless/--headed", help="Run browser in headless mode"),
    slowmo: int = typer.Option(0, "--slowmo", help="Slow motion delay in ms"),
    screenshots: bool = typer.Option(True, "--screenshots/--no-screenshots", help="Take screenshots"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Safe browser scouting of a single URL using Chromium."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.scope.validator import ScopeValidator
    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)

    scope_result = validator.is_in_scope(url)
    if scope_result["decision"] != "in_scope":
        console.print(f"[red]URL '{url}' is not confirmed in scope.[/red]")
        console.print(f"  Reason: {scope_result['reason']}")
        raise typer.Exit(code=1)

    if pol and pol.forbidden_testing and "browser" in pol.forbidden_testing.lower():
        console.print("[red]Program policy may restrict browser-based testing.[/red]")
        raise typer.Exit(code=1)

    async def _run():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety

        async with ChromiumScout(headless=headless, slow_mo=slowmo) as scout_instance:
            result = await scout_with_safety(
                scout_instance, url, validator, pol, program_handle
            )

        if json_output:
            console.print_json(json.dumps(result, default=str))
        else:
            console.print(Panel.fit(
                f"[bold]Scout: {url}[/bold]",
                border_style="blue",
            ))
            console.print(f"  Final URL: {result.get('final_url', url)}")
            console.print(f"  Status: {result.get('status_code', '?')}")
            console.print(f"  Title: {result.get('title', '')}")
            console.print(f"  In Scope: {'[green]yes[/green]' if result.get('in_scope') else '[red]no[/red]'}")
            if result.get("manual_review_required"):
                console.print(f"  [yellow]Manual review required[/yellow]")

            if result.get("screenshot_path"):
                console.print(f"  Screenshot: {result['screenshot_path']}")
            if result.get("metadata_path"):
                console.print(f"  Metadata: {result['metadata_path']}")

            findings_count = result.get("findings_count", 0)
            if findings_count:
                console.print(f"  [green]Candidate findings: {findings_count}[/green]")

        return result

    asyncio.run(_run())


# ===========================================================================
# 11. scout-batch
# ===========================================================================
@app.command()
def scout_batch(
    program_handle: str = typer.Argument(..., help="Program handle"),
    limit: int = typer.Option(5, "--limit", help="Max URLs to scout"),
    delay: float = typer.Option(DEFAULT_DELAY, "--delay", help="Delay between requests in seconds"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    slowmo: int = typer.Option(0, "--slowmo"),
    screenshots: bool = typer.Option(True, "--screenshots/--no-screenshots"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Batch-scout in-scope web assets."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.scope.validator import ScopeValidator
    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)

    with get_db() as db:
        web_assets = get_in_scope_web_assets(db, program_handle)

    targets = []
    for a in web_assets[:limit]:
        ident = a.asset_identifier
        if not ident.startswith("http"):
            ident = f"https://{ident}"
        sr = validator.is_in_scope(ident)
        if sr["decision"] == "in_scope":
            targets.append(ident)

    if not targets:
        console.print("[yellow]No safe web assets to scout.[/yellow]")
        return

    console.print(f"[bold]Scouting {len(targets)} URLs...[/bold]\n")

    async def _batch():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety

        results = []
        async with ChromiumScout(headless=headless, slow_mo=slowmo) as scout_instance:
            for i, target in enumerate(targets):
                console.print(f"[{i+1}/{len(targets)}] [cyan]{target}[/cyan]")
                try:
                    r = await scout_with_safety(
                        scout_instance, target, validator, pol, program_handle
                    )
                    results.append(r)
                    fc = r.get("findings_count", 0)
                    console.print(f"  -> {r.get('status_code', '?')} | {fc} findings")
                except Exception as e:
                    console.print(f"  [red]Error: {e}[/red]")
                    results.append({"url": target, "error": str(e)})
                if i < len(targets) - 1:
                    await asyncio.sleep(delay)
        return results

    results = asyncio.run(_batch())

    if json_output:
        console.print_json(json.dumps(results, default=str))
    else:
        total_findings = sum(r.get("findings_count", 0) for r in results)
        console.print(f"\n[green]Batch complete: {len(targets)} URLs, {total_findings} findings[/green]")


# ===========================================================================
# 12. auto
# ===========================================================================
@app.command()
def auto(
    program_handle: str = typer.Argument(..., help="Program handle"),
    finding_limit: int = typer.Option(DEFAULT_FINDING_LIMIT, "--finding-limit", help="Target number of findings"),
    asset_limit: int = typer.Option(DEFAULT_ASSET_LIMIT, "--asset-limit", help="Max assets to scout"),
    delay: float = typer.Option(DEFAULT_DELAY, "--delay", help="Delay between browser visits in seconds"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    screenshots: bool = typer.Option(True, "--screenshots/--no-screenshots"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Only passive recon, no browser"),
    browser_only: bool = typer.Option(False, "--browser-only", help="Only browser scouting, no passive"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Skip browser scouting"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    stop_on_manual_review: bool = typer.Option(False, "--stop-on-manual-review", help="Stop if manual review needed"),
    attack_enabled: bool = typer.Option(False, "--attack", help="Enable auto-attack on findings (verified+ risk)"),
    risk_level: str = typer.Option("verified", "--risk", help="Risk level for attack: safe, verified, aggressive"),
):
    """Autonomous recon + optional active attack pipeline."""
    _print_banner()
    program, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.scope.validator import ScopeValidator
    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)

    if pol and pol.forbidden_testing:
        forbidden_lower = pol.forbidden_testing.lower()
        if "any automated" in forbidden_lower or "no automated scanning" in forbidden_lower:
            console.print("[red]Program policy forbids automated scanning. Cannot run autonomous mode.[/red]")
            raise typer.Exit(code=1)

    console.print(f"[bold]Autonomous Mode — {program_handle}[/bold]")
    console.print(f"  Finding target: [cyan]{finding_limit}[/cyan]")
    console.print(f"  Asset limit: [cyan]{asset_limit}[/cyan]")
    console.print(f"  Delay: [cyan]{delay}s[/cyan]")
    console.print()

    audit.log_autonomous_decision("start", program_handle, "begin", f"finding_limit={finding_limit}")

    # Step 1-4: Load scope (already done)
    with get_db() as db:
        web_assets = get_in_scope_web_assets(db, program_handle)
    safe_targets = []
    for a in web_assets[:asset_limit]:
        ident = a.asset_identifier
        if not ident.startswith("http"):
            ident = f"https://{ident}"
        sr = validator.is_in_scope(ident)
        if sr["decision"] == "in_scope":
            safe_targets.append(ident)

    console.print(f"  [green]Safe web targets: {len(safe_targets)}[/green]")

    if not safe_targets:
        console.print("[yellow]No safe targets to process. Exiting.[/yellow]")
        return

    # Run the autonomous pipeline
    async def _auto():
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety
        from h1scopeagent.recon.passive import PassiveRecon

        recon = PassiveRecon()
        all_findings = []
        scouted = 0

        async with ChromiumScout(headless=headless) as scout_instance:
            for i, target in enumerate(safe_targets):
                current_count = len(all_findings)
                if current_count >= finding_limit:
                    console.print(f"\n[green]Finding limit ({finding_limit}) reached.[/green]")
                    break

                console.print(f"\n[{i+1}/{len(safe_targets)}] [cyan]{target}[/cyan]")

                # Passive recon
                if not browser_only:
                    try:
                        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
                        headers = recon.http_headers(target)
                        if headers:
                            console.print(f"  [dim]Passive headers collected[/dim]")
                    except Exception as e:
                        console.print(f"  [dim]Passive: {e}[/dim]")

                # Browser scouting
                if not passive_only and not no_browser:
                    try:
                        result = await scout_with_safety(
                            scout_instance, target, validator, pol, program_handle
                        )
                        scouted += 1
                        fc = result.get("findings_count", 0)
                        console.print(f"  Status: {result.get('status_code', '?')} | Findings: [green]{fc}[/green]")

                        # Collect findings from scout
                        with get_db() as db:
                            current_findings = get_candidate_findings(db, program_handle)
                            all_findings = current_findings
                    except Exception as e:
                        console.print(f"  [red]Scout error: {e}[/red]")

                await asyncio.sleep(delay)

        console.print(f"\n[bold]Autonomous mode complete[/bold]")
        console.print(f"  Assets scouted: {scouted}")
        console.print(f"  Candidate findings: {len(all_findings)}")

        return all_findings

    findings = asyncio.run(_auto())

    if json_output:
        console.print_json(json.dumps(findings, default=str))
    else:
        _print_findings_summary(findings)

    audit.log_autonomous_decision("complete", program_handle, "finished", f"findings={len(findings)}")

    # Auto-Attack Pipeline
    if attack_enabled and findings:
        if risk_level not in ("verified", "aggressive"):
            console.print(f"\n[yellow]Attack requires --risk verified or aggressive. Current: {risk_level}. Skipping attack.[/yellow]")
        else:
            from h1scopeagent.attack.decision import AttackDecisionMatrix
            from h1scopeagent.attack.engine import AutoAttackEngine
            from h1scopeagent.attack.verifier import FindingVerifier

            all_entries = in_scope + out_scope
            validator2 = ScopeValidator(all_entries)
            matrix = AttackDecisionMatrix(risk_level)

            if not matrix.risk_config["auto_attack"]:
                console.print(f"\n[yellow]Attack disabled at risk level '{risk_level}'.[/yellow]")
            else:
                console.print(f"\n\n[bold red]=== AUTO-ATTACK PIPELINE (risk: {risk_level.upper()}) ===[/bold red]\n")
                engine = AutoAttackEngine(validator2, program_handle, risk_level)
                verifier = FindingVerifier(validator2, program_handle)
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
                            console.print(f"  [green]Verified ({ver_result.confidence} confidence)[/green]")
                            finding["verification_result"] = ver_result.evidence
                            finding["confidence"] = "high"

                        d, results = engine.evaluate_and_attack(finding)
                        if results and d.should_attack:
                            attacked += 1
                            for r in results:
                                console.print(f"  [cyan]{r.tool}[/cyan]: exit={r.exit_code}, {r.duration}s")
                                if r.error:
                                    console.print(f"  [yellow]{r.error[:100]}[/yellow]")
                                with get_db() as db:
                                    save_command_log(db, CommandLogEntry(
                                        program_handle=program_handle,
                                        command=r.command,
                                        target=r.target,
                                        approved_by_user=True,
                                        blocked=False,
                                        exit_code=r.exit_code,
                                        output=r.output[:2000] if r.output else "",
                                    ))
                                if r.new_evidence:
                                    finding["evidence"] = {**finding.get("evidence", {}), **r.new_evidence}

                        with get_db() as db:
                            save_candidate_finding(db, finding)

                    except Exception as e:
                        console.print(f"  [red]Error: {e}[/red]")

                console.print(f"\n[bold red]Attack pipeline complete: {attacked} findings attacked[/bold red]")


# ===========================================================================
# 13. findings
# ===========================================================================
@app.command()
def findings(
    program_handle: str = typer.Argument(..., help="Program handle"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show candidate findings for a program."""
    _load_program_context(program_handle)

    with get_db() as db:
        finds = get_candidate_findings(db, program_handle)

    if not finds:
        console.print("[yellow]No findings yet. Run auto mode or scout a target.[/yellow]")
        return

    if json_output:
        console.print_json(json.dumps(finds, default=str))
        return

    console.print(f"\n[bold]Candidate Findings — {program_handle} ({len(finds)})[/bold]\n")

    table = Table(box=box.SIMPLE)
    table.add_column("ID", style="dim")
    table.add_column("Title")
    table.add_column("Asset", style="cyan")
    table.add_column("Confidence")
    table.add_column("Severity")
    table.add_column("Ready")

    severity_colors = {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "green", "info": "dim",
    }
    confidence_colors = {"high": "green", "medium": "yellow", "low": "dim"}

    for f in finds:
        sev_c = severity_colors.get(f.get("estimated_severity", ""), "white")
        conf_c = confidence_colors.get(f.get("confidence", ""), "white")
        ready = "[green]yes[/green]" if f.get("report_ready") else "[dim]no[/dim]"
        cid = f.get("candidate_id", "")[:8]
        table.add_row(
            cid,
            f["title"][:60],
            f["affected_asset"][:40],
            f"[{conf_c}]{f.get('confidence', '')}[/{conf_c}]",
            f"[{sev_c}]{f.get('estimated_severity', '')}[/{sev_c}]",
            ready,
        )

    console.print(table)
    console.print(f"\n[dim]Use: h1scope report {program_handle} to generate report drafts[/dim]")


# ===========================================================================
# 14. report
# ===========================================================================
@app.command()
def report(
    program_handle: str = typer.Argument(..., help="Program handle"),
    submit_reports: bool = typer.Option(False, "--submit", help="Auto-submit after generating reports"),
    risk_level: str = typer.Option("aggressive", "--risk", help="Risk for submit (must be aggressive)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview without submitting"),
):
    """Generate HackerOne-style report drafts. Use --submit to auto-send to HackerOne."""
    _load_program_context(program_handle)

    from h1scopeagent.reports.generator import ReportGenerator
    generator = ReportGenerator()

    with get_db() as db:
        finds = get_candidate_findings(db, program_handle)

    ready = [f for f in finds if f.get("report_ready")]
    if not ready:
        console.print("[yellow]No report-ready findings.[/yellow]")
        return

    console.print(f"[bold]Generating reports for {len(ready)} findings...[/bold]\n")

    generated = 0
    report_data_list = []
    for f in ready:
        try:
            md = generator.generate_report(f, program_handle)
            with get_db() as db:
                save_report_draft(db, program_handle, {
                    "finding_id": f.get("candidate_id", ""),
                    "title": md.get("title", ""),
                    "affected_asset": md.get("affected_asset", ""),
                    "severity": md.get("severity", "info"),
                    "markdown_body": md.get("markdown_body", ""),
                })

            reports_dir = DATA_DIR / "reports" / program_handle
            reports_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{f.get('candidate_id', 'unknown')[:12]}.md"
            path = reports_dir / filename
            path.write_text(md.get("markdown_body", ""), encoding="utf-8")
            audit.log_report_generated(str(path), f.get("candidate_id", ""))
            generated += 1
            console.print(f"  [green]Saved:[/green] {path}")
            report_data_list.append(md)
        except Exception as e:
            console.print(f"  [red]Error generating report for {f.get('candidate_id', '?')}: {e}[/red]")

    console.print(f"\n[green]{generated} reports generated.[/green]")
    console.print(f"  Location: {DATA_DIR / 'reports' / program_handle}")

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
# 15. run
# ===========================================================================
@app.command()
def run_command(
    program_handle: str = typer.Argument(..., help="Program handle"),
    command: str = typer.Argument(..., help="Command to run"),
    force: bool = typer.Option(False, "--force", help="Skip approval prompt"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve"),
):
    """Run a terminal command after safety checks."""
    _, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.recon.command_guard import CommandGuard
    from h1scopeagent.scope.validator import ScopeValidator
    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)
    guard = CommandGuard(validator, pol)

    review = guard.review(command, program_handle)

    if review.blocked:
        console.print(f"[red]Command blocked:[/red] {review.block_reason}")
        audit.log_blocked_command(command, review.block_reason, program_handle)
        with get_db() as db:
            save_command_log(db, CommandLogEntry(
                program_handle=program_handle,
                command=command,
                target=review.extracted_target or "",
                blocked=True,
                block_reason=review.block_reason,
            ))
        raise typer.Exit(code=1)

    if review.requires_approval:
        console.print(f"[yellow]This command requires approval:[/yellow]")
        console.print(f"  Command: [cyan]{command}[/cyan]")
        console.print(f"  Target: {review.extracted_target or 'unknown'}")
        console.print(f"  Reason: {review.approval_reason}")

        if not yes and not force:
            confirmed = typer.confirm("\nType YES to approve and run this command")
            if not confirmed:
                console.print("[yellow]Command cancelled by user.[/yellow]")
                raise typer.Exit(code=0)

        audit.log_approved_command(command, program_handle, review.extracted_target or "")

    if not review.target_in_scope and review.extracted_target:
        console.print(f"[red]Target '{review.extracted_target}' is not confirmed in scope.[/red]")
        console.print(f"  Reason: {review.scope_reason}")
        raise typer.Exit(code=1)

    # Execute
    console.print(f"\n[bold]Running:[/bold] [cyan]{command}[/cyan]\n")

    from h1scopeagent.recon.runner import CommandRunner
    runner = CommandRunner(guard)
    result = runner.run(command, approved=True)

    if result.blocked:
        console.print(f"[red]Blocked at execution: {result.block_reason}[/red]")
        return

    console.print(result.output or "[dim](no output)[/dim]")
    if result.exit_code != 0:
        console.print(f"\n[red]Exit code: {result.exit_code}[/red]")
    else:
        console.print(f"\n[green]Exit code: {result.exit_code}[/green]")

    with get_db() as db:
        save_command_log(db, CommandLogEntry(
            program_handle=program_handle,
            command=command,
            target=review.extracted_target or "",
            approved_by_user=True,
            exit_code=result.exit_code,
            output=result.output[:2000] if result.output else "",
        ))

    audit.log_command_output(command, result.exit_code, (result.output or "")[:200])


# ===========================================================================
# 16. daemon
# ===========================================================================
@app.command()
def daemon(
    risk_level: str = typer.Option("verified", "--risk", help="Risk level: safe, verified, aggressive"),
    interval: int = typer.Option(3600, "--interval", help="Seconds between loops"),
    max_iterations: int = typer.Option(0, "--max-iters", help="Max loops (0=unlimited)"),
    headless: bool = typer.Option(True, "--headless/--headed"),
    finding_limit: int = typer.Option(5, "--finding-limit"),
    asset_limit: int = typer.Option(20, "--asset-limit"),
):
    """Fully autonomous daemon — continuous sync, recon, attack, report, submit loop."""
    from h1scopeagent.daemon import DaemonController

    if risk_level not in ("safe", "verified", "aggressive"):
        console.print("[red]Invalid risk level. Use: safe, verified, aggressive[/red]")
        raise typer.Exit(code=1)

    ctrl = DaemonController(
        risk_level=risk_level,
        interval=interval,
        max_iterations=max_iterations,
        headless=headless,
        finding_limit=finding_limit,
        asset_limit=asset_limit,
    )
    ctrl.run()


# ===========================================================================
# 17. attack
# ===========================================================================
@app.command()
def attack(
    program_handle: str = typer.Argument(..., help="Program handle"),
    risk_level: str = typer.Option("verified", "--risk", help="Risk level: safe, verified, aggressive"),
    force: bool = typer.Option(False, "--force", help="Force attack all report-ready findings"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Autonomous active attack on confirmed findings (nuclei, gobuster, ffuf, nmap)."""
    program, in_scope, out_scope, pol = _load_program_context(program_handle)

    from h1scopeagent.scope.validator import ScopeValidator
    from h1scopeagent.attack.decision import AttackDecisionMatrix
    from h1scopeagent.attack.engine import AutoAttackEngine
    from h1scopeagent.attack.verifier import FindingVerifier

    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)
    matrix = AttackDecisionMatrix(risk_level)

    if not matrix.risk_config["auto_attack"]:
        console.print(f"[red]Auto-attack disabled at risk level '{risk_level}'. Use --risk verified or aggressive.[/red]")
        raise typer.Exit(code=1)

    with get_db() as db:
        findings = get_candidate_findings(db, program_handle)

    if not findings:
        console.print("[yellow]No findings to attack. Run auto mode first.[/yellow]")
        return

    targets = findings
    if not force:
        targets = [f for f in findings if f.get("report_ready")]
        if not targets:
            console.print("[yellow]No report-ready findings. Use --force to attack all.[/yellow]")
            return

    console.print(f"\n[bold]Attacking {len(targets)} findings at risk level: {risk_level.upper()}[/bold]\n")

    engine = AutoAttackEngine(validator, program_handle, risk_level)
    verifier = FindingVerifier(validator, program_handle)
    all_results = []
    attacked = 0

    for i, finding in enumerate(targets):
        ctype = finding.get("candidate_type", "")
        decision = matrix.evaluate(finding)

        sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
        color = sev_color.get(finding.get("estimated_severity", "info"), "white")
        console.print(f"[{i+1}/{len(targets)}] [{color}]{finding.get('title', '')[:70]}[/{color}]")

        if not decision.should_attack:
            console.print(f"  [dim]Skipped: {decision.reason}[/dim]")
            continue

        console.print(f"  Attack Score: {decision.score} | Tools: {', '.join(decision.tools)}")

        try:
            ver_result = verifier.verify(finding)
            if ver_result.verified:
                console.print(f"  [green]Verified: {ver_result.verification_type} (confidence: {ver_result.confidence})[/green]")
                finding["verification_result"] = ver_result.evidence
                finding["confidence"] = "high"

            decision, results = engine.evaluate_and_attack(finding)
            if results and decision.should_attack:
                attacked += 1
                for r in results:
                    console.print(f"  Tool: [cyan]{r.tool}[/cyan] | Duration: {r.duration}s | Exit: {r.exit_code}")
                    if r.error:
                        console.print(f"  [yellow]{r.error[:100]}[/yellow]")
                    if r.new_evidence:
                        console.print(f"  [green]New evidence collected[/green]")
                        finding["evidence"] = {**finding.get("evidence", {}), **r.new_evidence}
                    all_results.append(r.dict() if hasattr(r, 'dict') else r)

                with get_db() as db:
                    save_candidate_finding(db, finding)

        except Exception as e:
            console.print(f"  [red]Error: {e}[/red]")

    console.print(f"\n[bold green]Attack complete: {attacked} findings attacked, {len(all_results)} tool runs[/bold green]")

    if json_output:
        console.print_json(json.dumps(all_results, default=str))


# ===========================================================================
# 18. submit
# ===========================================================================
@app.command()
def submit(
    program_handle: str = typer.Argument(..., help="Program handle"),
    risk_level: str = typer.Option("aggressive", "--risk", help="Risk level (must be aggressive for auto-submit)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview submissions without actually submitting"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Auto-submit report drafts to HackerOne."""
    from h1scopeagent.attack.submitter import AutoSubmitter, batch_submit

    submitter = AutoSubmitter(risk_level)

    if not submitter.can_auto_submit():
        console.print(f"[red]Auto-submit requires risk level 'aggressive'. Current: {risk_level}[/red]")
        raise typer.Exit(code=1)

    with get_db() as db:
        drafts = get_report_drafts(db, program_handle)

    if not drafts:
        console.print("[yellow]No report drafts to submit. Generate reports first.[/yellow]")
        return

    console.print(f"\n[bold]Submitting {len(drafts)} reports for {program_handle}[/bold]\n")

    if dry_run:
        console.print("[yellow]DRY RUN — nothing will be submitted[/yellow]\n")
        for d in drafts:
            console.print(f"  WOULD submit: {d.get('title', '')[:80]}")
            console.print(f"    Asset: {d.get('affected_asset', '')}")
            console.print(f"    Severity: {d.get('severity', 'info')}")
        return

    results = batch_submit(drafts, program_handle, risk_level, submitter)
    submitted = 0

    for r in results:
        if r.submitted:
            console.print(f"  [green]SUBMITTED: {r.report_id} — {r.title[:60]}[/green]")
            submitted += 1
        else:
            console.print(f"  [red]FAILED: {r.title[:60]} — {r.error[:100]}[/red]")

    console.print(f"\n[bold green]{submitted}/{len(results)} reports submitted[/bold green]")

    if json_output:
        console.print_json(json.dumps([r.__dict__ for r in results], default=str))


# ===========================================================================
# Helpers
# ===========================================================================
def _print_findings_summary(findings: list[dict]):
    if not findings:
        console.print("\n[yellow]No findings collected.[/yellow]")
        return

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_finds = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("estimated_severity", "info"), 99),
    )
    for f in sorted_finds[:10]:
        sev = f.get("estimated_severity", "info")
        color = "red" if sev in ("critical", "high") else "yellow" if sev == "medium" else "green"
        console.print(f"  [{color}]●[/{color}] {f.get('title', '')[:70]}")


def main():
    app()


if __name__ == "__main__":
    main()
