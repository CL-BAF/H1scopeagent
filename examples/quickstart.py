#!/usr/bin/env python3
"""Quickstart example — run H1ScopeAgent on a single program end-to-end.

Usage:
    python examples/quickstart.py

Prerequisites:
    - pip install -e .
    - .env with HACKERONE_USERNAME and HACKERONE_TOKEN
    - playwright install chromium
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from h1scopeagent.api.hackerone import HackerOneClient
from h1scopeagent.db.database import init_db, get_db, upsert_program, upsert_scopes, upsert_policy, get_programs
from h1scopeagent.db.models import Program, ScopeEntry, PolicyRecord
from h1scopeagent.scope.validator import ScopeValidator
from h1scopeagent.policy.summarizer import PolicySummarizer
from h1scopeagent.browser.chromium import ChromiumScout
from h1scopeagent.browser.scout import scout_with_safety
from rich.console import Console

console = Console()


def sync_program(handle: str):
    console.print(f"[cyan]Syncing program: {handle}[/cyan]")
    init_db()

    with HackerOneClient() as client:
        programs = client.get_programs()
        target = next((p for p in programs if p["handle"] == handle), None)

        if not target:
            console.print(f"[red]Program '{handle}' not found[/red]")
            return None

        with get_db() as db:
            upsert_program(db, Program(
                handle=target["handle"],
                name=target.get("name", ""),
                state=target.get("state", ""),
                offers_bounties=target.get("offers_bounties", False),
            ))

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

            policy_text = client.get_policy(handle)
            if policy_text:
                summary = PolicySummarizer().summarize(policy_text)
                upsert_policy(db, handle, PolicyRecord(
                    program_handle=handle,
                    raw_policy_text=policy_text,
                    summary=summary.get("summary", ""),
                    allowed_testing=summary.get("allowed_testing", ""),
                    forbidden_testing=summary.get("forbidden_testing", ""),
                    rate_limits=summary.get("rate_limits", ""),
                    disclosure_rules=summary.get("disclosure_rules", ""),
                ))

    console.print(f"[green]Synced {handle} successfully[/green]")
    return handle


async def scout_program(handle: str):
    console.print(f"[cyan]Scouting in-scope targets for: {handle}[/cyan]")

    with get_db() as db:
        program = [p for p in get_programs(db) if p.handle == handle]
        if not program:
            console.print("[red]Program not synced[/red]")
            return

        from h1scopeagent.db.database import get_scopes, get_policy, get_in_scope_web_assets
        in_scope, out_scope = get_scopes(db, handle)
        policy = get_policy(db, handle)
        web_assets = get_in_scope_web_assets(db, handle)

    all_entries = in_scope + out_scope
    validator = ScopeValidator(all_entries)

    targets = []
    for a in web_assets[:5]:
        ident = a.asset_identifier
        if not ident.startswith("http"):
            ident = f"https://{ident}"
        sr = validator.is_in_scope(ident)
        if sr["decision"] == "in_scope":
            targets.append(ident)

    console.print(f"  [green]{len(targets)} safe targets found[/green]")

    async with ChromiumScout(headless=True) as scout_instance:
        for target in targets:
            console.print(f"  Scouting: {target}")
            try:
                result = await scout_with_safety(
                    scout_instance, target, validator, policy, handle
                )
                fc = result.get("findings_count", 0)
                console.print(f"    Status: {result.get('status_code', '?')} | Findings: {fc}")
            except Exception as e:
                console.print(f"    [red]Error: {e}[/red]")

    with get_db() as db:
        from h1scopeagent.db.database import get_candidate_findings
        findings = get_candidate_findings(db, handle)

    console.print(f"\n[bold green]Total findings: {len(findings)}[/bold green]")
    for f in findings:
        console.print(f"  [{f.get('estimated_severity', 'info')}] {f.get('title', '')}")
    return findings


def generate_reports(handle: str, findings: list):
    from h1scopeagent.reports.generator import ReportGenerator
    from h1scopeagent.config import DATA_DIR
    generator = ReportGenerator()

    report_ready = [f for f in findings if f.get("report_ready")]
    console.print(f"[cyan]Generating reports for {len(report_ready)} report-ready findings[/cyan]")

    for f in report_ready:
        md = generator.generate_report(f, handle)
        reports_dir = DATA_DIR / "reports" / handle
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{f.get('candidate_id', 'unknown')[:12]}.md"
        path.write_text(md.get("markdown_body", ""), encoding="utf-8")
        console.print(f"  [green]Saved: {path}[/green]")


async def main():
    program_handle = input("Enter HackerOne program handle: ").strip()
    if not program_handle:
        console.print("[red]No handle provided[/red]")
        return

    sync_program(program_handle)
    findings = await scout_program(program_handle)
    if findings:
        generate_reports(program_handle, findings)

    console.print("\n[bold green]Quickstart complete![/bold green]")


if __name__ == "__main__":
    asyncio.run(main())
