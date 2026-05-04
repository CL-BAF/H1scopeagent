"""Daemon — continuous autonomous HackerOne bot loop."""

from __future__ import annotations

import asyncio
import signal
import time
from datetime import datetime, timezone
from typing import Any

from h1scopeagent.config import (
    DAEMON_LOOP_INTERVAL, DAEMON_MAX_ITERATIONS, RISK_LEVEL, RISK_LEVELS,
    get_settings, load_profile, AUTO_ATTACK_TOOLS, AUTO_ATTACK_TOOL_TIMEOUTS,
)
from h1scopeagent.logs.audit import AuditLogger
from h1scopeagent.db.database import (
    get_db, init_db, get_programs, get_scopes, get_policy,
    get_in_scope_web_assets, get_candidate_findings, count_candidate_findings,
    save_candidate_finding, save_report_draft, get_report_drafts, save_command_log,
)
from h1scopeagent.api.hackerone import HackerOneClient
from h1scopeagent.scope.validator import ScopeValidator


class DaemonController:
    """Continuous autonomous HackerOne Bot."""

    def __init__(
        self,
        risk_level: str | None = None,
        profile: str = "default",
        interval: int = DAEMON_LOOP_INTERVAL,
        max_iterations: int = DAEMON_MAX_ITERATIONS,
        headless: bool = True,
        workers: int = 2,
    ):
        self._risk_level = risk_level or RISK_LEVEL
        self._risk_config = RISK_LEVELS.get(self._risk_level, RISK_LEVELS["verified"])
        self._profile_name = profile
        self._profile = load_profile(profile)
        self._interval = interval
        self._max_iterations = max_iterations
        self._auto_submit = self._risk_config.get("submit_enabled", False)
        self._headless = headless
        self._workers = workers
        self._running = True
        self._iteration = 0
        self._audit = AuditLogger()
        self._stats: dict[str, Any] = {
            "started": datetime.now(timezone.utc).isoformat(),
            "iterations": 0, "findings_total": 0, "attacks_launched": 0,
            "reports_generated": 0, "reports_submitted": 0, "errors": 0,
        }
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print("\n[yellow]Daemon shutting down gracefully...[/yellow]")
        self._running = False

    def run(self):
        print("=" * 60)
        print(f"  H1ScopeAgent Daemon — Fully Automated HackerOne Bot")
        print(f"  Risk: {self._risk_level.upper()} | Profile: {self._profile_name}")
        print(f"  Attack: {self._risk_config.get('attack_enabled', False)}")
        print(f"  Submit: {self._auto_submit}")
        print(f"  Interval: {self._interval}s | Max Iters: {self._max_iterations or 'unlimited'}")
        print("=" * 60)

        self._audit.log_autonomous_decision("daemon_start", "all", "begin",
            f"risk={self._risk_level},profile={self._profile_name}")

        init_db()

        while self._running:
            self._iteration += 1
            if self._max_iterations > 0 and self._iteration > self._max_iterations:
                print(f"\n[green]Max iterations ({self._max_iterations}) reached.[/green]")
                break

            print(f"\n{'=' * 40}")
            print(f"  Loop #{self._iteration} — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'=' * 40}")

            try:
                asyncio.run(self._run_iteration())
            except Exception as e:
                print(f"  [red]Loop error: {e}[/red]")
                self._audit.log_error("daemon_loop", str(e))

            self._stats["iterations"] = self._iteration
            if self._running:
                for _ in range(min(self._interval, 60)):
                    if not self._running:
                        break
                    time.sleep(1)
                if self._interval > 60 and self._running:
                    time.sleep(self._interval - 60)

        self._print_summary()

    async def _run_iteration(self):
        if not get_settings().has_credentials:
            print("  [red]No credentials. Skipping.[/red]")
            return

        with get_db() as db:
            programs = get_programs(db)
        if not programs:
            self._sync_programs()
            with get_db() as db:
                programs = get_programs(db)
        if not programs:
            return

        for prog in programs[:5]:
            if not self._running:
                break
            handle = prog.get("handle", "")
            print(f"\n  [cyan]Processing: {handle}[/cyan]")
            try:
                await self._process_program(handle)
            except Exception as e:
                print(f"    [red]{e}[/red]")
                self._stats["errors"] += 1

    async def _process_program(self, handle: str):
        with get_db() as db:
            program = ([p for p in get_programs(db) if p.get("handle") == handle] or [None])[0]
            if not program:
                return
            in_scope, out_scope = get_scopes(db, handle)
            policy = get_policy(db, handle)

        all_entries = in_scope + out_scope
        validator = ScopeValidator(all_entries)

        with get_db() as db:
            web_assets = get_in_scope_web_assets(db, handle)

        safe_targets = []
        for a in web_assets[:self._profile.asset_limit]:
            ident = a.get("asset_identifier", "")
            if not ident.startswith("http"):
                ident = f"https://{ident}"
            if validator.is_in_scope(ident)["decision"] == "in_scope":
                safe_targets.append(ident)

        if not safe_targets:
            return

        print(f"    Scouting {len(safe_targets)} targets...")
        from h1scopeagent.browser.chromium import ChromiumScout
        from h1scopeagent.browser.scout import scout_with_safety

        async with ChromiumScout(headless=self._headless) as scout:
            for target in safe_targets:
                if not self._running:
                    break
                try:
                    await scout_with_safety(scout, target, validator, policy, handle)
                except Exception as e:
                    print(f"      Scout error {target}: {e}")

        with get_db() as db:
            findings = get_candidate_findings(db, handle)

        if not findings:
            return

        print(f"    Found {len(findings)} findings")
        self._stats["findings_total"] += len(findings)

        if self._profile.attack_enabled and self._risk_config.get("attack_enabled"):
            await self._attack_findings(findings, handle, validator)

        report_ready = [f for f in findings if f.get("report_ready")]
        if report_ready:
            self._generate_reports(report_ready, handle)

        if self._auto_submit and report_ready:
            self._submit_reports(handle)

    async def _attack_findings(self, findings: list[dict], handle: str, validator):
        from h1scopeagent.attack.decision import AttackDecisionMatrix
        from h1scopeagent.attack.engine import AutoAttackEngine
        from h1scopeagent.attack.verifier import FindingVerifier

        matrix = AttackDecisionMatrix(self._risk_level)
        engine = AutoAttackEngine(validator, handle, self._risk_level)
        verifier = FindingVerifier(validator, handle)

        for finding in findings:
            if not self._running:
                break
            ctype = finding.get("candidate_type", "")
            if ctype in ("secret_leakage", "console_errors", "source_maps"):
                continue

            decision = matrix.evaluate(finding)
            if not decision.should_attack:
                continue

            print(f"      [cyan]Attacking: {finding.get('title', '')[:60]}[/cyan]")
            try:
                ver_result = verifier.verify(finding)
                if ver_result.verified:
                    finding["verification_result"] = ver_result.evidence
                    finding["confidence"] = "high"
                d, results = engine.evaluate_and_attack(finding)
                if results and d.should_attack:
                    self._stats["attacks_launched"] += 1
                    for r in results:
                        with get_db() as db:
                            save_command_log(db, {
                                "program_handle": handle, "command": r.command,
                                "target": r.target, "exit_code": r.exit_code,
                                "output": r.output[:2000] if r.output else "",
                            })
                        if r.new_evidence:
                            finding["evidence"] = {**finding.get("evidence", {}), **r.new_evidence}
                with get_db() as db:
                    save_candidate_finding(db, finding)
            except Exception as e:
                print(f"        [red]{e}[/red]")

    def _generate_reports(self, report_ready: list[dict], handle: str):
        from h1scopeagent.reports.generator import ReportGenerator
        generator = ReportGenerator()
        for f in report_ready[:10]:
            try:
                md = generator.generate_report(f, handle)
                with get_db() as db:
                    save_report_draft(db, handle, {
                        "finding_id": f.get("candidate_id", ""),
                        "title": md.get("title", ""),
                        "affected_asset": md.get("affected_asset", ""),
                        "severity": md.get("severity", "info"),
                        "markdown_body": md.get("markdown_body", ""),
                    })
                self._stats["reports_generated"] += 1
            except Exception as e:
                print(f"      [red]Report error: {e}[/red]")

    def _submit_reports(self, handle: str):
        from h1scopeagent.attack.submitter import AutoSubmitter
        submitter = AutoSubmitter(self._risk_level)
        with get_db() as db:
            drafts = get_report_drafts(db, handle)
        for draft in drafts[-5:]:
            if not self._running:
                break
            result = submitter.submit(draft, handle)
            if result.submitted:
                print(f"      [green]Submitted: {result.report_id} — {result.title[:50]}[/green]")
                self._stats["reports_submitted"] += 1
            else:
                print(f"      [yellow]Submit: {result.error[:100]}[/yellow]")

    def _sync_programs(self):
        if not get_settings().has_credentials:
            return
        with HackerOneClient() as client:
            programs = client.get_programs()
            with get_db() as db:
                from h1scopeagent.db.database import upsert_program, upsert_scopes, upsert_policy
                for prog in programs:
                    handle = prog.get("handle", "")
                    upsert_program(db, prog)
                    try:
                        scopes_raw = client.get_structured_scopes(handle)
                        scope_entries = []
                        for sr in scopes_raw:
                            conf = sr.get("confidentiality", "")
                            scope_entries.append({
                                "asset_identifier": sr.get("asset_identifier", ""),
                                "asset_type": sr.get("asset_type", ""),
                                "eligible_for_bounty": sr.get("eligible_for_bounty", False),
                                "eligible_for_submission": sr.get("eligible_for_submission", False),
                                "max_severity": sr.get("max_severity", ""),
                                "instruction": sr.get("instruction", ""),
                                "in_scope": not (conf and "out_of_scope" in conf.lower()),
                            })
                        upsert_scopes(db, handle, scope_entries)
                    except Exception:
                        pass
                    try:
                        from h1scopeagent.policy.summarizer import PolicySummarizer
                        policy_text = client.get_policy(handle)
                        if policy_text:
                            r = PolicySummarizer().summarize(policy_text)
                            upsert_policy(db, handle, {
                                "program_handle": handle, "raw_policy_text": policy_text,
                                "summary": r.get("summary", ""),
                                "allowed_testing": r.get("allowed_testing", ""),
                                "forbidden_testing": r.get("forbidden_testing", ""),
                                "rate_limits": r.get("rate_limits", ""),
                                "disclosure_rules": r.get("disclosure_rules", ""),
                            })
                    except Exception:
                        pass

    def _print_summary(self):
        print("\n" + "=" * 60)
        print(f"  Daemon Complete — {self._risk_level.upper()}")
        s = self._stats
        print(f"  Iters: {s['iterations']} | Findings: {s['findings_total']}")
        print(f"  Attacks: {s['attacks_launched']} | Reports: {s['reports_generated']}")
        print(f"  Submitted: {s['reports_submitted']} | Errors: {s['errors']}")
        print("=" * 60)
