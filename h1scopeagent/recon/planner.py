"""Reconnaissance plan generator.

Creates a structured markdown plan from scope entries and policy,
categorizing steps as safe, approval-required, or forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from h1scopeagent.db.models import ScopeEntry, PolicyRecord


@dataclass
class ReconPlanResult:
    targets: list[str] = field(default_factory=list)
    safe_steps: list[str] = field(default_factory=list)
    approval_required_steps: list[str] = field(default_factory=list)
    forbidden_steps: list[str] = field(default_factory=list)
    rate_limit_notes: str = ""
    estimated_risk: str = "low"
    policy_notes: str = ""
    markdown: str = ""


class ReconPlanner:
    """Build a safe recon plan from scope entries and program policy."""

    def build_plan(
        self,
        program_handle: str,
        all_scope_entries: list[ScopeEntry],
        policy: PolicyRecord | None,
    ) -> ReconPlanResult:
        in_scope = [s for s in all_scope_entries if s.in_scope]
        out_scope = [s for s in all_scope_entries if not s.in_scope]

        result = ReconPlanResult()

        # Targets: only web-accessible in-scope assets
        web_types = {"url", "domain", "web", "wildcard_domain"}
        for s in in_scope:
            if s.asset_type.lower() in web_types:
                ident = s.asset_identifier
                if ident.startswith("http"):
                    result.targets.append(ident)
                elif not ident.startswith("com.") and not ident.startswith("org."):
                    result.targets.append(f"https://{ident}")
                    result.targets.append(f"http://{ident}")
        result.targets = list(dict.fromkeys(result.targets))

        # Safe steps
        result.safe_steps = [
            "Fetch program scope and policy data",
            "Validate all targets against scope",
            "Passive DNS resolution per target",
            "WHOIS lookups",
            "HTTP header checks (HEAD requests)",
            "Fetch robots.txt, security.txt, sitemap.xml",
            "TLS certificate inspection",
            "Non-invasive browser scouting (screenshots only)",
            "Security header analysis",
            "Cookie name collection (no values)",
            "Form discovery without submission",
            "Console error collection",
        ]

        # Approval-required steps
        result.approval_required_steps = [
            "nmap service version scans (-sV, -A)",
            "Directory brute forcing (gobuster, dirsearch, ffuf)",
            "Nikto web server scans",
            "Nuclei template scans",
            "Any POST/PUT/PATCH/DELETE requests",
            "Authenticated browser sessions",
            "Any form interaction or submission",
            "Suspicious endpoint probing",
        ]

        # Forbidden
        result.forbidden_steps = [
            "Any exploitation",
            "SQL injection exploitation",
            "XSS payload injection",
            "Authentication bypass attempts",
            "Brute force / credential stuffing",
            "Denial of service testing",
            "Malware or phishing",
            "Data exfiltration",
            "Submitting forms automatically",
            "Destructive browser actions",
            "Any action targeting out-of-scope infrastructure",
        ]

        # Policy notes
        if policy:
            if policy.forbidden_testing:
                result.forbidden_steps.append(f"Policy-specific: {policy.forbidden_testing[:200]}")
            if policy.rate_limits:
                result.rate_limit_notes = policy.rate_limits
            if policy.disclosure_rules:
                result.policy_notes = policy.disclosure_rules

        if not result.rate_limit_notes:
            result.rate_limit_notes = "Conservative default: 1 request/second, 3-second delay between browser visits"

        # Risk estimation
        if out_scope:
            result.estimated_risk = "medium"
        else:
            result.estimated_risk = "low"

        if policy and policy.forbidden_testing:
            result.estimated_risk = "medium"

        # Build markdown
        result.markdown = self._render_markdown(program_handle, result)

        return result

    def _render_markdown(self, program_handle: str, plan: ReconPlanResult) -> str:
        lines = [
            f"# Recon Plan: {program_handle}",
            "",
            f"**Estimated Risk:** {plan.estimated_risk}",
            f"**Rate Limits:** {plan.rate_limit_notes[:300]}",
            "",
            "---",
            "",
        ]

        if plan.targets:
            lines.append("## In-Scope Targets\n")
            for t in plan.targets[:30]:
                lines.append(f"- {t}")
            lines.append("")

        lines.append("## Safe Autonomous Steps\n")
        for s in plan.safe_steps:
            lines.append(f"- {s}")
        lines.append("")

        lines.append("## Approval-Required Steps\n")
        for s in plan.approval_required_steps:
            lines.append(f"- {s}")
        lines.append("")

        lines.append("## Forbidden Steps\n")
        for s in plan.forbidden_steps:
            lines.append(f"- {s}")
        lines.append("")

        if plan.policy_notes:
            lines.append(f"## Policy Notes\n\n{plan.policy_notes}\n")

        lines.append("## Recommended Workflow\n")
        lines.append("```bash")
        lines.append(f"h1scope auto {program_handle} --finding-limit 5 --screenshots")
        lines.append(f"h1scope findings {program_handle}")
        lines.append(f"h1scope report {program_handle}")
        lines.append("```")

        return "\n".join(lines)
