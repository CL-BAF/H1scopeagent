"""Policy text summarizer for H1ScopeAgent.

Parses free-text HackerOne program policies into structured
allowed/forbidden testing categories using keyword analysis.
"""

from __future__ import annotations

import re
from typing import Any


class PolicySummarizer:
    """Extract structured rules from HackerOne policy text."""

    ALLOWED_KEYWORDS: list[str] = [
        "allowed", "permitted", "may test", "can test", "may perform",
        "encouraged", "within scope", "acceptable",
    ]
    FORBIDDEN_KEYWORDS: list[str] = [
        "prohibited", "not allowed", "do not", "must not", "cannot",
        "should not", "not permitted", "will not", "forbidden",
        "explicitly out of scope", "out of scope", "excluded",
        "we will not accept", "will not be accepted",
    ]

    CATEGORIES: dict[str, list[str]] = {
        "denial_of_service": [
            "dos", "ddos", "denial of service", "denial-of-service",
            "load testing", "stress testing", "resource exhaustion",
        ],
        "social_engineering": [
            "phishing", "social engineering", "impersonat",
            "pretext", "vishing", "smishing",
        ],
        "physical": [
            "physical security", "physical access", "trespass",
        ],
        "brute_force": [
            "brute force", "brute-force", "bruteforce", "password guessing",
            "credential stuffing", "credential-stuffing",
        ],
        "automated_scanning": [
            "automated scanning", "automated tool", "automated scanner",
            "no automation", "without automation",
        ],
        "third_party": [
            "third party", "third-party", "not owned", "vendor",
        ],
        "malware": [
            "malware", "virus", "trojan", "ransomware", "worm",
        ],
        "data_exfiltration": [
            "exfiltrat", "data breach", "steal data", "copy data",
            "download data", "bulk download",
        ],
        "code_execution": [
            "command injection", "code execution", "remote code",
            "rce", "os command",
        ],
        "sql_injection": [
            "sql injection", "sqli", "sqlmap",
        ],
        "xss": [
            "xss", "cross-site scripting", "cross site scripting",
        ],
    }

    def summarize(self, raw_text: str) -> dict[str, Any]:
        if not raw_text or not raw_text.strip():
            return {
                "summary": "No policy text available.",
                "allowed_testing": "",
                "forbidden_testing": "",
                "rate_limits": "",
                "disclosure_rules": "",
                "warnings": ["No policy text — exercise extreme caution"],
                "is_safe_for_autonomous_recon": False,
                "is_safe_for_autonomous_scouting": False,
            }

        lines = raw_text.split("\n")
        allowed_items: list[str] = []
        forbidden_items: list[str] = []
        rate_limits: list[str] = []
        disclosure_rules: list[str] = []
        warnings: list[str] = []

        forbidden_categories_found: list[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            lower = stripped.lower()

            # Rate limits
            if any(kw in lower for kw in ["rate limit", "requests per", "rps", "rpm", "per second", "per minute"]):
                rate_limits.append(stripped)

            # Disclosure
            if any(kw in lower for kw in ["disclos", "confidential", "responsible disclosure", "coordinated disclosure"]):
                disclosure_rules.append(stripped)

            # Forbidden
            forbidden = self._check_forbidden(lower)
            if forbidden:
                forbidden_items.append(stripped)

            # Categories
            for cat, keywords in self.CATEGORIES.items():
                if any(kw in lower for kw in keywords):
                    forbidden_categories_found.append(cat)

            # Allowed
            if any(kw in lower for kw in self.ALLOWED_KEYWORDS):
                allowed_items.append(stripped)

        # Rate limits
        if not rate_limits:
            rate_limits.append("No explicit rate limits in policy — use conservative defaults (1 req/s)")

        # Warnings
        for cat in set(forbidden_categories_found):
            warnings.append(f"Policy forbids: {cat.replace('_', ' ').title()}")

        is_safe_autonomous = True
        blocking_categories = [
            "automated_scanning", "denial_of_service",
        ]
        for cat in blocking_categories:
            if cat in forbidden_categories_found:
                is_safe_autonomous = False
                warnings.append(f"Autonomous mode may conflict with policy on {cat}")

        is_safe_scouting = "automated_scanning" not in forbidden_categories_found

        summary_parts = []
        if allowed_items:
            summary_parts.append(f"Allowed: {'; '.join(allowed_items[:3])}")
        if forbidden_items:
            summary_parts.append(f"Forbidden: {'; '.join(forbidden_items[:3])}")
        if not summary_parts:
            summary_parts.append("Policy text present but no clear rules extracted")

        return {
            "summary": " | ".join(summary_parts),
            "allowed_testing": "\n".join(allowed_items[:10]) if allowed_items else "No explicit allowed testing rules found",
            "forbidden_testing": "\n".join(forbidden_items[:15]) if forbidden_items else "No explicit forbidden testing rules found",
            "rate_limits": "\n".join(rate_limits[:5]),
            "disclosure_rules": "\n".join(disclosure_rules[:5]) if disclosure_rules else "No disclosure rules found in policy",
            "warnings": warnings,
            "is_safe_for_autonomous_recon": is_safe_autonomous,
            "is_safe_for_autonomous_scouting": is_safe_scouting,
        }

    def _check_forbidden(self, lower: str) -> bool:
        for kw in self.FORBIDDEN_KEYWORDS:
            if kw in lower:
                return True
        return False
