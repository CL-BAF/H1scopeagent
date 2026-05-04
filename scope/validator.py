"""Scope validation engine for H1ScopeAgent.

Handles exact domains, wildcards, IPs, URLs, and out-of-scope overrides.
Returns structured decisions with reasoning.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from h1scopeagent.db.models import ScopeEntry


class ScopeValidator:
    """Validates whether a target is in scope for a given program."""

    def __init__(self, scope_entries: list[ScopeEntry]):
        self._in_scope: list[ScopeEntry] = []
        self._out_scope: list[ScopeEntry] = []
        for e in scope_entries:
            if e.in_scope:
                self._in_scope.append(e)
            else:
                self._out_scope.append(e)

        self._in_scope_patterns = self._compile_patterns(self._in_scope)
        self._out_scope_patterns = self._compile_patterns(self._out_scope)

    def _compile_patterns(
        self, entries: list[ScopeEntry]
    ) -> list[tuple[re.Pattern, ScopeEntry]]:
        compiled: list[tuple[re.Pattern, ScopeEntry]] = []
        for entry in entries:
            ident = entry.asset_identifier.strip().lower()

            if ident.startswith("*."):
                base = re.escape(ident[2:])
                pattern = re.compile(
                    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                    + base
                    + r"$",
                    re.IGNORECASE,
                )
                compiled.append((pattern, entry))
            else:
                pattern = re.compile(
                    r"^" + re.escape(ident) + r"$", re.IGNORECASE
                )
                compiled.append((pattern, entry))

        return compiled

    def _normalize_target(self, target: str) -> str:
        target = target.strip().lower()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split(":")[0]

    def is_in_scope(self, target: str) -> dict[str, Any]:
        target = target.strip()
        if not target:
            return {"decision": "ambiguous", "reason": "Empty target", "requires_manual_review": True}

        # Normalize
        normal = self._normalize_target(target)

        # Check out-of-scope first (overrides)
        out_result = self._match_any(normal, self._out_scope_patterns)
        if out_result:
            return {
                "decision": "out_of_scope",
                "reason": f"Explicit out-of-scope entry: {out_result.asset_identifier}",
                "requires_manual_review": False,
                "matched_entry": out_result.asset_identifier,
            }

        # Check in-scope
        in_result = self._match_any(normal, self._in_scope_patterns)
        if in_result:
            return {
                "decision": "in_scope",
                "reason": f"Matched scope entry: {in_result.asset_identifier}",
                "requires_manual_review": False,
                "matched_entry": in_result.asset_identifier,
            }

        # Check IP range
        if self._is_ip(normal):
            ip_result = self._check_ip_in_scope(normal)
            if ip_result:
                return ip_result

        # Ambiguous
        return {
            "decision": "ambiguous",
            "reason": f"No scope entry matches '{target}'",
            "requires_manual_review": True,
        }

    def is_out_of_scope(self, target: str) -> bool:
        normal = self._normalize_target(target)
        return self._match_any(normal, self._out_scope_patterns) is not None

    def validate_url(self, url: str) -> dict[str, Any]:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return {"decision": "out_of_scope", "reason": "Only http/https URLs allowed", "requires_manual_review": True}
        if not parsed.hostname:
            return {"decision": "ambiguous", "reason": "No hostname in URL", "requires_manual_review": True}
        return self.is_in_scope(url)

    def _match_any(
        self, target: str, patterns: list[tuple[re.Pattern, ScopeEntry]]
    ) -> ScopeEntry | None:
        for pat, entry in patterns:
            if pat.match(target):
                return entry
        return None

    def _is_ip(self, value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _check_ip_in_scope(self, ip_str: str) -> dict[str, Any] | None:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return None

        for entry in self._in_scope:
            ident = entry.asset_identifier.strip()

            # Check if out-of-scope first
            for out_entry in self._out_scope:
                out_ident = out_entry.asset_identifier.strip()
                if self._ip_matches(ip, out_ident):
                    return {
                        "decision": "out_of_scope",
                        "reason": f"IP in out-of-scope range: {out_ident}",
                        "requires_manual_review": False,
                    }

            if self._ip_matches(ip, ident):
                return {
                    "decision": "in_scope",
                    "reason": f"IP in scope range: {ident}",
                    "requires_manual_review": False,
                }

        return None

    def _ip_matches(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, ident: str) -> bool:
        try:
            if "/" in ident:
                network = ipaddress.ip_network(ident, strict=False)
                return ip in network
            else:
                return str(ip) == ident.strip()
        except ValueError:
            return False

    def validate_redirect(self, original_url: str, final_url: str) -> dict[str, Any]:
        orig_result = self.is_in_scope(original_url)
        if orig_result["decision"] != "in_scope":
            return {
                "allowed": False,
                "reason": f"Original URL not in scope: {orig_result['reason']}",
                "original_in_scope": False,
                "final_in_scope": False,
                "requires_manual_review": True,
            }

        final_result = self.is_in_scope(final_url)
        if final_result["decision"] != "in_scope":
            return {
                "allowed": False,
                "reason": f"Redirect target out of scope: {final_result['reason']}",
                "original_in_scope": True,
                "final_in_scope": False,
                "requires_manual_review": True,
            }

        return {
            "allowed": True,
            "reason": "Both URLs are in scope",
            "original_in_scope": True,
            "final_in_scope": True,
            "requires_manual_review": False,
        }

    def needs_manual_review(self, target: str) -> bool:
        result = self.is_in_scope(target)
        return result["decision"] == "ambiguous" or result["requires_manual_review"]

    def _extract_domain(self, value: str) -> str:
        if value.startswith("http://") or value.startswith("https://"):
            parsed = urlparse(value)
            return parsed.hostname or value
        return value.split(":")[0].split("/")[0]
