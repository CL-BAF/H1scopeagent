"""Command safety guard — blocks dangerous commands, requires approval for active scans.

Parses commands to extract targets, validates them against scope,
and enforces the hard safety requirements.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from h1scopeagent.config import (
    BLOCKED_PATTERNS,
    APPROVAL_REQUIRED_PATTERNS,
    SAFE_COMMAND_PATTERNS,
    AUTO_ATTACK_TOOLS,
)
from h1scopeagent.logs.audit import AuditLogger


@dataclass
class CommandReview:
    command: str
    blocked: bool = False
    block_reason: str = ""
    requires_approval: bool = False
    approval_reason: str = ""
    is_safe_autonomous: bool = False
    extracted_target: str | None = None
    target_in_scope: bool = False
    scope_reason: str = ""


class CommandGuard:
    """Review commands for safety, scope-compliance, and policy adherence."""

    def __init__(self, scope_validator, policy=None, autonomous_attack: bool = False):
        self._validator = scope_validator
        self._policy = policy
        self._audit = AuditLogger()
        self._autonomous_attack = autonomous_attack

    def review(self, command: str, program_handle: str = "") -> CommandReview:
        result = CommandReview(command=command)

        result.blocked = self.is_blocked(command)
        if result.blocked:
            result.block_reason = self._block_reason(command)
            self._audit.log_blocked_command(command, result.block_reason, program_handle)
            return result

        target = self.extract_target(command)
        result.extracted_target = target

        if not target:
            result.blocked = True
            result.block_reason = "No identifiable target found in command"
            self._audit.log_blocked_command(command, result.block_reason, program_handle)
            return result

        scope_result = self._validator.is_in_scope(target)
        result.target_in_scope = (scope_result["decision"] == "in_scope")
        result.scope_reason = scope_result["reason"]

        if not result.target_in_scope:
            result.blocked = True
            result.block_reason = f"Target not in scope: {scope_result['reason']}"
            self._audit.log_scope_decision(target, scope_result["decision"], scope_result["reason"])
            self._audit.log_blocked_command(command, result.block_reason, program_handle)
            return result

        if scope_result["requires_manual_review"]:
            result.blocked = True
            result.block_reason = "Target requires manual review before execution"
            return result

        result.requires_approval = self.needs_approval(command)
        if result.requires_approval:
            result.approval_reason = "Command requires explicit user approval (active scanning / state-changing)"
        else:
            result.is_safe_autonomous = True

        return result

    def is_blocked(self, command: str) -> bool:
        command_lower = command.lower()

        for pattern in BLOCKED_PATTERNS:
            if pattern.search(command_lower):
                return True

        blocked_keywords = [
            "masscan", "hping3", "slowloris", "metasploit",
            "msfconsole", "hydra", "medusa", "patator",
            "credential stuffing", "credential-stuffing", "bruteforce",
        ]
        for kw in blocked_keywords:
            if kw in command_lower:
                return True

        # sqlmap with destructive flags
        if "sqlmap" in command_lower:
            destructive_flags = ["--dump", "--os-shell", "--os-cmd", "--file-read", "--file-write", "--reg-read", "--reg-write", "--priv-esc"]
            if any(flag in command_lower for flag in destructive_flags):
                return True

        # Reverse shell patterns
        reverse_shell_indicators = [
            "nc -e", "nc.traditional -e", "bash -i",
            "/dev/tcp/", "python -c 'import socket",
            "exec(", "popen",
        ]
        for ind in reverse_shell_indicators:
            if ind in command_lower:
                return True

        # rm -rf
        if re.search(r"rm\s+-rf\s+/", command_lower):
            return True

        # POST/PUT/DELETE with curl or wget (autonomous block)
        curl_post = re.search(r"curl\s.*-(?:X|--request)\s*(?:POST|PUT|PATCH|DELETE)", command_lower)
        if curl_post:
            return False  # Not blocked, but needs approval

        return False

    def _block_reason(self, command: str) -> str:
        command_lower = command.lower()

        if "masscan" in command_lower:
            return "masscan is blocked (high-volume port scanning)"
        if "hping3" in command_lower or "slowloris" in command_lower:
            return "DoS tools are blocked"
        if "metasploit" in command_lower or "msfconsole" in command_lower:
            return "Exploitation frameworks are blocked"
        if "hydra" in command_lower or "medusa" in command_lower:
            return "Brute force tools are blocked"
        if "sqlmap" in command_lower:
            return "sqlmap with destructive flags is blocked"
        if any(ind in command_lower for ind in ["nc -e", "bash -i", "/dev/tcp/"]):
            return "Reverse shell commands are blocked"
        if re.search(r"rm\s+-rf\s+", command_lower):
            return "Destructive rm -rf is blocked"
        return "Blocked safety pattern matched"

    def needs_approval(self, command: str) -> bool:
        if self._autonomous_attack:
            cmd_lower = command.lower()
            for tool in AUTO_ATTACK_TOOLS:
                if tool in cmd_lower:
                    cmd_words = cmd_lower.split()
                    first_word = cmd_words[0] if cmd_words else ""
                    if first_word == tool or (tool in command.lower() and not any(
                        kw in cmd_lower for kw in ["--dump", "--os-shell", "--os-cmd", "-os-shell", "-os-cmd"]
                    )):
                        return False

        command_lower = command.lower()

        for pattern in APPROVAL_REQUIRED_PATTERNS:
            if pattern.search(command_lower):
                return True

        if "sqlmap" in command_lower:
            return True

        if re.search(r"curl\s.*-(?:X|--request)\s*(?:POST|PUT|PATCH|DELETE)", command_lower):
            return True
        if re.search(r"curl\s.*--data", command_lower):
            return True
        if re.search(r"wget\s.*--post-data", command_lower):
            return True

        return False

    def extract_target(self, command: str) -> str | None:
        patterns = [
            # dig/target.com
            r"(?:dig|nslookup|host)\s+(?:@\S+\s+)?(?:\S+\s+)?(\S+\.\S{2,})",
            # whois target.com
            r"whois\s+(\S+\.\S{2,})",
            # curl https://target.com/...
            r"curl\s+(?:-[A-Za-z]\s+\S+\s+)*(?:--?[A-Za-z-]+\s+\S+\s+)*(https?://[^\s]+)",
            # openssl s_client -connect target.com:443
            r"-connect\s+(\S+)",
            # nmap target
            r"(?:nmap|nikto)\s+(?:(?:-[A-Za-z]+\s+\S+\s+)*)([A-Za-z0-9\.\-]+\.\S{2,})",
            # gobuster dir -u https://target.com
            r"(?:gobuster|ffuf|dirsearch|wfuzz).*(?:-u|--url)\s+(https?://[^\s]+)",
        ]

        for pattern in patterns:
            m = re.search(pattern, command, re.IGNORECASE)
            if m:
                target = m.group(1).strip()
                # Remove optional flags from target capture
                if target.startswith("-"):
                    continue
                return target

        # Fallback: find any domain-like string
        domain_pattern = r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
        m = re.search(domain_pattern, command)
        if m:
            return m.group(0)

        return None
