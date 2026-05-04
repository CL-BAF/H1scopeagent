"""Auto-Attack Engine — runs nuclei, gobuster, ffuf, nmap autonomously on in-scope targets."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import shutil
import time
from dataclasses import dataclass, field
from typing import Any

from h1scopeagent.config import (
    AUTO_ATTACK_TOOLS,
    AUTO_ATTACK_TOOL_TIMEOUTS,
    AUTO_ATTACK_MAX_CONCURRENCY,
    RISK_LEVEL,
    RISK_LEVELS,
)
from h1scopeagent.logs.audit import AuditLogger
from h1scopeagent.attack.decision import AttackDecisionMatrix, AttackDecision


@dataclass
class AttackResult:
    finding_id: str = ""
    target: str = ""
    tool: str = ""
    command: str = ""
    exit_code: int = -1
    output: str = ""
    error: str = ""
    timeout: bool = False
    findings_enhanced: list[dict] = field(default_factory=list)
    new_evidence: dict = field(default_factory=dict)
    duration: float = 0.0


class AutoAttackEngine:
    """Execute automated attacks when the decision matrix says to."""

    def __init__(self, scope_validator, program_handle: str, risk_level: str | None = None):
        self._validator = scope_validator
        self._program_handle = program_handle
        self._risk_level = risk_level or RISK_LEVEL
        self._decision_matrix = AttackDecisionMatrix(self._risk_level)
        self._audit = AuditLogger()
        self._running = True

    def stop(self):
        self._running = False

    def evaluate_and_attack(
        self, finding: dict[str, Any]
    ) -> tuple[AttackDecision, list[AttackResult]]:
        decision = self._decision_matrix.evaluate(finding)
        if not decision.should_attack:
            return decision, []

        results = []
        available_tools = [
            t for t in decision.tools
            if t in AUTO_ATTACK_TOOLS and shutil.which(t)
        ]

        if not available_tools:
            decision = AttackDecision(
                should_attack=False,
                score=decision.score,
                tools=[],
                reason="Required tools not installed: " + ", ".join(decision.tools),
                target=decision.target,
                severity=decision.severity,
                confidence=decision.confidence,
                finding_id=decision.finding_id,
            )
            return decision, []

        for tool in available_tools[:AUTO_ATTACK_MAX_CONCURRENCY]:
            if not self._running:
                break
            result = self._run_tool(tool, decision)
            results.append(result)

        return decision, results

    def _run_tool(self, tool: str, decision: AttackDecision) -> AttackResult:
        target = self._clean_target(decision.target)
        timeout = AUTO_ATTACK_TOOL_TIMEOUTS.get(tool, 120)
        command = self._build_command(tool, target, decision)

        if not command:
            return AttackResult(
                finding_id=decision.finding_id,
                target=target,
                tool=tool,
                error="Could not build command",
            )

        self._audit.log_autonomous_decision(
            "attack_start", self._program_handle, tool, f"target={target}"
        )

        start = time.time()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = (proc.stdout or "")[:20000]
            if proc.stderr:
                output += "\n[STDERR]\n" + (proc.stderr or "")[:5000]
            exit_code = proc.returncode
            err = "" if exit_code == 0 else f"Exit code: {exit_code}"
            timed_out = False
        except subprocess.TimeoutExpired:
            output = ""
            exit_code = -1
            err = f"Timed out after {timeout}s"
            timed_out = True
        except Exception as e:
            output = ""
            exit_code = -1
            err = str(e)
            timed_out = False

        duration = round(time.time() - start, 2)

        enhanced = self._parse_output(tool, decision, output) if output else []
        new_evidence = self._extract_evidence(tool, decision, output) if output else {}

        self._audit.log_command_output(command, exit_code, output[:200])

        return AttackResult(
            finding_id=decision.finding_id,
            target=target,
            tool=tool,
            command=command,
            exit_code=exit_code,
            output=output,
            error=err,
            timeout=timed_out,
            findings_enhanced=enhanced,
            new_evidence=new_evidence,
            duration=duration,
        )

    def _clean_target(self, target: str) -> str:
        for prefix in ("https://", "http://"):
            if target.startswith(prefix):
                return target[len(prefix):]
        return target

    def _build_command(self, tool: str, target: str, decision: AttackDecision) -> str:
        candidate_type = ""
        if tool == "nuclei":
            templates = self._nuclei_templates(candidate_type)
            return f"nuclei -u {target} -silent -no-interactsh -tags {templates} -timeout 10 -retries 1"
        elif tool == "gobuster":
            wordlist = self._find_wordlist()
            return f"gobuster dir -u https://{target} -w {wordlist} -q -t 10 --timeout 10s --no-error"
        elif tool == "ffuf":
            wordlist = self._find_wordlist()
            return f"ffuf -u https://{target}/FUZZ -w {wordlist} -t 10 -timeout 10 -maxtime 120 -of json -o /dev/null 2>&1 || ffuf -u https://{target}/FUZZ -w {wordlist} -t 5 -timeout 10 -maxtime 90"
        elif tool == "nmap":
            return f"nmap -sV --top-ports 100 -T4 --min-rate 100 --max-retries 1 {target}"
        return ""

    def _nuclei_templates(self, candidate_type: str) -> str:
        mapping = {
            "cors_misconfig": "cors,misconfig",
            "csp": "csp,misconfig",
            "x_frame_options": "clickjack,frame",
            "cookies": "cookie,http",
            "exposed_graphql": "graphql,exposure",
            "exposed_swagger": "swagger,exposure",
            "public_admin": "admin,panel,login",
            "outdated_tech": "tech,version",
        }
        return mapping.get(candidate_type, "generic,misconfig")

    def _find_wordlist(self) -> str:
        candidates = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ]
        for path in candidates:
            from pathlib import Path
            if Path(path).exists():
                return path
        return "/usr/share/wordlists/dirb/common.txt"

    def _parse_output(self, tool: str, decision: AttackDecision, output: str) -> list[dict]:
        enhanced = []
        lines = output.split("\n")
        for line in lines[:50]:
            line = line.strip()
            if not line:
                continue
            matched = False
            for keyword in ["vulnerability", "exposed", "CVE-", "critical", "HIGH", "MEDIUM"]:
                if keyword.lower() in line.lower():
                    matched = True
                    break
            if matched:
                enhanced.append({
                    "tool": tool,
                    "target": decision.target,
                    "finding_id": decision.finding_id,
                    "raw_line": line[:500],
                    "severity": self._guess_severity(line),
                })
        return enhanced

    def _guess_severity(self, line: str) -> str:
        line_upper = line.upper()
        if "CRITICAL" in line_upper or "CVE-" in line_upper:
            return "high"
        if "HIGH" in line_upper:
            return "high"
        if "MEDIUM" in line_upper:
            return "medium"
        if "LOW" in line_upper:
            return "low"
        return "info"

    def _extract_evidence(self, tool: str, decision: AttackDecision, output: str) -> dict:
        evidence = {"tool": tool, "target": decision.target}
        lines = [l.strip() for l in output.split("\n") if l.strip()]
        evidence["lines_found"] = min(len(lines), 5)
        evidence["sample_output"] = lines[:10]
        key_indicators = []
        for line in lines:
            for kw in ["open", "found", "discovered", "detected", "vulnerable", "CVE-"]:
                if kw.lower() in line.lower():
                    key_indicators.append(line[:300])
                    break
            if len(key_indicators) >= 3:
                break
        if key_indicators:
            evidence["key_indicators"] = key_indicators
        evidence["attack_tool"] = tool
        evidence["attack_risk_level"] = self._risk_level
        return evidence
