"""Attack Decision Matrix — determines whether to execute active testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from h1scopeagent.config import ATTACK_SCORE_THRESHOLD, RISK_LEVEL, RISK_LEVELS


SEVERITY_SCORES = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}
CONFIDENCE_SCORES = {"high": 1.0, "medium": 0.6, "low": 0.3}

ATTACKABLE_TYPES = {
    "cors_misconfig": {"tools": ["nuclei", "ffuf"], "attack_score_boost": 0.2},
    "redirect_params": {"tools": ["gobuster"], "attack_score_boost": 0.1},
    "x_frame_options": {"tools": ["nuclei"], "attack_score_boost": 0.0},
    "csp": {"tools": ["nuclei"], "attack_score_boost": 0.1},
    "hsts": {"tools": ["nuclei"], "attack_score_boost": 0.0},
    "x_content_type_options": {"tools": ["nuclei"], "attack_score_boost": 0.0},
    "cookies": {"tools": ["nuclei", "ffuf"], "attack_score_boost": 0.15},
    "exposed_graphql": {"tools": ["nuclei", "gobuster", "ffuf"], "attack_score_boost": 0.3},
    "exposed_swagger": {"tools": ["gobuster", "ffuf"], "attack_score_boost": 0.15},
    "public_admin": {"tools": ["gobuster", "ffuf", "nuclei"], "attack_score_boost": 0.2},
    "outdated_tech": {"tools": ["nuclei"], "attack_score_boost": 0.25},
    "secret_leakage": {"tools": [], "attack_score_boost": 0.0},
    "console_errors": {"tools": [], "attack_score_boost": 0.0},
    "source_maps": {"tools": [], "attack_score_boost": 0.0},
    "robots_sensitive": {"tools": ["gobuster"], "attack_score_boost": 0.15},
}


@dataclass
class AttackDecision:
    should_attack: bool = False
    score: float = 0.0
    tools: list[str] = field(default_factory=list)
    reason: str = ""
    target: str = ""
    severity: str = "info"
    confidence: str = "low"
    finding_id: str = ""


class AttackDecisionMatrix:
    """Determine whether a finding warrants active testing."""

    def __init__(self, risk_level: str | None = None):
        self.risk_level = risk_level or RISK_LEVEL
        self.risk_config = RISK_LEVELS.get(self.risk_level, RISK_LEVELS["verified"])

    def evaluate(self, finding: dict[str, Any]) -> AttackDecision:
        severity = finding.get("estimated_severity", "info")
        confidence = finding.get("confidence", "low")
        candidate_type = finding.get("candidate_type", "")
        title = finding.get("title", "")
        asset = finding.get("affected_asset", "")
        finding_id = finding.get("candidate_id", "")

        sev_score = SEVERITY_SCORES.get(severity, 0.1)
        conf_score = CONFIDENCE_SCORES.get(confidence, 0.3)

        type_config = ATTACKABLE_TYPES.get(candidate_type, {"tools": [], "attack_score_boost": 0.0})
        available_tools = type_config.get("tools", [])
        type_boost = type_config.get("attack_score_boost", 0.0)

        score = (sev_score * 0.6) + (conf_score * 0.3) + type_boost

        max_sev = self.risk_config["max_severity_attack"]
        max_sev_score = SEVERITY_SCORES.get(max_sev, 0.5)
        sev_allowed = sev_score <= max_sev_score

        auto_attack = self.risk_config["auto_attack"]
        should_attack = auto_attack and score >= ATTACK_SCORE_THRESHOLD and sev_allowed

        if not available_tools and candidate_type not in ("",):
            should_attack = False

        reason_parts = []
        if not auto_attack:
            reason_parts.append(f"risk level '{self.risk_level}' disables auto-attack")
        if not sev_allowed:
            reason_parts.append(f"severity {severity} exceeds max {max_sev} for this risk level")
        if score < ATTACK_SCORE_THRESHOLD:
            reason_parts.append(f"attack score {score:.2f} below threshold {ATTACK_SCORE_THRESHOLD}")
        if not available_tools:
            reason_parts.append(f"no attack tools available for '{candidate_type}'")
        if should_attack:
            reason_parts.append(f"attack score {score:.2f} meets threshold; {len(available_tools)} tools available")

        return AttackDecision(
            should_attack=should_attack,
            score=round(score, 2),
            tools=available_tools if should_attack else [],
            reason="; ".join(reason_parts) if reason_parts else "evaluated",
            target=asset,
            severity=severity,
            confidence=confidence,
            finding_id=finding_id,
        )
