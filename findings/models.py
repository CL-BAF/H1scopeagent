"""Candidate finding dataclasses for H1ScopeAgent."""

from dataclasses import dataclass, field, asdict
from typing import Any, Literal


@dataclass
class CandidateFinding:
    candidate_id: str
    title: str = ""
    affected_asset: str = ""
    candidate_type: str = ""
    confidence: str = "low"
    estimated_severity: str = "info"
    evidence: dict[str, Any] = field(default_factory=dict)
    screenshot_path: str = ""
    metadata_path: str = ""
    safe_to_verify: bool = False
    verification_requires_approval: bool = False
    report_ready: bool = False
    policy_notes: str = ""
    recommended_next_step: str = ""
    program_handle: str = ""
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
