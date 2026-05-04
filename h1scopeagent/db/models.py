"""Database models as dataclasses for H1ScopeAgent."""

from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class Program:
    id: int | None = None
    handle: str = ""
    name: str = ""
    state: str = ""
    offers_bounties: bool = False
    currency: str = ""
    confidential: bool = False
    bookmarked: bool = False
    last_synced_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> "Program":
        return cls(
            id=row.get("id"),
            handle=row.get("handle", ""),
            name=row.get("name", ""),
            state=row.get("state", ""),
            offers_bounties=bool(row.get("offers_bounties", False)),
            currency=row.get("currency", ""),
            confidential=bool(row.get("confidential", False)),
            bookmarked=bool(row.get("bookmarked", False)),
            last_synced_at=row.get("last_synced_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScopeEntry:
    id: int | None = None
    program_handle: str = ""
    asset_identifier: str = ""
    asset_type: str = ""
    eligible_for_bounty: bool = False
    eligible_for_submission: bool = False
    max_severity: str = ""
    instruction: str = ""
    in_scope: bool = True
    notes: str = ""
    tags: str = ""
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> "ScopeEntry":
        return cls(
            id=row.get("id"),
            program_handle=row.get("program_handle", ""),
            asset_identifier=row.get("asset_identifier", ""),
            asset_type=row.get("asset_type", ""),
            eligible_for_bounty=bool(row.get("eligible_for_bounty", False)),
            eligible_for_submission=bool(row.get("eligible_for_submission", False)),
            max_severity=row.get("max_severity", ""),
            instruction=row.get("instruction", ""),
            in_scope=bool(row.get("in_scope", True)),
            notes=row.get("notes", ""),
            tags=row.get("tags", ""),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyRecord:
    id: int | None = None
    program_handle: str = ""
    raw_policy_text: str = ""
    summary: str = ""
    allowed_testing: str = ""
    forbidden_testing: str = ""
    rate_limits: str = ""
    disclosure_rules: str = ""
    updated_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> "PolicyRecord":
        return cls(
            id=row.get("id"),
            program_handle=row.get("program_handle", ""),
            raw_policy_text=row.get("raw_policy_text", ""),
            summary=row.get("summary", ""),
            allowed_testing=row.get("allowed_testing", ""),
            forbidden_testing=row.get("forbidden_testing", ""),
            rate_limits=row.get("rate_limits", ""),
            disclosure_rules=row.get("disclosure_rules", ""),
            updated_at=row.get("updated_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReconPlan:
    id: int | None = None
    program_handle: str = ""
    plan_markdown: str = ""
    profile_used: str = ""
    created_at: str = ""

    @classmethod
    def from_row(cls, row: dict) -> "ReconPlan":
        return cls(
            id=row.get("id"),
            program_handle=row.get("program_handle", ""),
            plan_markdown=row.get("plan_markdown", ""),
            profile_used=row.get("profile_used", ""),
            created_at=row.get("created_at", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
