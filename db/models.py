"""Database models as dataclasses for H1ScopeAgent."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class Program:
    id: int | None = None
    handle: str = ""
    name: str = ""
    state: str = ""
    offers_bounties: bool = False
    last_synced_at: str = ""

    @classmethod
    def from_row(cls, row: tuple | dict) -> "Program":
        if isinstance(row, dict):
            return cls(
                id=row.get("id"),
                handle=row.get("handle", ""),
                name=row.get("name", ""),
                state=row.get("state", ""),
                offers_bounties=bool(row.get("offers_bounties", False)),
                last_synced_at=row.get("last_synced_at", ""),
            )
        return cls(*row) if row else cls()

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
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_row(cls, row: tuple | dict) -> "ScopeEntry":
        if isinstance(row, dict):
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
                created_at=row.get("created_at", ""),
                updated_at=row.get("updated_at", ""),
            )
        return cls(*row) if row else cls()

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
    def from_row(cls, row: tuple | dict) -> "PolicyRecord":
        if isinstance(row, dict):
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
        return cls(*row) if row else cls()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommandLogEntry:
    id: int | None = None
    program_handle: str = ""
    command: str = ""
    target: str = ""
    approved_by_user: bool = False
    blocked: bool = False
    block_reason: str = ""
    output: str = ""
    exit_code: int = -1
    created_at: str = ""

    @classmethod
    def from_row(cls, row: tuple | dict) -> "CommandLogEntry":
        if isinstance(row, dict):
            return cls(
                id=row.get("id"),
                program_handle=row.get("program_handle", ""),
                command=row.get("command", ""),
                target=row.get("target", ""),
                approved_by_user=bool(row.get("approved_by_user", False)),
                blocked=bool(row.get("blocked", False)),
                block_reason=row.get("block_reason", ""),
                output=row.get("output", ""),
                exit_code=row.get("exit_code", -1),
                created_at=row.get("created_at", ""),
            )
        return cls(*row) if row else cls()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserScoutEntry:
    id: int | None = None
    program_handle: str = ""
    original_url: str = ""
    final_url: str = ""
    in_scope: bool = True
    manual_review_required: bool = False
    status_code: int = 0
    title: str = ""
    screenshot_path: str = ""
    metadata_json: str = ""
    console_errors_json: str = ""
    forms_json: str = ""
    links_json: str = ""
    created_at: str = ""

    @classmethod
    def from_row(cls, row: tuple | dict) -> "BrowserScoutEntry":
        if isinstance(row, dict):
            return cls(
                id=row.get("id"),
                program_handle=row.get("program_handle", ""),
                original_url=row.get("original_url", ""),
                final_url=row.get("final_url", ""),
                in_scope=bool(row.get("in_scope", True)),
                manual_review_required=bool(row.get("manual_review_required", False)),
                status_code=row.get("status_code", 0),
                title=row.get("title", ""),
                screenshot_path=row.get("screenshot_path", ""),
                metadata_json=row.get("metadata_json", ""),
                console_errors_json=row.get("console_errors_json", ""),
                forms_json=row.get("forms_json", ""),
                links_json=row.get("links_json", ""),
                created_at=row.get("created_at", ""),
            )
        return cls(*row) if row else cls()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReconPlan:
    id: int | None = None
    program_handle: str = ""
    plan_markdown: str = ""
    created_at: str = ""

    @classmethod
    def from_row(cls, row: tuple | dict) -> "ReconPlan":
        if isinstance(row, dict):
            return cls(
                id=row.get("id"),
                program_handle=row.get("program_handle", ""),
                plan_markdown=row.get("plan_markdown", ""),
                created_at=row.get("created_at", ""),
            )
        return cls(*row) if row else cls()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
