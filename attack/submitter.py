"""Auto-Submission — submit reports directly to HackerOne via REST API."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from h1scopeagent.config import (
    HACKERONE_SUBMIT_URL,
    RISK_LEVEL,
    RISK_LEVELS,
    redact_token_from_text,
)
from h1scopeagent.logs.audit import AuditLogger
from h1scopeagent.api.hackerone import HackerOneClient, APIError, AuthError, NoTokenError


SEVERITY_H1_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "none",
    "none": "none",
}


@dataclass
class SubmissionResult:
    submitted: bool = False
    report_id: str = ""
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    error: str = ""
    response: dict = field(default_factory=dict)


class AutoSubmitter:
    """Submit verified report drafts to HackerOne."""

    def __init__(self, risk_level: str | None = None):
        self._risk_level = risk_level or RISK_LEVEL
        self._risk_config = RISK_LEVELS.get(self._risk_level, RISK_LEVELS["verified"])
        self._audit = AuditLogger()

    def can_auto_submit(self) -> bool:
        return self._risk_config.get("auto_submit", False)

    def submit(self, report_data: dict[str, Any], program_handle: str) -> SubmissionResult:
        if not self.can_auto_submit():
            return SubmissionResult(
                finding_id=report_data.get("finding_id", ""),
                error=f"Auto-submission disabled at risk level '{self._risk_level}'. Switch to 'aggressive'.",
            )

        title = report_data.get("title", "Untitled")
        severity = report_data.get("severity", "info")
        markdown = report_data.get("markdown_body", "")
        finding_id = report_data.get("finding_id", "")
        asset = report_data.get("affected_asset", "")

        h1_severity = SEVERITY_H1_MAP.get(severity, "none")

        submission_data = {
            "type": "report",
            "attributes": {
                "title": title[:200],
                "vulnerability_information": self._enrich_markdown(markdown, asset, program_handle),
                "severity_rating": h1_severity,
                "structured_scope": asset,
                "collaborator_ids": [],
            },
            "relationships": {
                "team": {"data": {"type": "team", "handle": program_handle}},
            },
        }

        if not markdown:
            return SubmissionResult(
                finding_id=finding_id,
                title=title,
                severity=severity,
                error="Report markdown body is empty",
            )

        try:
            with HackerOneClient() as client:
                resp = client._request(
                    "POST",
                    HACKERONE_SUBMIT_URL,
                    json=submission_data,
                )
                data = resp.json()
                report_id = ""
                if isinstance(data, dict):
                    d = data.get("data", data)
                    if isinstance(d, dict):
                        report_id = str(d.get("id", "") or d.get("report_id", ""))

                self._audit.log_report_generated(
                    f"HackerOne report {report_id}", finding_id
                )

                return SubmissionResult(
                    submitted=True,
                    report_id=report_id,
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    response=data if isinstance(data, dict) else {},
                )

        except NoTokenError:
            return SubmissionResult(
                finding_id=finding_id,
                title=title,
                severity=severity,
                error="No API credentials configured",
            )
        except AuthError as e:
            return SubmissionResult(
                finding_id=finding_id,
                title=title,
                severity=severity,
                error=f"Authentication failed: {e}",
            )
        except APIError as e:
            return SubmissionResult(
                finding_id=finding_id,
                title=title,
                severity=severity,
                error=f"API error ({e.status_code}): {str(e)[:500]}",
            )
        except Exception as e:
            return SubmissionResult(
                finding_id=finding_id,
                title=title,
                severity=severity,
                error=f"Submission error: {str(e)[:500]}",
            )

    def _enrich_markdown(self, body: str, asset: str, program: str) -> str:
        header = (
            f"**Auto-submitted by H1ScopeAgent (risk level: {self._risk_level})**\n"
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"Program: {program} | Asset: {asset}\n\n"
        )
        return header + body


def batch_submit(
    reports: list[dict[str, Any]],
    program_handle: str,
    risk_level: str | None = None,
    submitter: AutoSubmitter | None = None,
) -> list[SubmissionResult]:
    if submitter is None:
        submitter = AutoSubmitter(risk_level)

    results = []
    for report in reports:
        result = submitter.submit(report, program_handle)
        results.append(result)
    return results
