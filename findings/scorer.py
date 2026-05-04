"""Finding scoring engine — assigns confidence and severity to candidate findings."""

from __future__ import annotations

from typing import Any


class FindingScorer:
    """Score candidate findings for confidence and severity."""

    SEVERITY_MAP: dict[str, str] = {
        "check_hsts": "low",
        "check_csp": "medium",
        "check_x_frame_options": "medium",
        "check_x_content_type_options": "low",
        "check_cookies": "medium",
        "check_mixed_content": "medium",
        "check_exposed_source_maps": "low",
        "check_console_errors": "low",
        "check_exposed_swagger": "low",
        "check_exposed_graphql": "info",
        "check_public_admin": "info",
        "check_redirect_params": "low",
        "check_cors_misconfig": "medium",
        "check_secret_leakage": "high",
        "check_outdated_tech": "medium",
        "check_exposed_files": "medium",
        "check_robots_sensitive": "info",
        "check_subdomain_takeover": "high",
    }

    CONFIDENCE_DEFAULTS: dict[str, str] = {
        "check_hsts": "high",
        "check_csp": "high",
        "check_x_frame_options": "high",
        "check_x_content_type_options": "high",
        "check_cookies": "high",
        "check_console_errors": "medium",
        "check_exposed_source_maps": "high",
        "check_exposed_swagger": "high",
        "check_exposed_graphql": "high",
        "check_public_admin": "medium",
        "check_redirect_params": "low",
        "check_cors_misconfig": "medium",
        "check_secret_leakage": "high",
        "check_outdated_tech": "medium",
        "check_exposed_files": "medium",
        "check_robots_sensitive": "high",
        "check_subdomain_takeover": "low",
    }

    def score_confidence(self, detector_name: str, evidence: dict) -> str:
        base = self.CONFIDENCE_DEFAULTS.get(detector_name, "low")

        ev_count = len(evidence)
        if ev_count >= 3 and base == "medium":
            base = "high"
        elif ev_count >= 5 and base == "low":
            base = "medium"

        return base

    def score_severity(self, detector_name: str, context: dict | None = None) -> str:
        return self.SEVERITY_MAP.get(detector_name, "info")

    def assess_safe_to_verify(self, detector_name: str) -> bool:
        safe_detectors = {
            "check_hsts", "check_csp", "check_x_frame_options",
            "check_x_content_type_options", "check_cookies",
            "check_exposed_source_maps", "check_exposed_swagger",
            "check_console_errors", "check_robots_sensitive",
            "check_outdated_tech",
        }
        return detector_name in safe_detectors

    def assess_report_ready(self, finding: dict) -> bool:
        min_confidence = "medium"
        if finding.get("confidence", "low") == "low":
            return False
        evidence = finding.get("evidence", {})
        if not evidence or len(evidence) == 0:
            return False
        if not finding.get("affected_asset"):
            return False
        return True

    def score(self, detector_name: str, finding: dict) -> dict:
        finding["confidence"] = self.score_confidence(detector_name, finding.get("evidence", {}))
        finding["estimated_severity"] = self.score_severity(detector_name)
        finding["safe_to_verify"] = self.assess_safe_to_verify(detector_name)
        finding["report_ready"] = self.assess_report_ready(finding)
        return finding
