"""Tests for finding scoring — confidence levels, severity assignment,
deduplication, secret redaction, and report readiness."""

import pytest
from h1scopeagent.findings.scorer import FindingScorer
from h1scopeagent.findings.dedupe import FindingDeduplicator


class TestFindingScoring:
    def test_missing_hsts_scores_low_severity(self):
        scorer = FindingScorer()
        sev = scorer.score_severity("check_hsts")
        assert sev == "low"

    def test_missing_csp_scores_medium(self):
        scorer = FindingScorer()
        sev = scorer.score_severity("check_csp")
        assert sev == "medium"

    def test_secret_leakage_scores_high(self):
        scorer = FindingScorer()
        sev = scorer.score_severity("check_secret_leakage")
        assert sev == "high"

    def test_robots_sensitive_scores_info(self):
        scorer = FindingScorer()
        sev = scorer.score_severity("check_robots_sensitive")
        assert sev == "info"

    def test_missing_xfo_scores_medium(self):
        scorer = FindingScorer()
        sev = scorer.score_severity("check_x_frame_options")
        assert sev == "medium"

    def test_confidence_defaults(self):
        scorer = FindingScorer()
        assert scorer.score_confidence("check_hsts", {}) == "high"
        assert scorer.score_confidence("check_outdated_tech", {}) == "medium"
        assert scorer.score_confidence("check_redirect_params", {}) == "low"

    def test_confidence_improves_with_evidence(self):
        scorer = FindingScorer()
        evidence = {"a": 1, "b": 2, "c": 3}
        conf = scorer.score_confidence("check_outdated_tech", evidence)
        assert conf == "high"

    def test_safe_to_verify(self):
        scorer = FindingScorer()
        assert scorer.assess_safe_to_verify("check_hsts") is True
        assert scorer.assess_safe_to_verify("check_secret_leakage") is False

    def test_report_ready_false_for_low_confidence(self):
        scorer = FindingScorer()
        finding = {"confidence": "low", "evidence": {"test": "data"}, "affected_asset": "test.com"}
        assert scorer.assess_report_ready(finding) is False

    def test_report_ready_true_for_high_confidence(self):
        scorer = FindingScorer()
        finding = {"confidence": "high", "evidence": {"test": "data"}, "affected_asset": "test.com"}
        assert scorer.assess_report_ready(finding) is True

    def test_report_ready_false_without_evidence(self):
        scorer = FindingScorer()
        finding = {"confidence": "high", "evidence": {}, "affected_asset": "test.com"}
        assert scorer.assess_report_ready(finding) is False


class TestDeduplication:
    def test_same_type_same_asset_detected(self):
        deduper = FindingDeduplicator()
        f1 = {
            "candidate_type": "hsts",
            "affected_asset": "example.com",
            "evidence": {"hsts": "missing"},
            "title": "Missing HSTS",
        }
        f2 = {
            "candidate_type": "hsts",
            "affected_asset": "example.com",
            "evidence": {"hsts": "missing"},
            "title": "Missing HSTS",
        }
        h1 = deduper._compute_hash(f1)
        h2 = deduper._compute_hash(f2)
        assert h1 == h2

    def test_different_types_not_deduped(self):
        deduper = FindingDeduplicator()
        f1 = {
            "candidate_type": "hsts",
            "affected_asset": "example.com",
            "evidence": {"hsts": "missing"},
        }
        f2 = {
            "candidate_type": "csp",
            "affected_asset": "example.com",
            "evidence": {"csp": "missing"},
        }
        assert deduper._compute_hash(f1) != deduper._compute_hash(f2)

    def test_different_assets_not_deduped(self):
        deduper = FindingDeduplicator()
        f1 = {
            "candidate_type": "hsts",
            "affected_asset": "example.com",
            "evidence": {"hsts": "missing"},
        }
        f2 = {
            "candidate_type": "hsts",
            "affected_asset": "other.com",
            "evidence": {"hsts": "missing"},
        }
        assert deduper._compute_hash(f1) != deduper._compute_hash(f2)

    def test_similar_titles_detected(self):
        deduper = FindingDeduplicator()
        f1 = {
            "title": "Missing HSTS Header on example.com",
            "affected_asset": "example.com",
        }
        f2 = {
            "title": "Missing HSTS Header on example.com (duplicate)",
            "affected_asset": "example.com",
        }
        assert deduper.are_similar(f1, f2) is True

    def test_different_titles_not_similar(self):
        deduper = FindingDeduplicator()
        f1 = {
            "title": "Missing HSTS Header on example.com",
            "affected_asset": "example.com",
        }
        f2 = {
            "title": "Exposed Source Maps on app.example.com",
            "affected_asset": "app.example.com",
        }
        assert deduper.are_similar(f1, f2) is False


class TestSecretRedaction:
    def test_redact_secret_long(self):
        from h1scopeagent.config import redact_secret
        redacted = redact_secret("AKIA1234567890ABCDEF")
        assert "AKIA" in redacted
        assert "CDEF" in redacted
        assert "*" in redacted
        assert "1234567890" not in redacted

    def test_redact_secret_short(self):
        from h1scopeagent.config import redact_secret
        redacted = redact_secret("token")
        # Short tokens just get asterisked
        assert redacted.startswith("t")
        assert "*" in redacted
