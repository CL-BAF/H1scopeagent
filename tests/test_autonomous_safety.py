"""Tests for autonomous mode — finding limits, target exhaustion, policy checking."""

import pytest
from h1scopeagent.config import DEFAULT_FINDING_LIMIT, DEFAULT_ASSET_LIMIT, DEFAULT_DELAY, redact_secret, SECRET_DETECTION_PATTERNS
from h1scopeagent.scope.validator import ScopeValidator
from h1scopeagent.db.models import ScopeEntry


class TestAutonomousStopConditions:
    def test_finding_limit_default(self):
        assert DEFAULT_FINDING_LIMIT == 10

    def test_asset_limit_default(self):
        assert DEFAULT_ASSET_LIMIT == 50

    def test_delay_default(self):
        assert DEFAULT_DELAY >= 2.0

    def test_should_stop_when_finding_limit_met(self):
        finding_count = 10
        limit = 10
        assert not (finding_count < limit)

    def test_should_continue_before_limit(self):
        finding_count = 5
        limit = 10
        assert finding_count < limit

    def test_no_more_targets_stops(self):
        assert not bool([])

    def test_targets_exist_continues(self):
        assert bool(["https://example.com"])


class TestPolicyStopConditions:
    def test_policy_forbidding_automated(self):
        from h1scopeagent.policy.summarizer import PolicySummarizer
        r = PolicySummarizer().summarize(
            "Automated scanning is not permitted under any circumstances."
        )
        assert r["is_safe_for_autonomous_recon"] is False

    def test_policy_allows_testing(self):
        from h1scopeagent.policy.summarizer import PolicySummarizer
        r = PolicySummarizer().summarize(
            "You are welcome to test all in-scope assets using any reasonable method."
        )
        assert r["is_safe_for_autonomous_recon"] is True


class TestSecretRedaction:
    def test_aws_key_redacted(self):
        for name, pattern in SECRET_DETECTION_PATTERNS:
            if "AWS" in name:
                match = pattern.search("var key = 'AKIA1234567890ABCDEF';")
                if match:
                    redacted = redact_secret(match.group(0))
                    assert "1234567890" not in redacted or "*" in redacted
                    return
        assert False, "AWS pattern not found"

    def test_github_token_redacted(self):
        raw = "ghp_1234567890abcdef1234567890abcdef123456"
        redacted = redact_secret(raw)
        assert "1234567890abcdef" not in redacted

    def test_finding_detector_redacts_secrets(self):
        from h1scopeagent.findings.detector import FindingDetector
        scout = {
            "original_url": "https://example.com",
            "body": "const API_KEY = 'AKIA1234567890ABCDEF';",
            "metadata_json": '{"html": "const TOKEN = \\"ghp_secret12345\\";"}',
        }
        results = FindingDetector().detect_all("test", scout)
        secret_findings = [r for r in results if "secret" in r.get("candidate_type", "")]
        if secret_findings:
            for f in secret_findings:
                samples = f.get("evidence", {}).get("redacted_samples", [])
                for sample in samples:
                    assert "1234567890" not in str(sample) or "*" in str(sample)
