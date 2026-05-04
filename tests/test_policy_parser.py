"""Tests for the policy summarizer — parsing policy text into
structured allowed/forbidden testing rules."""

import pytest
from h1scopeagent.policy.summarizer import PolicySummarizer


class TestPolicyParsing:
    def test_simple_allowed(self):
        s = PolicySummarizer()
        r = s.summarize(
            "You are allowed to test for XSS. "
            "You may test for SQL injection using safe methods."
        )
        assert "allowed" in r["summary"].lower()
        assert len(r["allowed_testing"]) > 0

    def test_simple_forbidden(self):
        s = PolicySummarizer()
        r = s.summarize(
            "You must not perform denial of service attacks. "
            "Automated scanning is prohibited. "
            "Do not attempt brute force attacks."
        )
        assert "forbidden" in r["summary"].lower()
        assert len(r["forbidden_testing"]) > 0
        assert len(r["warnings"]) > 0

    def test_forbidden_blocks_autonomous(self):
        s = PolicySummarizer()
        r = s.summarize(
            "Automated scanning is not allowed. "
            "Do not use automated tools or scanners."
        )
        assert r["is_safe_for_autonomous_recon"] is False

    def test_no_automated_blocks_scouting(self):
        s = PolicySummarizer()
        r = s.summarize(
            "Automated scanning is explicitly prohibited. "
            "Manual testing only."
        )
        assert r["is_safe_for_autonomous_scouting"] is False

    def test_rate_limits_extracted(self):
        s = PolicySummarizer()
        r = s.summarize(
            "You may test at a rate of 1 request per second. "
            "Do not exceed 60 requests per minute."
        )
        assert len(r["rate_limits"]) > 0
        assert "request" in r["rate_limits"].lower()

    def test_disclosure_rules_extracted(self):
        s = PolicySummarizer()
        r = s.summarize(
            "This program follows a responsible disclosure policy. "
            "Do not disclose vulnerabilities until they are resolved."
        )
        assert len(r["disclosure_rules"]) > 0

    def test_empty_policy(self):
        s = PolicySummarizer()
        r = s.summarize("")
        assert r["is_safe_for_autonomous_recon"] is False
        assert len(r["warnings"]) > 0

    def test_no_clear_rules(self):
        s = PolicySummarizer()
        r = s.summarize("This is a standard bug bounty program. Thank you for participating.")
        assert r["is_safe_for_autonomous_recon"] is True
        assert r["is_safe_for_autonomous_scouting"] is True

    def test_category_detection(self):
        s = PolicySummarizer()
        r = s.summarize(
            "Do not perform denial of service attacks. "
            "Phishing and social engineering are prohibited. "
            "No brute force or credential stuffing. "
            "Do not use malware."
        )
        assert len(r["warnings"]) >= 4

    def test_sql_injection_category(self):
        s = PolicySummarizer()
        r = s.summarize(
            "SQL injection and SQLi attacks are not allowed "
            "on production. SQLmap usage is prohibited."
        )
        assert any("sql" in w.lower() for w in r["warnings"])

    def test_xss_category(self):
        s = PolicySummarizer()
        r = s.summarize(
            "Cross-site scripting (XSS) attacks must not be executed. "
            "Do not inject XSS payloads."
        )
        assert any("xss" in w.lower() for w in r["warnings"])
