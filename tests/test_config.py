"""Tests for config profiles, settings validation, and env var parsing."""

import pytest
from h1scopeagent.config import (
    get_settings, load_profile, list_profiles, ConfigProfile,
    DEFAULT_FINDING_LIMIT, DEFAULT_ASSET_LIMIT, DEFAULT_DELAY, DB_PATH,
    redact_secret, SECRET_DETECTION_PATTERNS,
)


class TestConfigDefaults:
    def test_finding_limit_default(self):
        assert DEFAULT_FINDING_LIMIT == 10

    def test_asset_limit_default(self):
        assert DEFAULT_ASSET_LIMIT == 50

    def test_delay_default(self):
        assert DEFAULT_DELAY == 3.0

    def test_db_path_exists_in_config(self):
        assert str(DB_PATH).endswith("h1scopeagent.db")


class TestProfiles:
    def test_default_profile_loads(self):
        prof = load_profile("default")
        assert prof.name == "default"
        assert prof.delay == 3.0
        assert prof.concurrency == 3

    def test_fast_profile_loads(self):
        prof = load_profile("fast")
        assert prof.name == "fast"
        assert prof.concurrency == 10
        assert prof.delay == 0.5

    def test_deep_profile_loads(self):
        prof = load_profile("deep")
        assert prof.name == "deep"
        assert prof.port_scanning is True
        assert prof.github_search is True

    def test_passive_only_profile(self):
        prof = load_profile("passive-only")
        assert prof.name == "passive-only"
        assert prof.risk_level == "safe"
        assert not prof.attack_tools

    def test_list_profiles(self):
        profiles = list_profiles()
        assert "default" in profiles
        assert "fast" in profiles
        assert "deep" in profiles
        assert "passive-only" in profiles

    def test_unknown_profile_falls_back(self):
        prof = load_profile("nonexistent")
        assert prof.name == "nonexistent"
        assert prof.delay == 3.0


class TestSecretRedaction:
    def test_aws_key_redacted(self):
        raw = "AKIA1234567890ABCDEF"
        redacted = redact_secret(raw)
        assert "1234567890" not in redacted or "*" in redacted

    def test_github_token_redacted(self):
        raw = "ghp_1234567890abcdef1234567890abcdef123456"
        redacted = redact_secret(raw)
        assert "1234567890abcdef" not in redacted
        assert redacted.startswith("ghp_")

    def test_secret_patterns_exist(self):
        assert len(SECRET_DETECTION_PATTERNS) >= 6
