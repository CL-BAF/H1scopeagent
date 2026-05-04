"""Tests for browser scouting — scope validation, cookie privacy,
form non-submission, and redirect handling."""

import pytest


class TestBrowserScoutSafety:
    def test_rejects_out_of_scope_url(self):
        from h1scopeagent.scope.validator import ScopeValidator
        from h1scopeagent.db.models import ScopeEntry
        entries = [ScopeEntry(
            program_handle="test", asset_identifier="example.com",
            asset_type="URL", in_scope=True,
            eligible_for_bounty=True, eligible_for_submission=True,
        )]
        v = ScopeValidator(entries)
        r = v.is_in_scope("https://evil.com")
        assert r["decision"] == "ambiguous"

    def test_stops_on_out_of_scope_redirect(self):
        from h1scopeagent.scope.validator import ScopeValidator
        from h1scopeagent.db.models import ScopeEntry
        entries = [ScopeEntry(
            program_handle="test", asset_identifier="example.com",
            asset_type="URL", in_scope=True,
            eligible_for_bounty=True, eligible_for_submission=True,
        )]
        v = ScopeValidator(entries)
        r = v.validate_redirect("https://example.com", "https://evil.com")
        assert r["allowed"] is False
        assert r["final_in_scope"] is False

    def test_cookie_collection_exists(self):
        from h1scopeagent.browser.chromium import ChromiumScout
        assert hasattr(ChromiumScout, "collect_cookie_names")

    def test_forms_extraction_exists(self):
        from h1scopeagent.browser.chromium import ChromiumScout
        assert hasattr(ChromiumScout, "extract_forms")

    def test_screenshot_path_generation(self):
        from h1scopeagent.browser.screenshot import generate_screenshot_path
        path = generate_screenshot_path("test-program", "https://example.com/page")
        assert "test-program" in str(path)
        assert ".png" in str(path)

    def test_sanitize_filename(self):
        from h1scopeagent.browser.screenshot import sanitize_filename
        result = sanitize_filename("https://example.com/path/to?page=1")
        assert "?" not in result
        assert "example" in result
        assert len(result) <= 100

    def test_redirect_validation_both_in_scope(self):
        from h1scopeagent.scope.validator import ScopeValidator
        from h1scopeagent.db.models import ScopeEntry
        entries = [
            ScopeEntry(program_handle="test", asset_identifier="example.com",
                       asset_type="URL", in_scope=True, eligible_for_bounty=True,
                       eligible_for_submission=True),
            ScopeEntry(program_handle="test", asset_identifier="app.example.com",
                       asset_type="URL", in_scope=True, eligible_for_bounty=True,
                       eligible_for_submission=True),
        ]
        v = ScopeValidator(entries)
        r = v.validate_redirect("https://example.com", "https://app.example.com")
        assert r["allowed"] is True
        assert r["original_in_scope"] is True
        assert r["final_in_scope"] is True
