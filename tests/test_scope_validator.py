"""Tests for scope validation — exact domains, wildcards, out-of-scope overrides,
URL paths, IPs, redirects, and ambiguous targets."""

import pytest
from h1scopeagent.scope.validator import ScopeValidator
from h1scopeagent.db.models import ScopeEntry


def _make_entry(identifier: str, asset_type: str = "URL", in_scope: bool = True) -> ScopeEntry:
    return ScopeEntry(
        program_handle="test",
        asset_identifier=identifier,
        asset_type=asset_type,
        in_scope=in_scope,
        eligible_for_bounty=True,
        eligible_for_submission=True,
    )


class TestExactDomainMatching:
    def test_exact_domain_match(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("example.com")
        assert r["decision"] == "in_scope"

    def test_exact_domain_no_match(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("other.com")
        assert r["decision"] == "ambiguous"

    def test_url_with_exact_domain_match(self):
        entries = [_make_entry("app.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("https://app.example.com/path")
        assert r["decision"] == "in_scope"

    def test_subdomain_does_not_match_exact(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("sub.example.com")
        assert r["decision"] == "ambiguous"


class TestWildcardMatching:
    def test_wildcard_matches_subdomain(self):
        entries = [_make_entry("*.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("app.example.com")
        assert r["decision"] == "in_scope"

    def test_wildcard_matches_multi_level_subdomain(self):
        entries = [_make_entry("*.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("api.staging.example.com")
        assert r["decision"] == "in_scope"

    def test_wildcard_does_not_match_root(self):
        entries = [_make_entry("*.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("example.com")
        assert r["decision"] == "ambiguous"

    def test_wildcard_does_not_match_evil_domain(self):
        entries = [_make_entry("*.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("evil-example.com")
        assert r["decision"] == "ambiguous"

    def test_wildcard_does_not_match_completely_different_domain(self):
        entries = [_make_entry("*.example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("attacker.com")
        assert r["decision"] == "ambiguous"


class TestOutOfScopeOverrides:
    def test_out_of_scope_overrides_in_scope(self):
        entries = [
            _make_entry("*.example.com", in_scope=True),
            _make_entry("admin.example.com", in_scope=False),
        ]
        v = ScopeValidator(entries)
        r = v.is_in_scope("admin.example.com")
        assert r["decision"] == "out_of_scope"

    def test_in_scope_still_works_with_out_of_scope_entry(self):
        entries = [
            _make_entry("*.example.com", in_scope=True),
            _make_entry("admin.example.com", in_scope=False),
        ]
        v = ScopeValidator(entries)
        r = v.is_in_scope("app.example.com")
        assert r["decision"] == "in_scope"

    def test_out_of_scope_exact_blocks_exact(self):
        entries = [
            _make_entry("example.com", in_scope=True),
            _make_entry("example.com", in_scope=False),
        ]
        v = ScopeValidator(entries)
        r = v.is_in_scope("example.com")
        assert r["decision"] == "out_of_scope"


class TestURLPathValidation:
    def test_url_with_path_matches_domain_scope(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("https://example.com/some/path?query=1")
        assert r["decision"] == "in_scope"

    def test_validate_url_method(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.validate_url("https://example.com/page")
        assert r["decision"] == "in_scope"

    def test_validate_url_rejects_non_http(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.validate_url("ftp://example.com")
        assert r["decision"] == "out_of_scope"


class TestIPRange:
    def test_ip_in_range_is_in_scope(self):
        entries = [_make_entry("192.168.1.0/24", asset_type="ip_range", in_scope=True)]
        v = ScopeValidator(entries)
        r = v.is_in_scope("192.168.1.50")
        assert r["decision"] == "in_scope"

    def test_ip_outside_range_is_ambiguous(self):
        entries = [_make_entry("192.168.1.0/24", asset_type="ip_range", in_scope=True)]
        v = ScopeValidator(entries)
        r = v.is_in_scope("10.0.0.1")
        assert r["decision"] == "ambiguous"

    def test_ip_in_out_of_scope_range_blocked(self):
        entries = [
            _make_entry("192.168.1.0/24", asset_type="ip_range", in_scope=True),
            _make_entry("192.168.1.10", asset_type="ip", in_scope=False),
        ]
        v = ScopeValidator(entries)
        r = v.is_in_scope("192.168.1.10")
        assert r["decision"] == "out_of_scope"


class TestRedirects:
    def test_redirect_both_in_scope_allowed(self):
        entries = [_make_entry("example.com"), _make_entry("app.example.com")]
        v = ScopeValidator(entries)
        r = v.validate_redirect("https://example.com", "https://app.example.com")
        assert r["allowed"] is True

    def test_redirect_out_of_scope_blocked(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.validate_redirect("https://example.com", "https://evil.com")
        assert r["allowed"] is False
        assert r["final_in_scope"] is False

    def test_redirect_original_not_in_scope_blocked(self):
        entries = [_make_entry("app.example.com")]
        v = ScopeValidator(entries)
        r = v.validate_redirect("https://evil.com", "https://app.example.com")
        assert r["allowed"] is False
        assert r["original_in_scope"] is False


class TestAmbiguousTargets:
    def test_empty_target_is_ambiguous(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("")
        assert r["decision"] == "ambiguous"
        assert r["requires_manual_review"] is True

    def test_unmatched_target_is_ambiguous(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        r = v.is_in_scope("completely-different-domain.net")
        assert r["decision"] == "ambiguous"

    def test_needs_manual_review_method(self):
        entries = [_make_entry("example.com")]
        v = ScopeValidator(entries)
        assert v.needs_manual_review("unknown.com") is True
        assert v.needs_manual_review("example.com") is False
