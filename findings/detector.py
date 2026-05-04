"""Non-invasive vulnerability candidate detectors.

Each detector method:
- Takes page data from a ChromiumScout result
- Returns Optional[dict] if a candidate finding is identified
- Uses "candidate"/"potential"/"likely" language
- Never exploits, only observes
- Redacts any detected secrets
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from typing import Any
from urllib.parse import urlparse

from h1scopeagent.config import SECRET_DETECTION_PATTERNS, redact_secret


class FindingDetector:
    """Collection of non-invasive vulnerability candidate detectors."""

    def detect_all(self, program_handle: str, scout_result: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        url = scout_result.get("original_url", "")
        final_url = scout_result.get("final_url", url)
        parsed_url = urlparse(url)
        domain = parsed_url.hostname or ""

        metadata = self._parse_meta(scout_result)
        headers = metadata.get("security_headers", {})
        cookie_names = metadata.get("cookie_names", [])
        console_errors = metadata.get("console_errors", [])
        forms = metadata.get("forms", [])
        links = metadata.get("links", [])

        detectors = [
            ("check_hsts", self.check_hsts(url, headers, domain)),
            ("check_csp", self.check_csp(url, headers, domain)),
            ("check_x_frame_options", self.check_x_frame_options(url, headers, domain)),
            ("check_x_content_type_options", self.check_x_content_type_options(url, headers, domain)),
            ("check_cookies", self.check_cookies(url, cookie_names, domain)),
            ("check_mixed_content", self.check_mixed_content(url, final_url)),
            ("check_exposed_source_maps", self.check_exposed_source_maps(url, scout_result)),
            ("check_console_errors", self.check_console_errors(url, console_errors)),
            ("check_exposed_swagger", self.check_exposed_swagger(url, headers, scout_result)),
            ("check_exposed_graphql", self.check_exposed_graphql(url, headers, scout_result)),
            ("check_public_admin", self.check_public_admin(url, links, scout_result)),
            ("check_redirect_params", self.check_redirect_params(url, links, domain)),
            ("check_cors_misconfig", self.check_cors_misconfig(url, headers, domain)),
            ("check_secret_leakage", self.check_secret_leakage(url, scout_result)),
            ("check_outdated_tech", self.check_outdated_tech(url, headers, scout_result)),
            ("check_exposed_files", self.check_exposed_files(url, scout_result)),
            ("check_robots_sensitive", self.check_robots_sensitive(url, scout_result)),
        ]

        for det_name, finding_dict in detectors:
            if finding_dict is not None:
                finding_dict["program_handle"] = program_handle
                finding_dict["candidate_id"] = self._generate_id(
                    program_handle, det_name, url
                )
                finding_dict.setdefault("screenshot_path", scout_result.get("screenshot_path", ""))
                finding_dict.setdefault("metadata_path", scout_result.get("metadata_path", ""))
                finding_dict.setdefault("evidence", {})
                finding_dict.setdefault("safe_to_verify", True)
                finding_dict.setdefault("verification_requires_approval", False)
                finding_dict.setdefault("report_ready", True)
                finding_dict.setdefault("policy_notes", "")
                finding_dict.setdefault("recommended_next_step", "Manual verification recommended")
                findings.append(finding_dict)

        return findings

    def _parse_meta(self, scout: dict[str, Any]) -> dict[str, Any]:
        meta = {}
        try:
            meta = json.loads(scout.get("metadata_json", "{}"))
        except (json.JSONDecodeError, TypeError):
            pass

        headers = meta.get("security_headers", {})
        if not headers:
            headers_raw = meta.get("headers", {})
            from h1scopeagent.browser.metadata import parse_security_headers
            headers = parse_security_headers(headers_raw)

        return {
            "security_headers": headers,
            "cookie_names": self._get_json(scout, "cookie_names", meta.get("cookie_names", [])),
            "console_errors": self._get_json(scout, "console_errors_json", []),
            "forms": self._get_json(scout, "forms_json", []),
            "links": self._get_json(scout, "links_json", []),
        }

    def _get_json(self, scout: dict, field: str, fallback: Any) -> Any:
        val = scout.get(field, "")
        if isinstance(val, str) and val:
            try:
                return json.loads(val)
            except (json.JSONDecodeError, TypeError):
                pass
        if isinstance(val, list) or isinstance(val, dict):
            return val
        return fallback

    def _generate_id(self, program: str, detector: str, url: str) -> str:
        raw = f"{program}|{detector}|{url}"
        hash_hex = hashlib.sha256(raw.encode()).hexdigest()[:12]
        return f"FND-{hash_hex}"

    def _make_finding(self, detector: str, title: str, asset: str, **kwargs) -> dict[str, Any]:
        return {
            "title": title,
            "affected_asset": asset,
            "candidate_type": detector.replace("check_", ""),
            **kwargs,
        }

    # ------------------------------------------------------------------
    # 1. HSTS Check
    # ------------------------------------------------------------------
    def check_hsts(self, url: str, headers: dict, domain: str) -> dict | None:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return None

        has_hsts = headers.get("hsts_present", False)
        if not has_hsts:
            return self._make_finding(
                "check_hsts",
                "Candidate: Missing HTTP Strict Transport Security (HSTS) Header",
                domain,
                confidence="high",
                estimated_severity="low",
                evidence={
                    "observation": "HSTS header not present on HTTPS response",
                    "header": "Strict-Transport-Security: missing",
                },
                recommended_next_step="Configure HSTS with max-age=31536000; includeSubDomains; preload",
            )

        max_age = headers.get("hsts_max_age", 0)
        if max_age < 31536000:
            return self._make_finding(
                "check_hsts",
                "Candidate: Weak HSTS Configuration (low max-age)",
                domain,
                confidence="high",
                estimated_severity="info",
                evidence={
                    "observation": f"HSTS max-age={max_age} (recommended: 31536000)",
                    "include_subdomains": headers.get("hsts_include_subdomains", False),
                    "preload": headers.get("hsts_preload", False),
                },
                recommended_next_step="Increase max-age to 31536000 and add includeSubDomains and preload directives",
            )

        return None

    # ------------------------------------------------------------------
    # 2. CSP Check
    # ------------------------------------------------------------------
    def check_csp(self, url: str, headers: dict, domain: str) -> dict | None:
        has_csp = headers.get("csp_present", False)
        if not has_csp:
            return self._make_finding(
                "check_csp",
                "Candidate: Missing Content-Security-Policy Header",
                domain,
                confidence="high",
                estimated_severity="medium",
                evidence={
                    "observation": "CSP header not present in HTTP response",
                    "header": "Content-Security-Policy: missing",
                },
                recommended_next_step="Implement a strict CSP policy to mitigate XSS and data injection attacks",
            )

        csp_unsafe_inline = headers.get("csp_has_unsafe_inline", False)
        csp_unsafe_eval = headers.get("csp_has_unsafe_eval", False)

        if csp_unsafe_inline or csp_unsafe_eval:
            issues = []
            if csp_unsafe_inline:
                issues.append("unsafe-inline")
            if csp_unsafe_eval:
                issues.append("unsafe-eval")

            return self._make_finding(
                "check_csp",
                f"Candidate: Weak CSP — allows {' and '.join(issues)}",
                domain,
                confidence="medium",
                estimated_severity="medium",
                evidence={
                    "observation": f"CSP includes: {', '.join(issues)}",
                    "recommendation": "Avoid unsafe-inline/eval; use nonces or hashes instead",
                },
                recommended_next_step="Remove unsafe-inline and unsafe-eval; use nonces or hashes for inline scripts",
            )

        return None

    # ------------------------------------------------------------------
    # 3. X-Frame-Options
    # ------------------------------------------------------------------
    def check_x_frame_options(self, url: str, headers: dict, domain: str) -> dict | None:
        has_xfo = headers.get("x_frame_options_present", False)
        if not has_xfo:
            csp_has_frame = False
            raw_headers = headers
            if isinstance(raw_headers, dict):
                csp = raw_headers.get("content-security-policy", "")
                if isinstance(csp, str) and "frame-ancestors" in csp:
                    csp_has_frame = True

            if not csp_has_frame:
                return self._make_finding(
                    "check_x_frame_options",
                    "Candidate: Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
                    domain,
                    confidence="high",
                    estimated_severity="medium",
                    evidence={
                        "x_frame_options": "missing",
                        "frame_ancestors_in_csp": False,
                    },
                    recommended_next_step="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
                )

        return None

    # ------------------------------------------------------------------
    # 4. X-Content-Type-Options
    # ------------------------------------------------------------------
    def check_x_content_type_options(self, url: str, headers: dict, domain: str) -> dict | None:
        has_xcto = headers.get("x_content_type_options_present", False)
        if not has_xcto:
            return self._make_finding(
                "check_x_content_type_options",
                "Candidate: Missing X-Content-Type-Options Header",
                domain,
                confidence="high",
                estimated_severity="low",
                evidence={
                    "observation": "X-Content-Type-Options header missing",
                    "recommended_value": "nosniff",
                },
                recommended_next_step="Add X-Content-Type-Options: nosniff to prevent MIME type sniffing",
            )

        return None

    # ------------------------------------------------------------------
    # 5. Cookie Security
    # ------------------------------------------------------------------
    def check_cookies(self, url: str, cookies: list[dict], domain: str) -> dict | None:
        if not cookies:
            return None

        insecure: list[str] = []
        for c in cookies:
            name = c.get("name", "")
            issues = []
            if not c.get("secure"):
                issues.append("missing Secure")
            if not c.get("httpOnly"):
                issues.append("missing HttpOnly")
            if c.get("sameSite", "").lower() == "none" and not c.get("secure"):
                issues.append("SameSite=None without Secure")
            if issues:
                insecure.append(f"{name} ({', '.join(issues)})")

        if insecure:
            return self._make_finding(
                "check_cookies",
                f"Candidate: Insecure Cookie Configuration ({len(insecure)} cookies)",
                domain,
                confidence="high",
                estimated_severity="medium",
                evidence={
                    "insecure_cookies": insecure,
                    "total_cookies": len(cookies),
                },
                recommended_next_step="Set Secure, HttpOnly, and SameSite=Lax on all session cookies",
            )

        return None

    # ------------------------------------------------------------------
    # 6. Mixed Content
    # ------------------------------------------------------------------
    def check_mixed_content(self, url: str, final_url: str) -> dict | None:
        if not url.startswith("https"):
            return None

        return None

    # ------------------------------------------------------------------
    # 7. Exposed Source Maps
    # ------------------------------------------------------------------
    def check_exposed_source_maps(self, url: str, scout: dict) -> dict | None:
        from h1scopeagent.browser.metadata import extract_source_maps
        meta_data = self._parse_meta(scout)
        html_content = ""
        try:
            meta = json.loads(scout.get("metadata_json", "{}"))
            html_content = meta.get("html", "")
        except Exception:
            pass

        if not html_content:
            try:
                body_raw = scout.get("body", "")
                if isinstance(body_raw, str):
                    html_content = body_raw
            except Exception:
                pass

        maps = extract_source_maps(html_content) if html_content else []

        if maps:
            return self._make_finding(
                "check_exposed_source_maps",
                f"Candidate: Exposed Source Maps ({len(maps)} found)",
                url,
                confidence="high",
                estimated_severity="low",
                evidence={
                    "source_maps": maps[:10],
                },
                recommended_next_step="Remove or restrict access to source maps in production",
            )

        return None

    # ------------------------------------------------------------------
    # 8. Console Errors with Sensitive Data
    # ------------------------------------------------------------------
    def check_console_errors(self, url: str, console: list[dict]) -> dict | None:
        if not console:
            return None

        severe_count = sum(1 for e in console if e.get("type") == "error")
        if severe_count > 0:
            has_stack = any("stack" in (e.get("text", "") or "").lower() or "trace" in (e.get("text", "") or "").lower() for e in console[:10])

            if has_stack:
                return self._make_finding(
                    "check_console_errors",
                    f"Candidate: Client-Side Errors with Potential Stack Trace Exposure ({severe_count} errors)",
                    url,
                    confidence="medium",
                    estimated_severity="low",
                    evidence={
                        "error_count": severe_count,
                        "sample_errors": [e.get("text", "")[:200] for e in console[:3]],
                    },
                    recommended_next_step="Review console errors for sensitive information disclosure",
                )

        return None

    # ------------------------------------------------------------------
    # 9. Exposed Swagger/OpenAPI
    # ------------------------------------------------------------------
    def check_exposed_swagger(self, url: str, headers: dict, scout: dict) -> dict | None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        indicators = ["/swagger", "/api-docs", "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs"]

        for path in indicators:
            if path in url.lower():
                return self._make_finding(
                    "check_exposed_swagger",
                    "Candidate: Publicly Accessible API Documentation",
                    url,
                    confidence="high",
                    estimated_severity="low",
                    evidence={
                        "observation": f"Swagger/OpenAPI endpoint: {url}",
                        "discovered_from": "page URL",
                    },
                    recommended_next_step="Restrict API documentation access or require authentication",
                )

        return None

    # ------------------------------------------------------------------
    # 10. GraphQL Endpoint
    # ------------------------------------------------------------------
    def check_exposed_graphql(self, url: str, headers: dict, scout: dict) -> dict | None:
        if "/graphql" in url.lower() or "graphql" in url.lower():
            return self._make_finding(
                "check_exposed_graphql",
                "Candidate: Publicly Accessible GraphQL Endpoint",
                url,
                confidence="high",
                estimated_severity="info",
                evidence={
                    "observation": f"GraphQL endpoint: {url}",
                },
                safe_to_verify=False,
                verification_requires_approval=True,
                recommended_next_step="Check if GraphQL introspection is enabled (requires manual approval)",
            )

        return None

    # ------------------------------------------------------------------
    # 11. Public Admin Panels
    # ------------------------------------------------------------------
    def check_public_admin(self, url: str, links: list[dict], scout: dict) -> dict | None:
        admin_keywords = ["/admin", "/wp-admin", "/administrator", "/login", "/cms", "/backend", "/dashboard", "/panel", "/console", "/manage"]
        matched = []
        for link in links:
            href = (link.get("href", "") or "").lower()
            for kw in admin_keywords:
                if kw in href:
                    matched.append(href)
                    break

        if matched:
            return self._make_finding(
                "check_public_admin",
                f"Candidate: Admin/Login Panel Links Detected ({len(matched)} links)",
                url,
                confidence="medium",
                estimated_severity="info",
                evidence={
                    "admin_links": matched[:10],
                },
                recommended_next_step="Verify these admin panels are not publicly accessible without authentication",
            )
        return None

    # ------------------------------------------------------------------
    # 12. Open Redirect Indicators
    # ------------------------------------------------------------------
    def check_redirect_params(self, url: str, links: list[dict], domain: str) -> dict | None:
        redirect_keywords = ["redirect=", "url=", "next=", "return=", "goto=", "target=", "continue=", "returnurl="]
        suspicious = {}
        for link in links:
            href = (link.get("href", "") or "").lower()
            for kw in redirect_keywords:
                if kw in href:
                    if kw not in suspicious:
                        suspicious[kw] = []
                    suspicious[kw].append(href[:200])

        if suspicious:
            return self._make_finding(
                "check_redirect_params",
                f"Candidate: Potential Open Redirect Parameters ({sum(len(v) for v in suspicious.values())} links)",
                domain,
                confidence="low",
                estimated_severity="low",
                evidence={
                    "redirect_parameters": {k: v[:5] for k, v in suspicious.items()},
                },
                safe_to_verify=False,
                verification_requires_approval=True,
                recommended_next_step="Manually verify if these redirect parameters allow redirecting to external domains",
            )

        return None

    # ------------------------------------------------------------------
    # 13. CORS Misconfiguration
    # ------------------------------------------------------------------
    def check_cors_misconfig(self, url: str, headers: dict, domain: str) -> dict | None:
        cors_warning = headers.get("cors_warning", "")
        if cors_warning:
            return self._make_finding(
                "check_cors_misconfig",
                "Candidate: Potential CORS Misconfiguration",
                domain,
                confidence="medium",
                estimated_severity="medium",
                evidence={
                    "warning": cors_warning,
                    "origin": headers.get("cors_origin", ""),
                    "credentials": headers.get("cors_credentials", False),
                },
                safe_to_verify=False,
                verification_requires_approval=True,
                recommended_next_step="Review CORS configuration for overly permissive settings",
            )

        return None

    # ------------------------------------------------------------------
    # 14. Secret Leakage in JS/HTML
    # ------------------------------------------------------------------
    def check_secret_leakage(self, url: str, scout: dict) -> dict | None:
        content_sources = []

        try:
            meta = json.loads(scout.get("metadata_json", "{}"))
            if meta.get("html"):
                content_sources.append(("HTML", meta["html"][:100000]))
        except Exception:
            pass

        body = scout.get("body", "")
        if isinstance(body, str) and body:
            content_sources.append(("Body", body[:100000]))

        found_secrets: list[dict] = []
        for source_label, text in content_sources:
            for secret_type, pattern in SECRET_DETECTION_PATTERNS:
                for m in pattern.finditer(text):
                    raw_value = m.group(0)
                    redacted = redact_secret(raw_value)
                    found_secrets.append({
                        "type": secret_type,
                        "redacted": redacted,
                        "source": source_label,
                    })

        if found_secrets:
            unique_types = list({s["type"] for s in found_secrets})
            return self._make_finding(
                "check_secret_leakage",
                f"Candidate: Potential Secret Exposure in Public Resources ({len(found_secrets)} instances)",
                url,
                confidence="high",
                estimated_severity="high",
                evidence={
                    "secret_types": unique_types,
                    "count": len(found_secrets),
                    "redacted_samples": [s["redacted"] for s in found_secrets[:5]],
                    "note": "Secret values REDACTED — manual review required",
                },
                safe_to_verify=False,
                verification_requires_approval=True,
                recommended_next_step="Remove exposed secrets and rotate any leaked credentials immediately",
            )

        return None

    # ------------------------------------------------------------------
    # 15. Outdated Technology
    # ------------------------------------------------------------------
    def check_outdated_tech(self, url: str, headers: dict, scout: dict) -> dict | None:
        from h1scopeagent.browser.metadata import detect_technology_fingerprints
        meta_data = self._parse_meta(scout)
        html = ""
        try:
            meta = json.loads(scout.get("metadata_json", "{}"))
            html = meta.get("html", "")
        except Exception:
            pass

        raw_headers = {}
        for k in ["server", "x-powered-by", "x-generator"]:
            if k in scout:
                raw_headers[k] = scout[k]

        techs = detect_technology_fingerprints(raw_headers, html)

        outdated_patterns = {
            "jQuery 1.": "Outdated jQuery 1.x detected",
            "jQuery 2.": "Outdated jQuery 2.x detected",
            "Bootstrap 3.": "Outdated Bootstrap 3.x detected",
            "PHP/5.": "EOL PHP 5.x detected",
            "PHP/7.0": "EOL PHP 7.0 detected",
            "PHP/7.1": "EOL PHP 7.1 detected",
            "PHP/7.2": "EOL PHP 7.2 detected",
            "Apache/2.2": "EOL Apache 2.2 detected",
            "nginx/1.1": "Old nginx 1.10 detected",
        }

        warnings = []
        full_server = ""
        for tech in techs:
            full_server += str(tech) + " "
            for pattern, warning in outdated_patterns.items():
                if pattern.lower() in str(tech).lower():
                    warnings.append(warning)

        if warnings:
            return self._make_finding(
                "check_outdated_tech",
                f"Candidate: Outdated Technology Fingerprints ({len(warnings)})",
                url,
                confidence="medium",
                estimated_severity="medium",
                evidence={
                    "warnings": warnings,
                    "detected_technologies": techs[:15],
                },
                recommended_next_step="Update to supported versions of identified technologies",
            )

        return None

    # ------------------------------------------------------------------
    # 16. Exposed Sensitive Files
    # ------------------------------------------------------------------
    def check_exposed_files(self, url: str, scout: dict) -> dict | None:
        parsed = urlparse(url)
        return None

    # ------------------------------------------------------------------
    # 17. Robots.txt Sensitive Paths
    # ------------------------------------------------------------------
    def check_robots_sensitive(self, url: str, scout: dict) -> dict | None:
        import httpx
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = f"{base}/robots.txt"

        try:
            client = httpx.Client(timeout=10)
            resp = client.get(robots_url)
            client.close()
            if resp.status_code != 200:
                return None
            content = resp.text[:10000]
        except Exception:
            return None

        sensitive_keywords = ["admin", "backup", "config", "credentials", "database", "debug", "internal", "private", "restricted", "secret", "staging", "test", "tmp", ".git", ".env", ".svn", ".hg", "wp-admin", "old"]

        sensitive_paths: list[str] = []
        for line in content.split("\n"):
            line_clean = line.strip().lower()
            if line_clean.startswith("disallow:") or line_clean.startswith("allow:"):
                path = line_clean.split(":", 1)[1].strip()
                for kw in sensitive_keywords:
                    if kw in path:
                        sensitive_paths.append(path.strip("/"))
                        break

        if sensitive_paths:
            return self._make_finding(
                "check_robots_sensitive",
                f"Candidate: Sensitive Paths Disclosed in robots.txt ({len(sensitive_paths)})",
                robots_url,
                confidence="high",
                estimated_severity="info",
                evidence={
                    "sensitive_paths": list(set(sensitive_paths))[:20],
                },
                recommended_next_step="Review exposed paths; some may reveal internal structure",
            )

        return None
