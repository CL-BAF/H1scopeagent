"""Non-destructive PoC Verification — confirm findings without exploitation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from h1scopeagent.config import SECRET_DETECTION_PATTERNS, redact_secret
from h1scopeagent.logs.audit import AuditLogger


@dataclass
class VerificationResult:
    finding_id: str = ""
    verified: bool = False
    verification_type: str = ""
    confidence: str = "low"
    evidence: dict = field(default_factory=dict)
    safe_for_report: bool = False
    error: str = ""
    raw_response: str = ""


class FindingVerifier:
    """Non-destructively verify candidate findings."""

    def __init__(self, scope_validator, program_handle: str):
        self._validator = scope_validator
        self._program = program_handle
        self._audit = AuditLogger()

    def verify(self, finding: dict[str, Any]) -> VerificationResult:
        ctype = finding.get("candidate_type", "")
        url = finding.get("affected_asset", "")

        verifiers = {
            "cors_misconfig": self._verify_cors,
            "redirect_params": self._verify_open_redirect,
            "exposed_graphql": self._verify_graphql_introspection,
            "exposed_swagger": self._verify_swagger,
            "public_admin": self._verify_admin_access,
            "x_frame_options": self._verify_clickjack,
            "csp": self._verify_csp_weakness,
            "cookies": self._verify_cookies,
            "hsts": self._verify_hsts,
            "x_content_type_options": self._verify_xcto,
            "secret_leakage": self._verify_secret_leakage,
            "outdated_tech": self._verify_outdated_tech,
        }

        handler = verifiers.get(ctype)
        if handler:
            try:
                return handler(finding, url)
            except Exception as e:
                return VerificationResult(
                    finding_id=finding.get("candidate_id", ""),
                    verification_type=ctype,
                    error=str(e),
                )

        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verification_type=ctype,
            verified=False,
            safe_for_report=True,
        )

    def _build_url(self, raw: str) -> str:
        if not raw.startswith("http"):
            return f"https://{raw}"
        return raw

    def _safe_get(self, url: str, headers: dict | None = None) -> httpx.Response | None:
        try:
            client = httpx.Client(timeout=15, follow_redirects=False)
            resp = client.get(url, headers=headers)
            client.close()
            return resp
        except Exception:
            return None

    def _verify_cors(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base, headers={"Origin": "https://evil.example.com"})
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="cors_misconfig",
                error="Could not reach target",
            )

        acao = (resp.headers.get("access-control-allow-origin") or "").lower()
        acac = (resp.headers.get("access-control-allow-credentials") or "").lower()

        verified = False
        evidence = {}
        if acao == "*" and acac == "true":
            verified = True
            evidence["issue"] = "Wildcard origin with credentials"
        elif "evil.example.com" in acao:
            verified = True
            evidence["issue"] = "Origin reflected in Access-Control-Allow-Origin"
        elif acao == "*":
            evidence["observation"] = "Wildcard origin (no credentials)"
            verified = False

        evidence["acao"] = acao
        evidence["acac"] = acac
        confidence = "high" if verified else "low"

        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="cors_misconfig",
            confidence=confidence,
            evidence=evidence,
            safe_for_report=True,
        )

    def _verify_open_redirect(self, finding: dict, url: str) -> VerificationResult:
        evidence = finding.get("evidence", {})
        redirect_params = evidence.get("redirect_parameters", {})
        if not redirect_params:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="redirect_params",
                verified=False,
                evidence={"reason": "No redirect parameters in evidence"},
            )

        safe_test_url = "https://example.com"
        verified = False
        test_results = {}

        for param_name in list(redirect_params.keys())[:3]:
            clean_param = param_name.replace("=", "")

            if "://" in url:
                base = url
                if "?" in url:
                    test_url = f"{base}&{clean_param}={safe_test_url}"
                else:
                    test_url = f"{base}?{clean_param}={safe_test_url}"
            else:
                base = self._build_url(url)
                test_url = f"{base}?{clean_param}={safe_test_url}"

            resp = self._safe_get(test_url)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "example.com" in location:
                    verified = True
                    test_results[clean_param] = {"redirects_to": location[:200]}

        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="redirect_params",
            confidence="high" if verified else "low",
            evidence=test_results,
            safe_for_report=True,
        )

    def _verify_graphql_introspection(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        introspection_query = '{"query": "{ __schema { types { name } } }"}'
        headers = {"Content-Type": "application/json"}

        try:
            client = httpx.Client(timeout=15)
            resp = client.post(base, content=introspection_query, headers=headers)
            client.close()
            body = resp.text[:5000]
            verified = "__schema" in body or "types" in body
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verified=verified,
                verification_type="exposed_graphql",
                confidence="high" if verified else "low",
                evidence={"introspection_enabled": verified, "response_truncated": body[:500]},
                safe_for_report=True,
            )
        except Exception as e:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="exposed_graphql",
                error=str(e),
            )

    def _verify_swagger(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="exposed_swagger",
                error="Could not reach endpoint",
            )
        body = resp.text[:5000].lower()
        verified = any(kw in body for kw in ["swagger", "openapi", "paths", "api-docs"])
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="exposed_swagger",
            confidence="high" if verified else "low",
            evidence={"status_code": resp.status_code, "contains_api_keywords": verified},
            safe_for_report=True,
        )

    def _verify_admin_access(self, finding: dict, url: str) -> VerificationResult:
        evidence = finding.get("evidence", {})
        admin_links = evidence.get("admin_links", [])
        accessible = []

        for link in admin_links[:5]:
            full_url = link if link.startswith("http") else self._build_url(f"{self._build_url(url).rstrip('/')}/{link.lstrip('/')}")
            resp = self._safe_get(full_url)
            if resp and resp.status_code == 200:
                accessible.append({"url": link[:200], "status": resp.status_code})

        verified = len(accessible) > 0
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="public_admin",
            confidence="high" if verified else "low",
            evidence={"accessible_panels": accessible},
            safe_for_report=True,
        )

    def _verify_clickjack(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="x_frame_options",
                error="Could not reach target",
            )
        xfo = (resp.headers.get("x-frame-options") or "").lower()
        csp = (resp.headers.get("content-security-policy") or "").lower()
        has_xfo = bool(xfo)
        has_frame_ancestors = "frame-ancestors" in csp
        verified = not has_xfo and not has_frame_ancestors
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="x_frame_options",
            confidence="high",
            evidence={"x_frame_options": xfo or "missing", "frame_ancestors": has_frame_ancestors},
            safe_for_report=True,
        )

    def _verify_csp_weakness(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="csp",
                error="Could not reach target",
            )
        csp = (resp.headers.get("content-security-policy") or "").lower()
        has_csp = bool(csp)
        unsafe_inline = "unsafe-inline" in csp
        unsafe_eval = "unsafe-eval" in csp
        verified = not has_csp or unsafe_inline or unsafe_eval
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="csp",
            confidence="high",
            evidence={"has_csp": has_csp, "unsafe_inline": unsafe_inline, "unsafe_eval": unsafe_eval},
            safe_for_report=True,
        )

    def _verify_cookies(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="cookies",
                error="Could not reach target",
            )
        set_cookies = resp.headers.get_all("set-cookie") if hasattr(resp.headers, 'get_all') else [resp.headers.get("set-cookie", "")]
        set_cookies = [c for c in set_cookies if c]

        insecure = []
        for cookie in set_cookies[:20]:
            c_lower = cookie.lower()
            has_secure = "secure" in c_lower
            has_httponly = "httponly" in c_lower
            has_samesite = "samesite" in c_lower
            if not has_secure or not has_httponly or not has_samesite:
                name = cookie.split("=")[0].strip()
                issues = []
                if not has_secure:
                    issues.append("missing Secure")
                if not has_httponly:
                    issues.append("missing HttpOnly")
                if not has_samesite:
                    issues.append("missing SameSite")
                insecure.append(f"{name}: {', '.join(issues)}")

        verified = len(insecure) > 0
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="cookies",
            confidence="high" if verified else "low",
            evidence={"insecure_cookies": insecure[:10], "total": len(set_cookies)},
            safe_for_report=True,
        )

    def _verify_hsts(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="hsts",
                error="Could not reach target",
            )
        hsts = (resp.headers.get("strict-transport-security") or "").lower()
        verified = not bool(hsts)
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="hsts",
            confidence="high",
            evidence={"hsts_header": hsts or "missing"},
            safe_for_report=True,
        )

    def _verify_xcto(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="x_content_type_options",
                error="Could not reach target",
            )
        xcto = (resp.headers.get("x-content-type-options") or "").lower()
        verified = "nosniff" not in xcto
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="x_content_type_options",
            confidence="high",
            evidence={"x_content_type_options": xcto or "missing"},
            safe_for_report=True,
        )

    def _verify_secret_leakage(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        if not resp:
            return VerificationResult(
                finding_id=finding.get("candidate_id", ""),
                verification_type="secret_leakage",
                error="Could not reach target",
            )
        body = resp.text[:100000]
        found = []
        for secret_type, pattern in SECRET_DETECTION_PATTERNS:
            for m in pattern.finditer(body):
                raw = m.group(0)
                found.append({"type": secret_type, "redacted": redact_secret(raw)})
                if len(found) >= 10:
                    break
            if len(found) >= 10:
                break

        verified = len(found) > 0
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="secret_leakage",
            confidence="high" if verified else "low",
            evidence={"secrets_found": found, "note": "Values REDACTED"},
            safe_for_report=True,
        )

    def _verify_outdated_tech(self, finding: dict, url: str) -> VerificationResult:
        base = self._build_url(url)
        resp = self._safe_get(base)
        evidence = finding.get("evidence", {})
        if resp:
            server = resp.headers.get("server", "")
            powered_by = resp.headers.get("x-powered-by", "")
            evidence["server_header"] = server
            evidence["x_powered_by"] = powered_by
            verified = bool(evidence.get("warnings", []))
        else:
            verified = bool(evidence.get("warnings", []))
        return VerificationResult(
            finding_id=finding.get("candidate_id", ""),
            verified=verified,
            verification_type="outdated_tech",
            confidence="medium",
            evidence=evidence,
            safe_for_report=True,
        )
