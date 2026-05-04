"""Metadata extraction utilities for browser scouting.

Extracts and classifies page metadata: security headers, links,
source maps, technology fingerprints, etc.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


def parse_security_headers(headers_dict: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    result["csp_present"] = bool(headers_dict.get("content-security-policy"))
    csp = headers_dict.get("content-security-policy", "")
    if csp:
        result["csp_has_unsafe_inline"] = "unsafe-inline" in csp
        result["csp_has_unsafe_eval"] = "unsafe-eval" in csp
        result["csp_has_default_src"] = "default-src" in csp
        result["csp_uses_report_only"] = False

    csp_ro = headers_dict.get("content-security-policy-report-only", "")
    if csp_ro:
        result["csp_report_only_present"] = True

    result["hsts_present"] = bool(headers_dict.get("strict-transport-security"))
    hsts = headers_dict.get("strict-transport-security", "")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            result["hsts_max_age"] = int(max_age_match.group(1))
        result["hsts_include_subdomains"] = "includeSubDomains" in hsts
        result["hsts_preload"] = "preload" in hsts

    result["x_frame_options_present"] = bool(headers_dict.get("x-frame-options"))
    result["x_content_type_options_present"] = bool(headers_dict.get("x-content-type-options"))
    result["referrer_policy_present"] = bool(headers_dict.get("referrer-policy"))
    result["permissions_policy_present"] = bool(headers_dict.get("permissions-policy"))

    # CORS analysis
    acao = headers_dict.get("access-control-allow-origin")
    acac = headers_dict.get("access-control-allow-credentials")
    if acao:
        result["cors_origin"] = acao
        result["cors_wildcard"] = acao == "*"
        result["cors_credentials"] = acac and acac.lower() == "true"

    return result


def classify_links(
    links: list[dict[str, Any]], base_domain: str
) -> dict[str, Any]:
    base = base_domain.lower().lstrip("www.")
    internal: list[str] = []
    external: list[str] = []
    subdomain: list[str] = []
    suspicious: list[str] = []

    for link in links:
        href = link.get("href", "")
        if not href:
            continue
        try:
            parsed = urlparse(href)
            host = parsed.hostname or ""
        except Exception:
            continue

        if not host:
            internal.append(href)
            continue

        host_lower = host.lower()
        if host_lower == base or host_lower == f"www.{base}":
            internal.append(href)
        elif host_lower.endswith(f".{base}"):
            subdomain.append(href)
        else:
            external.append(href)

        # Suspicious patterns
        lower_href = href.lower()
        if any(kw in lower_href for kw in ["redirect", "url=", "next=", "return=", "goto=", "target="]):
            suspicious.append(href)

    return {
        "internal": len(internal),
        "subdomain": len(subdomain),
        "external": len(external),
        "total": len(links),
        "suspicious_redirect_params": suspicious[:20],
    }


def extract_source_maps(page_html: str) -> list[str]:
    maps: list[str] = []
    if not page_html:
        return maps
    pattern = re.compile(r"//#\s*sourceMappingURL=(.+?\.map)", re.IGNORECASE)
    for m in pattern.finditer(page_html):
        maps.append(m.group(1))
    return maps


def detect_technology_fingerprints(headers: dict[str, Any], html: str = "") -> list[str]:
    techs: list[str] = []
    h = {k.lower(): v for k, v in headers.items()} if headers else {}

    server = h.get("server", "")
    if server:
        techs.append(f"Server:{server}")

    powered = h.get("x-powered-by", "")
    if powered:
        techs.append(f"X-Powered-By:{powered}")

    if not html:
        return techs

    html_lower = html.lower()

    framework_signatures: dict[str, list[str]] = {
        "React": ["react", "react-dom", "__react"],
        "Vue.js": ["vue", "vue.js", "v-bind=", "v-if=", "v-for="],
        "Angular": ["ng-version", "angular", "ng-app", "ng-controller", "ng-module"],
        "jQuery": ["jquery", "jquery.min.js"],
        "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Drupal": ["drupal", "drupal.settings"],
        "Laravel": ["laravel", "csrf-token"],
        "Express": ["express", "x-powered-by: express"],
        "Django": ["django", "csrftoken"],
        "Ruby on Rails": ["rails", "csrf-param"],
        "ASP.NET": ["asp.net", "webforms", "__viewstate", "__eventvalidation"],
        "Next.js": ["next.js", "__next", "__NEXT_DATA__"],
        "Nuxt.js": ["nuxt", "__nuxt"],
        "Gatsby": ["gatsby", "___gatsby"],
    }

    for framework, signatures in framework_signatures.items():
        if any(sig.lower() in html_lower for sig in signatures):
            techs.append(framework)

    # Meta generator
    gen_match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.IGNORECASE,
    )
    if gen_match:
        techs.append(f"Generator:{gen_match.group(1)}")

    return techs
