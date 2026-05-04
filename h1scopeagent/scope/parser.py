"""Scope data normalization utilities."""

from urllib.parse import urlparse


def normalize_asset_identifier(raw: str) -> str:
    return raw.strip()


def classify_asset_type(identifier: str) -> str:
    ident = identifier.strip().lower()

    if ident.startswith("http://") or ident.startswith("https://"):
        return "url"
    if any(ident.endswith(ext) for ext in [".com", ".org", ".net", ".io", ".dev", ".app", ".co", ".gov", ".edu", ".mil"]):
        return "domain"
    if ident.startswith("*."):
        return "wildcard_domain"
    if ident.replace(".", "").replace(":", "").replace("/", "").isdigit():
        return "ip" if "/" not in ident else "ip_range"
    if ident.startswith("."):
        return "ip" if ident.count(".") >= 2 else "unknown"
    if ident.count(".") >= 3:
        parts = ident.split(".")
        if all(p.isdigit() for p in parts):
            return "ip"
    if ident.replace(".", "").isdigit():
        return "ip"
    if "github.com/" in ident.lower() or ident.lower().startswith("github.com"):
        return "github_repo"
    if ident.startswith("com.") or ident.startswith("org."):
        return "mobile_package"
    if "." in ident:
        return "domain"

    return "unknown"


def extract_domain_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname
