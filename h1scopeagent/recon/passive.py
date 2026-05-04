"""Passive non-invasive reconnaissance module.

Performs DNS lookups, WHOIS queries, HTTP header checks,
TLS certificate inspection, and safe file fetching.
All operations are synchronous and use conservative defaults.
"""

from __future__ import annotations

import socket
import ssl
import subprocess
import time
from urllib.parse import urljoin, urlparse

import httpx

from h1scopeagent.config import get_settings


class PassiveRecon:
    """Collection of passive recon methods, all read-only and non-invasive."""

    def __init__(self):
        self._client = httpx.Client(timeout=15.0, follow_redirects=False)
        self._last_request = 0.0

    def _rate_limit(self, min_interval: float = 1.0) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()

    def close(self) -> None:
        self._client.close()

    def dns_lookup(self, domain: str) -> dict:
        """Resolve domain to IP addresses using stdlib socket."""
        domain = domain.strip()
        try:
            addrs = socket.getaddrinfo(domain, None)
            ips = list({a[4][0] for a in addrs})
            return {
                "domain": domain,
                "ips": ips,
                "resolved": True,
                "error": None,
            }
        except socket.gaierror as e:
            return {
                "domain": domain,
                "ips": [],
                "resolved": False,
                "error": str(e),
            }

    def dns_cname_check(self, domain: str) -> dict:
        """Check CNAME for subdomain takeover indicators."""
        domain = domain.strip()
        try:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain, "CNAME", lifetime=5)
                cnames = [str(a.target).rstrip(".") for a in answers]
                return {
                    "domain": domain,
                    "cnames": cnames,
                    "check_error": None,
                }
            except ImportError:
                return {
                    "domain": domain,
                    "cnames": [],
                    "check_error": "dnspython package not installed; CNAME check unavailable",
                }
        except Exception as e:
            return {
                "domain": domain,
                "cnames": [],
                "check_error": str(e),
            }

    def whois_lookup(self, domain: str) -> dict | None:
        """WHOIS lookup via subprocess."""
        domain = domain.strip()
        try:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=15,
            )
            return {
                "domain": domain,
                "output": result.stdout[:5000],
                "exit_code": result.returncode,
            }
        except FileNotFoundError:
            return {
                "domain": domain,
                "output": None,
                "exit_code": -1,
                "error": "whois command not installed",
            }
        except subprocess.TimeoutExpired:
            return {
                "domain": domain,
                "output": None,
                "exit_code": -1,
                "error": "WHOIS query timed out",
            }
        except Exception as e:
            return {
                "domain": domain,
                "output": None,
                "exit_code": -1,
                "error": str(e),
            }

    def http_headers(self, url: str) -> dict | None:
        """Fetch HTTP response headers via HEAD request."""
        self._rate_limit()
        try:
            resp = self._client.head(url)
            return {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "error": None,
            }
        except Exception as e:
            return {
                "url": url,
                "status_code": 0,
                "headers": {},
                "error": str(e),
            }

    def tls_certificate(self, host: str, port: int = 443) -> dict:
        """Inspect TLS certificate using stdlib ssl."""
        host = host.strip()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            return {
                "host": host,
                "port": port,
                "certificate": cert,
                "error": None,
            }
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "certificate": None,
                "error": str(e),
            }

    def fetch_robots_txt(self, base_url: str) -> dict:
        """Fetch robots.txt."""
        self._rate_limit()
        url = urljoin(base_url.rstrip("/") + "/", "robots.txt")
        return self._safe_get(url, "robots.txt")

    def fetch_security_txt(self, base_url: str) -> dict:
        """Fetch security.txt from well-known and root locations."""
        self._rate_limit()
        base = base_url.rstrip("/")
        result = self._safe_get(f"{base}/.well-known/security.txt", "security.txt")
        if result.get("status_code") in (0, 404):
            result2 = self._safe_get(f"{base}/security.txt", "security.txt")
            if result2.get("status_code") > 0:
                return result2
        return result

    def fetch_sitemap(self, base_url: str) -> dict:
        """Fetch sitemap.xml."""
        self._rate_limit()
        url = urljoin(base_url.rstrip("/") + "/", "sitemap.xml")
        return self._safe_get(url, "sitemap.xml")

    def tech_fingerprint(self, url: str) -> dict:
        """Detect technology stack from HTTP headers and basic HTML."""
        self._rate_limit()
        try:
            resp = self._client.get(url)
        except Exception as e:
            return {"error": str(e), "technologies": []}

        techs = []
        headers = dict(resp.headers)

        server = headers.get("server", "")
        if server:
            techs.append(f"Server: {server}")

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            techs.append(f"X-Powered-By: {powered_by}")

        # Framework cookies
        set_cookies = headers.get("set-cookie", "")
        if "PHPSESSID" in set_cookies:
            techs.append("PHP")
        if "JSESSIONID" in set_cookies:
            techs.append("Java")
        if "ASP.NET_SessionId" in set_cookies or "ASPSESSIONID" in set_cookies:
            techs.append("ASP.NET")
        if "laravel_session" in set_cookies.lower():
            techs.append("Laravel")
        if "connect.sid" in set_cookies:
            techs.append("Express/Node.js")
        if "django" in set_cookies.lower() or "sessionid" in set_cookies.lower() and "csrftoken" in set_cookies.lower():
            techs.append("Django")

        # Headers
        if "x-drupal-cache" in headers:
            techs.append("Drupal")
        if "x-ua-compatible" in headers:
            techs.append("IE/Microsoft")
        if "cf-ray" in headers:
            techs.append("Cloudflare")

        return {
            "url": url,
            "status_code": resp.status_code,
            "technologies": techs,
        }

    def _safe_get(self, url: str, label: str = "") -> dict:
        try:
            resp = self._client.get(url)
            content = resp.text[:50000]
            return {
                "url": url,
                "status_code": resp.status_code,
                "content": content,
                "headers": dict(resp.headers),
                "error": None,
            }
        except Exception as e:
            return {
                "url": url,
                "status_code": 0,
                "content": "",
                "headers": {},
                "error": str(e),
            }
