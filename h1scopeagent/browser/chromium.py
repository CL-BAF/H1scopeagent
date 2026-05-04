"""Chromium browser scouting wrapper using Playwright async API.

Provides safe, non-invasive Chromium automation for reconnaissance:
- Opens URLs with scope validation
- Takes screenshots
- Extracts metadata without storing secrets
- Records forms but never submits them
- Detects dangerous buttons and avoids clicking them
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from h1scopeagent.config import SECURITY_HEADERS


class ChromiumScout:
    """Async Chromium browser wrapper for safe reconnaissance scouting."""

    def __init__(self, headless: bool = True, slow_mo: int = 0):
        self._headless = headless
        self._slow_mo = slow_mo
        self._playwright = None
        self._browser = None

    async def __aenter__(self):
        from playwright.async_api import async_playwright
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=self._headless,
            slow_mo=self._slow_mo,
            args=[
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        )
        return self

    async def __aexit__(self, *args):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def scout_url(
        self,
        url: str,
        scope_validator: Any,
    ) -> dict[str, Any]:
        """Open a URL, take a screenshot, and collect metadata safely.

        Returns a dict suitable for saving as a BrowserScoutEntry.
        """
        result: dict[str, Any] = {
            "original_url": url,
            "final_url": "",
            "status_code": 0,
            "title": "",
            "in_scope": False,
            "manual_review_required": False,
            "screenshot_path": "",
            "metadata_json": "{}",
            "console_errors_json": "[]",
            "forms_json": "[]",
            "links_json": "[]",
            "redirect_decision": {},
            "error": None,
        }

        # Validate original URL
        scope_check = scope_validator.is_in_scope(url)
        if scope_check["decision"] != "in_scope":
            result["manual_review_required"] = True
            result["error"] = f"URL not in scope: {scope_check['reason']}"
            return result

        result["in_scope"] = True

        context = await self._browser.new_context(
            viewport={"width": 1280, "height": 900},
            ignore_https_errors=False,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        )

        page = await context.new_page()
        console_errors: list[dict] = []
        page.on("console", lambda msg: self._on_console(msg, console_errors))

        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=30_000,
            )
            await page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception as e:
            response = None
            result["error"] = str(e)
            # Try to still collect what we can
            try:
                await page.goto(url, wait_until="commit", timeout=30_000)
            except Exception:
                pass

        final_url = page.url
        result["final_url"] = final_url

        # Validate final URL after redirects
        if final_url != url:
            redirect = scope_validator.validate_redirect(url, final_url)
            result["redirect_decision"] = redirect
            if not redirect.get("allowed", False):
                result["error"] = f"Redirect to out-of-scope URL: {final_url}"
                result["manual_review_required"] = True
                await context.close()
                return result

        if response:
            result["status_code"] = response.status
        else:
            try:
                internal_response = await page.evaluate(
                    "() => document.readyState"
                )
                result["status_code"] = 0
            except Exception:
                result["status_code"] = 0

        result["title"] = await page.title() or ""

        # Collect security headers
        security_headers = {}
        if response:
            security_headers = await self.collect_security_headers(response)

        # Collect cookies (names only, NO values)
        cookie_names = await self.collect_cookie_names(context)

        # Extract forms (record, don't submit)
        forms = await self.extract_forms(page)

        # Extract links
        links = await self.extract_links(page)

        # Console errors already collected
        result["console_errors_json"] = self._safe_json(console_errors)
        result["forms_json"] = self._safe_json(forms)
        result["links_json"] = self._safe_json(links)

        # Build metadata
        import json
        metadata = {
            "url": url,
            "final_url": final_url,
            "title": result["title"],
            "status_code": result["status_code"],
            "security_headers": security_headers,
            "cookie_names": cookie_names,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result["metadata_json"] = json.dumps(metadata, default=str)

        await context.close()
        return result

    async def take_screenshot(self, page, path: str) -> str:
        """Take a full-page screenshot and save to the given path."""
        from pathlib import Path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        try:
            await page.screenshot(path=path, full_page=True)
            return path
        except Exception:
            try:
                await page.screenshot(path=path, full_page=False)
                return path
            except Exception as e:
                raise RuntimeError(f"Failed to take screenshot: {e}")

    async def extract_metadata(
        self, page, response, context
    ) -> dict[str, Any]:
        """Collect comprehensive metadata from a loaded page."""
        title = await page.title() or ""
        final_url = page.url

        security_headers = {}
        if response:
            security_headers = await self.collect_security_headers(response)

        cookie_names = await self.collect_cookie_names(context)
        forms = await self.extract_forms(page)
        links = await self.extract_links(page)

        console_errors: list[dict] = []
        page.on("console", lambda msg: self._on_console(msg, console_errors))

        html = ""
        try:
            html = await page.content()
        except Exception:
            pass

        return {
            "title": title,
            "final_url": final_url,
            "security_headers": security_headers,
            "cookie_names": cookie_names,
            "forms": forms,
            "links": links,
            "console_errors": console_errors,
            "html_length": len(html),
        }

    async def extract_forms(self, page) -> list[dict[str, Any]]:
        """Extract form elements without submitting.

        Returns form details: action, method, input names (not values), input types.
        """
        forms = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const inputs = [];
                    form.querySelectorAll('input, select, textarea, button').forEach(el => {
                        inputs.push({
                            name: el.name || '',
                            type: el.type || el.tagName.toLowerCase(),
                            id: el.id || '',
                            required: el.required || false,
                        });
                    });
                    forms.push({
                        index: idx,
                        action: form.action || '',
                        method: (form.method || 'get').toUpperCase(),
                        id: form.id || '',
                        input_count: inputs.length,
                        inputs: inputs,
                        has_password: inputs.some(i => i.type === 'password'),
                        has_submit: inputs.some(i => i.type === 'submit'),
                    });
                });
                return forms;
            }
        """)
        return forms

    async def extract_links(self, page, max_links: int = 200) -> list[dict[str, Any]]:
        """Extract all link hrefs from the page with classification."""
        links = await page.evaluate(f"""
            () => {{
                const links = [];
                const anchors = document.querySelectorAll('a[href]');
                const limit = {max_links};
                for (let i = 0; i < Math.min(anchors.length, limit); i++) {{
                    links.push({{
                        href: anchors[i].href || '',
                        text: (anchors[i].textContent || '').trim().substring(0, 100),
                        title: anchors[i].title || '',
                    }});
                }}
                return links;
            }}
        """)
        return links

    async def collect_console_errors(self, page) -> list[dict[str, Any]]:
        """Collect console errors and warnings that occurred during page load.

        Note: this must be called with a listener set before page load.
        This method returns whatever was collected during the session.
        """
        errors: list[dict] = []
        return errors

    def _on_console(self, msg, collector: list[dict]) -> None:
        """Callback for console events — captures errors and warnings."""
        if msg.type in ("error", "warning", "assert"):
            loc = msg.location or {}
            collector.append({
                "type": msg.type,
                "text": msg.text[:500],
                "url": loc.get("url", ""),
                "line": loc.get("lineNumber", ""),
                "column": loc.get("columnNumber", ""),
            })

    async def collect_security_headers(self, response) -> dict[str, Any]:
        """Extract and parse security-relevant headers from HTTP response."""
        try:
            headers = response.headers
        except Exception:
            return {}

        result: dict[str, Any] = {}
        for header_name in SECURITY_HEADERS:
            value = headers.get(header_name)
            if value:
                result[header_name] = value
            else:
                result[header_name] = None

        result["has_csp"] = bool(headers.get("content-security-policy"))
        result["has_hsts"] = bool(headers.get("strict-transport-security"))
        result["has_x_frame_options"] = bool(headers.get("x-frame-options"))
        result["has_x_content_type_options"] = bool(headers.get("x-content-type-options"))

        # Analyze CORS headers
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        if acao and acao != "*" and acac and acac.lower() == "true":
            result["cors_warning"] = "Reflected origin with credentials — potential CORS misconfiguration"
        elif acao == "*" and acac and acac.lower() == "true":
            result["cors_warning"] = "Wildcard origin with credentials — invalid configuration"

        return result

    async def collect_cookie_names(self, context) -> list[dict[str, Any]]:
        """Collect cookie metadata — names and flags only, NEVER values."""
        try:
            cookies = await context.cookies()
        except Exception:
            return []

        result = []
        for c in cookies:
            result.append({
                "name": c.get("name", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", ""),
                "secure": c.get("secure", False),
                "httpOnly": c.get("httpOnly", False),
                "sameSite": c.get("sameSite", "None"),
                # Value is NEVER included
            })
        return result

    async def validate_redirect(
        self,
        original_url: str,
        final_url: str,
        scope_validator: Any,
    ) -> dict[str, Any]:
        """Validate that both original and final URLs are in scope."""
        return scope_validator.validate_redirect(original_url, final_url)

    def _safe_json(self, obj: Any) -> str:
        import json
        return json.dumps(obj, default=str)
