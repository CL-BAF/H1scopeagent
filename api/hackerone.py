"""HackerOne Hacker API client.

Handles both GraphQL (programs, scopes, policies) and REST (reports, simpler ops).
All operations are synchronous using httpx.Client.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from h1scopeagent.config import get_settings, redact_token_from_text


class H1ScopeAgentError(Exception):
    """Base exception for H1ScopeAgent."""


class NoTokenError(H1ScopeAgentError):
    """Raised when no API token is configured."""


class AuthError(H1ScopeAgentError):
    """Authentication failure (401, 403)."""


class RateLimitError(H1ScopeAgentError):
    """Rate limit hit, retry-after included."""

    def __init__(self, message: str, retry_after: float = 5):
        super().__init__(message)
        self.retry_after = retry_after


class APIError(H1ScopeAgentError):
    """General API error."""

    def __init__(self, message: str, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class HackerOneClient:
    """Synchronous HackerOne API client with auth, pagination, and rate-limit backoff."""

    def __init__(
        self,
        username: str | None = None,
        token: str | None = None,
        graphql_url: str | None = None,
        rest_base_url: str | None = None,
    ):
        settings = get_settings()
        self.username = username or settings.hackerone_username
        self.token = token or settings.hackerone_token
        self.graphql_url = graphql_url or settings.hackerone_graphql_url
        self.rest_base_url = rest_base_url or settings.hackerone_rest_base_url

        self._client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"H1ScopeAgent/0.1.0 (user:{self.username or 'unknown'})",
            },
        )

    def _ensure_auth(self) -> None:
        if not self.username or not self.token:
            raise NoTokenError(
                "HackerOne API credentials not set. Set HACKERONE_USERNAME and "
                "HACKERONE_TOKEN environment variables, or create a .env file."
            )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        self._ensure_auth()
        max_retries = 3

        for attempt in range(max_retries):
            try:
                resp = self._client.request(
                    method, url, headers=self._headers(), **kwargs
                )
            except httpx.TimeoutException:
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    time.sleep(wait)
                    continue
                raise APIError("Request timed out after multiple retries")

            if resp.status_code == 429:
                retry_after = _parse_retry_after(resp)
                if attempt < max_retries - 1:
                    time.sleep(retry_after)
                    continue
                raise RateLimitError("Rate limit exceeded", retry_after=retry_after)

            if resp.status_code in (401, 403):
                raise AuthError(
                    f"Authentication failed ({resp.status_code}). "
                    "Check your HACKERONE_USERNAME and HACKERONE_TOKEN."
                )

            if resp.status_code >= 500 and attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue

            if resp.status_code >= 400:
                raise APIError(
                    f"API error ({resp.status_code}): {_safe_body(resp)}",
                    status_code=resp.status_code,
                    body=_safe_body(resp),
                )

            return resp

        raise APIError("Maximum retries exceeded")

    def _graphql(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        resp = self._request("POST", self.graphql_url, json=payload)
        data = resp.json()

        if "errors" in data:
            msgs = [e.get("message", str(e)) for e in data["errors"]]
            raise APIError(f"GraphQL errors: {'; '.join(msgs)}")

        return data.get("data", {})

    def _graphql_paginate(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        *,
        path: list[str],
        page_size: int = 50,
    ) -> list[dict[str, Any]]:
        """Paginate through a GraphQL connection, yielding node dicts."""
        results: list[dict[str, Any]] = []
        cursor: str | None = None
        has_next = True

        while has_next:
            vars_with_pagination: dict[str, Any] = {
                **(variables or {}),
                "first": page_size,
            }
            if cursor:
                vars_with_pagination["after"] = cursor

            data = self._graphql(query, vars_with_pagination)

            container = data
            for segment in path:
                container = container.get(segment, {})

            edges = container.get("edges", [])
            for edge in edges:
                node = edge.get("node", {})
                if node:
                    results.append(node)

            page_info = container.get("pageInfo", {})
            has_next = page_info.get("hasNextPage", False)
            cursor = page_info.get("endCursor")
            if not has_next:
                break

        return results

    def test_auth(self) -> bool:
        """Quick auth test. Returns True if credentials work."""
        try:
            query = "query { current_user { username } }"
            data = self._graphql(query)
            user = data.get("current_user", {})
            return bool(user.get("username"))
        except (AuthError, NoTokenError, APIError):
            return False

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------
    def get_programs(self) -> list[dict[str, Any]]:
        query = """
        query($first: Int, $after: String) {
          teams(
            first: $first,
            after: $after,
            where: { submission_state: { _in: [open, pausable] } }
          ) {
            edges {
              node {
                handle
                name
                state
                offers_bounties
                currency
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
        """
        return self._graphql_paginate(
            query,
            path=["teams"],
        )

    def get_program_detail(self, handle: str) -> dict[str, Any]:
        query = """
        query($handle: String!) {
          team(handle: $handle) {
            handle
            name
            state
            offers_bounties
            currency
            profile_picture(size: medium)
            report_submission_form_state
            triage_active
          }
        }
        """
        data = self._graphql(query, {"handle": handle})
        return data.get("team", {})

    # ------------------------------------------------------------------
    # Structured Scopes
    # ------------------------------------------------------------------
    def get_structured_scopes(self, handle: str) -> list[dict[str, Any]]:
        query = """
        query($handle: String!, $first: Int, $after: String) {
          team(handle: $handle) {
            structured_scopes(
              first: $first,
              after: $after,
              archived: false
            ) {
              edges {
                node {
                  asset_identifier
                  asset_type
                  eligible_for_bounty
                  eligible_for_submission
                  max_severity
                  instruction
                  confidentiality
                }
              }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
        """
        return self._graphql_paginate(
            query,
            {"handle": handle},
            path=["team", "structured_scopes"],
        )

    # ------------------------------------------------------------------
    # Policy
    # ------------------------------------------------------------------
    def get_policy(self, handle: str) -> str:
        query = """
        query($handle: String!) {
          team(handle: $handle) {
            policy
          }
        }
        """
        data = self._graphql(query, {"handle": handle})
        return data.get("team", {}).get("policy", "")

    # ------------------------------------------------------------------
    # Reports (REST API)
    # ------------------------------------------------------------------
    def get_reports(
        self, program_handle: str, page: int = 1, per_page: int = 25
    ) -> dict[str, Any]:
        url = f"{self.rest_base_url}/hackers/reports"
        resp = self._request(
            "GET",
            url,
            params={
                "program": program_handle,
                "page": page,
                "per_page": per_page,
            },
        )
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _parse_retry_after(resp: httpx.Response) -> float:
    val = resp.headers.get("Retry-After", "5")
    try:
        return float(val)
    except (ValueError, TypeError):
        return 5.0


def _safe_body(resp: httpx.Response) -> str:
    try:
        text = resp.text
    except Exception:
        return "[body unreadable]"
    settings = get_settings()
    if settings.hackerone_token:
        text = redact_token_from_text(text, settings.hackerone_token)
    return text[:1000]
