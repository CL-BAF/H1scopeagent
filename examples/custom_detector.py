"""Example: Creating a custom finding detector.

Shows how to add a custom vulnerability detector to H1ScopeAgent.
"""

from h1scopeagent.findings.detector import FindingDetector
from urllib.parse import urlparse


class CustomDetector(FindingDetector):
    """Custom detector for Server-Timing header information disclosure."""

    def detect_all(self, program_handle: str, scout_result: dict) -> list[dict]:
        findings = super().detect_all(program_handle, scout_result)
        url = scout_result.get("original_url", "")

        timing_finding = self.check_server_timing(url, scout_result)
        if timing_finding:
            timing_finding["program_handle"] = program_handle
            timing_finding["candidate_id"] = self._generate_id(
                program_handle, "check_server_timing", url
            )
            timing_finding.setdefault("screenshot_path", scout_result.get("screenshot_path", ""))
            timing_finding.setdefault("metadata_path", scout_result.get("metadata_path", ""))
            timing_finding.setdefault("evidence", {})
            timing_finding.setdefault("report_ready", True)
            findings.append(timing_finding)

        return findings

    def check_server_timing(self, url: str, scout: dict) -> dict | None:
        """Detect Server-Timing header that may leak internal information."""
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        meta_data = {}
        import json
        try:
            meta_data = json.loads(scout.get("metadata_json", "{}"))
        except Exception:
            pass

        headers = meta_data.get("headers", {})
        server_timing = headers.get("server-timing", "")

        if not server_timing:
            return None

        sensitive_keywords = ["db", "cache", "redis", "sql", "queue", "internal", "service", "rpc"]
        leaked_metrics = []
        for metric in server_timing.split(","):
            metric = metric.strip()
            for kw in sensitive_keywords:
                if kw in metric.lower():
                    leaked_metrics.append(metric)
                    break

        if leaked_metrics:
            return self._make_finding(
                "check_server_timing",
                "Candidate: Server-Timing Header Information Disclosure",
                domain,
                confidence="medium",
                estimated_severity="low",
                evidence={
                    "server_timing_header": server_timing,
                    "leaked_metrics": leaked_metrics,
                },
                recommended_next_step=(
                    "Review Server-Timing header for internal infrastructure details. "
                    "Remove or restrict to authenticated users only."
                ),
            )

        return None


def demo():
    """Demonstrate the custom detector with sample data."""
    detector = CustomDetector()

    sample_scout = {
        "original_url": "https://api.example.com",
        "final_url": "https://api.example.com",
        "status_code": 200,
        "title": "Example API",
        "metadata_json": '{"headers": {"server-timing": "db;dur=53, cache;desc=\\"Redis\\";dur=12, app;dur=47"}}',
        "screenshot_path": "",
        "metadata_path": "",
    }

    findings = detector.detect_all("example-program", sample_scout)

    print(f"Detected {len(findings)} findings:")
    for f in findings:
        print(f"  - [{f.get('estimated_severity', '?')}] {f.get('title', '?')}")
        print(f"    Confidence: {f.get('confidence', '?')}")
        print(f"    Evidence: {f.get('evidence', {})}")


if __name__ == "__main__":
    demo()
