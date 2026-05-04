"""Finding deduplication using content hashing and title similarity."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any


class FindingDeduplicator:
    """Deduplicate candidate findings by hash and similarity analysis."""

    def deduplicate(
        self,
        db: sqlite3.Connection,
        program_handle: str,
        all_findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if len(all_findings) <= 1:
            return all_findings

        seen_hashes: set[str] = set()
        duplicates: list[int] = []

        for i, f in enumerate(all_findings):
            hash_key = self._compute_hash(f)
            if hash_key in seen_hashes:
                duplicates.append(i)
            else:
                seen_hashes.add(hash_key)

        for idx in sorted(duplicates, reverse=True):
            dup = all_findings[idx]
            dup_id = dup.get("candidate_id", "")
            dup_title = dup.get("title", "")
            try:
                db.execute(
                    "DELETE FROM candidate_findings WHERE candidate_id = ?",
                    (dup_id,),
                )
            except Exception:
                pass

        remaining = [f for i, f in enumerate(all_findings) if i not in duplicates]
        return remaining

    def _compute_hash(self, finding: dict) -> str:
        candidate_type = finding.get("candidate_type", "")
        asset = finding.get("affected_asset", "")
        evidence = str(finding.get("evidence", {}))
        key = f"{candidate_type}|{asset}|{evidence}"
        return hashlib.sha256(key.encode()).hexdigest()

    def are_similar(self, f1: dict, f2: dict) -> bool:
        t1 = (f1.get("title", "") or "").lower()
        t2 = (f2.get("title", "") or "").lower()
        a1 = (f1.get("affected_asset", "") or "").lower()
        a2 = (f2.get("affected_asset", "") or "").lower()

        if a1 != a2:
            return False

        words1 = set(t1.split())
        words2 = set(t2.split())
        if not words1 or not words2:
            return False

        intersection = words1 & words2
        union = words1 | words2
        similarity = len(intersection) / len(union)

        return similarity > 0.7
