"""The fixed schema a scan turns into. Matches the real shape
`scan_own_domains.py` and `functions/api/scan.js` already produce -
`{severity, title}` findings per target - this module doesn't invent a new
finding format, it wraps the existing one so it can be chained and diffed.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Finding:
    severity: str   # "critical" | "high" | "medium" | "low" - as scan_own_domains.py emits
    title: str
    detail: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(severity=d["severity"], title=d["title"], detail=d.get("detail", ""))

    def to_dict(self) -> dict:
        d = {"severity": self.severity, "title": self.title}
        if self.detail:
            d["detail"] = self.detail
        return d


_SEVERITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class ScanRecord:
    target: str
    scanned_at: str          # ISO 8601, as produced by scan_own_domains.py / scan.js
    findings: list[Finding] = field(default_factory=list)

    def worst_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, -1)).severity

    def severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanRecord":
        return cls(
            target=d["target"],
            scanned_at=d["scanned_at"],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
        )
