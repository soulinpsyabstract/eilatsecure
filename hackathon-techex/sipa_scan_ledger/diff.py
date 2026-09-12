"""What changed between two scans of the same target. Matches findings by
title (the same check reported twice, same wording, from the same fixed
check list scan_own_domains.py / scan.js run) - a human reading this doesn't
re-read two full reports side by side, they read what's different."""
from __future__ import annotations

from dataclasses import dataclass, field

from .record import ScanRecord


@dataclass
class ScanDiff:
    target: str
    new_findings: list[dict] = field(default_factory=list)       # appeared since last scan
    resolved_findings: list[dict] = field(default_factory=list)  # gone since last scan
    unchanged_findings: list[dict] = field(default_factory=list)

    def got_worse(self) -> bool:
        return len(self.new_findings) > 0

    def improved(self) -> bool:
        return len(self.resolved_findings) > 0 and not self.new_findings


def diff_scans(before: ScanRecord, after: ScanRecord) -> ScanDiff:
    if before.target != after.target:
        raise ValueError(f"diffing scans of different targets: {before.target!r} vs {after.target!r}")

    before_titles = {f.title: f for f in before.findings}
    after_titles = {f.title: f for f in after.findings}

    new = [after_titles[t].to_dict() for t in after_titles.keys() - before_titles.keys()]
    resolved = [before_titles[t].to_dict() for t in before_titles.keys() - after_titles.keys()]
    unchanged = [after_titles[t].to_dict() for t in after_titles.keys() & before_titles.keys()]

    return ScanDiff(target=after.target, new_findings=new, resolved_findings=resolved,
                     unchanged_findings=unchanged)
