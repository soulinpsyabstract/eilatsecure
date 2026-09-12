"""Bridges this module to the existing, unmodified scan_own_domains.py.

That script's main() builds and prints exactly this shape:

    {"ran_at": "<iso8601>", "targets": {"<host>": [{"severity", "title", ...}, ...], ...}}

(see scan_own_domains.py's own main(), read directly from the repo before
writing this - not guessed). This adapter turns that report dict into one
ScanRecord per host. It does not import or call scan_own_domains.py itself,
so this track can be built and tested without touching the existing script.
"""
from __future__ import annotations

from .record import Finding, ScanRecord


def records_from_self_scan_report(report: dict) -> list[ScanRecord]:
    ran_at = report["ran_at"]
    records = []
    for host, findings in report.get("targets", {}).items():
        records.append(ScanRecord(
            target=host,
            scanned_at=ran_at,
            findings=[Finding.from_dict(f) for f in findings],
        ))
    return records
