"""sipa_scan_ledger: verifiable, diffable history for EilatSecure's passive
scans. Built for TechEx Amsterdam Hackathon (cybersecurity track) as new
work on top of the existing, live EilatSecure scanner - it does not modify
scan.js or scan_own_domains.py, only consumes what they already produce.

Today a scan is a one-off JSON blob: no proof it wasn't edited after the
fact, and no way to see what changed since the last scan of the same target
without diffing two files by hand. This adds both, without touching the
scanner itself.
"""
from .record import ScanRecord, Finding
from .chain import ScanLedger
from .verify import verify, VerifyResult
from .diff import diff_scans, ScanDiff
from .adapter import records_from_self_scan_report

__all__ = [
    "ScanRecord",
    "Finding",
    "ScanLedger",
    "verify",
    "VerifyResult",
    "diff_scans",
    "ScanDiff",
    "records_from_self_scan_report",
]
