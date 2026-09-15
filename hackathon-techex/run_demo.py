"""End-to-end demo: two example self-scan reports (the exact shape
scan_own_domains.py's main() already produces), fed through the ledger and
diffed. Example data, clearly marked as such - not a live scan.

    python run_demo.py
"""
from __future__ import annotations

import os
import tempfile

from sipa_scan_ledger.adapter import records_from_self_scan_report
from sipa_scan_ledger.chain import ScanLedger
from sipa_scan_ledger.diff import diff_scans
from sipa_scan_ledger.verify import verify

# EXAMPLE reports, shaped exactly like scan_own_domains.py's real output -
# not a live scan result.
REPORT_DAY_1 = {
    "ran_at": "2026-10-16T08:00:00+00:00",
    "targets": {
        "sipa-os.org": [],
        "focus.sipa-os.org": [
            {"severity": "medium", "title": "Missing Content-Security-Policy"},
            {"severity": "low", "title": "Missing Referrer-Policy"},
        ],
    },
}

REPORT_DAY_8 = {
    "ran_at": "2026-10-23T08:00:00+00:00",
    "targets": {
        "sipa-os.org": [
            {"severity": "high", "title": "TLS cert expires in 6 days"},
        ],
        "focus.sipa-os.org": [
            {"severity": "low", "title": "Missing Referrer-Policy"},
        ],
    },
}


def main() -> None:
    log_path = os.path.join(tempfile.mkdtemp(), "scan_history.jsonl")
    ledger = ScanLedger(log_path)

    ledger.append_many(records_from_self_scan_report(REPORT_DAY_1))
    ledger.append_many(records_from_self_scan_report(REPORT_DAY_8))

    print("== sipa-os.org: 8 days apart ==")
    history = ledger.history_for("sipa-os.org")
    d = diff_scans(history[0], history[1])
    print(f"  new findings:      {d.new_findings}")
    print(f"  resolved findings: {d.resolved_findings}")
    print(f"  got_worse={d.got_worse()}  (a cert expiring soon showed up between scans)")

    print("\n== focus.sipa-os.org: 8 days apart ==")
    history = ledger.history_for("focus.sipa-os.org")
    d = diff_scans(history[0], history[1])
    print(f"  new findings:      {d.new_findings}")
    print(f"  resolved findings: {d.resolved_findings}")
    print(f"  improved={d.improved()}  (the CSP finding got fixed between scans)")

    res = verify(log_path)
    print(f"\nscan history: {res.count} entries - {'OK' if res.ok else 'FAIL: ' + str(res.problems)}")
    print(f"log file: {log_path}")


if __name__ == "__main__":
    main()
