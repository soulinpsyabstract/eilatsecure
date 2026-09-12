from sipa_scan_ledger.adapter import records_from_self_scan_report

# Shape copied from scan_own_domains.py's own main(): report = {"ran_at": ..., "targets": {host: findings}}
SAMPLE_REPORT = {
    "ran_at": "2026-10-16T08:00:00+00:00",
    "targets": {
        "sipa-os.org": [],
        "focus.sipa-os.org": [
            {"severity": "medium", "title": "Missing Content-Security-Policy"},
        ],
        "shell.sipa-os.org": [
            {"severity": "critical", "title": "Unreachable over HTTPS", "detail": "timed out"},
        ],
    },
}


def test_one_record_per_target():
    records = records_from_self_scan_report(SAMPLE_REPORT)
    assert len(records) == 3
    targets = {r.target for r in records}
    assert targets == {"sipa-os.org", "focus.sipa-os.org", "shell.sipa-os.org"}


def test_scanned_at_taken_from_ran_at():
    records = records_from_self_scan_report(SAMPLE_REPORT)
    assert all(r.scanned_at == "2026-10-16T08:00:00+00:00" for r in records)


def test_findings_preserved():
    records = records_from_self_scan_report(SAMPLE_REPORT)
    by_target = {r.target: r for r in records}
    assert by_target["shell.sipa-os.org"].findings[0].severity == "critical"
    assert by_target["shell.sipa-os.org"].findings[0].detail == "timed out"
    assert by_target["sipa-os.org"].findings == []
