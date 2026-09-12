from sipa_scan_ledger.record import Finding, ScanRecord


def test_roundtrip():
    r = ScanRecord("example.com", "2026-10-16T00:00:00Z",
                    [Finding("high", "No forced HTTPS redirect")])
    d = r.to_dict()
    back = ScanRecord.from_dict(d)
    assert back == r


def test_worst_severity():
    r = ScanRecord("x", "t", [Finding("low", "a"), Finding("critical", "b"), Finding("medium", "c")])
    assert r.worst_severity() == "critical"


def test_worst_severity_none_when_clean():
    r = ScanRecord("x", "t", [])
    assert r.worst_severity() is None


def test_severity_counts():
    r = ScanRecord("x", "t", [Finding("low", "a"), Finding("low", "b"), Finding("high", "c")])
    counts = r.severity_counts()
    assert counts["low"] == 2
    assert counts["high"] == 1
    assert counts["critical"] == 0
