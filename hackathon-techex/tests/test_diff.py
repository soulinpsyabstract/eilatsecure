import pytest

from sipa_scan_ledger.diff import diff_scans
from sipa_scan_ledger.record import Finding, ScanRecord


def test_new_finding_detected():
    before = ScanRecord("a.com", "t1", [Finding("low", "Missing HSTS")])
    after = ScanRecord("a.com", "t2", [Finding("low", "Missing HSTS"), Finding("high", "No forced HTTPS redirect")])
    d = diff_scans(before, after)
    assert len(d.new_findings) == 1
    assert d.new_findings[0]["title"] == "No forced HTTPS redirect"
    assert d.got_worse()


def test_resolved_finding_detected():
    before = ScanRecord("a.com", "t1", [Finding("high", "No forced HTTPS redirect")])
    after = ScanRecord("a.com", "t2", [])
    d = diff_scans(before, after)
    assert len(d.resolved_findings) == 1
    assert d.improved()
    assert not d.got_worse()


def test_unchanged_findings_tracked():
    before = ScanRecord("a.com", "t1", [Finding("low", "Missing HSTS")])
    after = ScanRecord("a.com", "t2", [Finding("low", "Missing HSTS")])
    d = diff_scans(before, after)
    assert len(d.unchanged_findings) == 1
    assert not d.new_findings and not d.resolved_findings


def test_different_targets_raises():
    before = ScanRecord("a.com", "t1", [])
    after = ScanRecord("b.com", "t2", [])
    with pytest.raises(ValueError):
        diff_scans(before, after)
