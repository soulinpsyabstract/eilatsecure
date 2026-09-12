import json

from sipa_scan_ledger.chain import ScanLedger
from sipa_scan_ledger.record import Finding, ScanRecord
from sipa_scan_ledger.verify import verify


def _populate(path):
    log = ScanLedger(path)
    log.append(ScanRecord("a.com", "t1", [Finding("high", "No forced HTTPS redirect")]))
    log.append(ScanRecord("a.com", "t2", []))
    return log


def test_clean_ledger_verifies(tmp_path):
    p = tmp_path / "l.jsonl"
    _populate(p)
    res = verify(p)
    assert res.ok
    assert res.count == 2


def test_missing_file(tmp_path):
    res = verify(tmp_path / "nope.jsonl")
    assert not res.ok


def test_altered_entry_is_caught(tmp_path):
    p = tmp_path / "l.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["findings"] = []  # quietly erase the finding
    lines[0] = json.dumps(tampered)
    p.write_text("\n".join(lines) + "\n")
    res = verify(p)
    assert not res.ok
    assert any("altered" in x for x in res.problems)
