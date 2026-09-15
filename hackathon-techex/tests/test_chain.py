from sipa_scan_ledger.chain import GENESIS, ScanLedger
from sipa_scan_ledger.record import Finding, ScanRecord


def test_chain_links(tmp_path):
    log = ScanLedger(tmp_path / "l.jsonl")
    e1 = log.append(ScanRecord("a.com", "t1", [Finding("low", "x")]))
    e2 = log.append(ScanRecord("b.com", "t2", []))
    assert e1["prev_hash"] == GENESIS
    assert e2["prev_hash"] == e1["hash"]


def test_reopen_continues_sequence(tmp_path):
    p = tmp_path / "l.jsonl"
    log = ScanLedger(p)
    log.append(ScanRecord("a.com", "t1", []))
    last = log.append(ScanRecord("a.com", "t2", []))

    reopened = ScanLedger(p)
    nxt = reopened.append(ScanRecord("a.com", "t3", []))
    assert nxt["seq"] == 2
    assert nxt["prev_hash"] == last["hash"]


def test_history_for_filters_by_target(tmp_path):
    log = ScanLedger(tmp_path / "l.jsonl")
    log.append(ScanRecord("a.com", "t1", [Finding("low", "x")]))
    log.append(ScanRecord("b.com", "t1", [Finding("high", "y")]))
    log.append(ScanRecord("a.com", "t2", []))

    history = log.history_for("a.com")
    assert len(history) == 2
    assert [r.scanned_at for r in history] == ["t1", "t2"]
