# hackathon-techex — Verifiable Scan History

New work for the [TechEx Amsterdam Hackathon](https://lablab.ai/ai-hackathons/techex-amsterdam-hackathon)
(cybersecurity track, online build 16–19 Oct 2026), built on top of the
existing live EilatSecure scanner — **does not modify** `scan.js` or
`scan_own_domains.py` at the repo root, only consumes what they already
produce.

Full concept and track status:
[docs/BUILD_PLAN.md](docs/BUILD_PLAN.md)

## The gap

A scan today is a one-off JSON blob: nothing proves it wasn't edited after
the fact, and comparing two scans of the same site means reading two files
by hand. Both are real gaps in a product that's already live.

## Quickstart (no network calls, no changes to the live scanner)

```bash
cd hackathon-techex
pip install -e ".[dev]"
python run_demo.py     # example data, shaped exactly like the real scanner's output
pytest -q              # 17 tests
```

```python
from sipa_scan_ledger import ScanLedger, ScanRecord, Finding, diff_scans

ledger = ScanLedger("scan_history.jsonl")
ledger.append(ScanRecord("example.com", "2026-10-16T08:00:00Z",
                          [Finding("high", "No forced HTTPS redirect")]))
```

## Structure

| Module | What it does | Status |
| --- | --- | --- |
| `sipa_scan_ledger/record.py` | Fixed schema wrapping the scanner's existing finding format | built, tested |
| `sipa_scan_ledger/chain.py` + `verify.py` | Hash-chained history + tamper check | built, tested |
| `sipa_scan_ledger/diff.py` | What changed between two scans of the same target | built, tested |
| `sipa_scan_ledger/adapter.py` | Converts `scan_own_domains.py`'s real report shape into ledger entries | built, tested |

## What's still open (see the plan for skill-matched slots)

- Wire the adapter into a real scheduled run of `scan_own_domains.py`
- A diff view on the EilatSecure landing page, not just terminal output
- Demo video + lablab.ai submission

Team: solo on this hackathon (the only other teammate on the team page
opted out of TechEx Amsterdam specifically) — the tracks above are scoped
for anyone who joins, not written assuming they will.
