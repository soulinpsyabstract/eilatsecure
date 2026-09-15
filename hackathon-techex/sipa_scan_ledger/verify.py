"""Recompute the hash chain from scratch. Run it against a ledger file you
did not produce and it still tells you whether the record is intact."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .chain import GENESIS, _PAYLOAD_KEYS, compute_hash


@dataclass
class VerifyResult:
    ok: bool
    count: int
    problems: list[str] = field(default_factory=list)


def verify(path: str | Path) -> VerifyResult:
    path = Path(path)
    if not path.exists():
        return VerifyResult(False, 0, [f"no such log: {path}"])
    problems: list[str] = []
    entries = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    prev = GENESIS
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            problems.append(f"entry {i}: seq is {e.get('seq')}, expected {i}")
        if e.get("prev_hash") != prev:
            problems.append(f"entry {i}: chain broken")
        expected = compute_hash(e.get("prev_hash", ""), {k: e.get(k) for k in _PAYLOAD_KEYS})
        if e.get("hash") != expected:
            problems.append(f"entry {i}: hash mismatch (altered)")
        prev = e.get("hash", "")
    return VerifyResult(ok=not problems, count=len(entries), problems=problems)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m sipa_scan_ledger.verify <ledger.jsonl>")
        return 2
    res = verify(argv[0])
    print(f"entries: {res.count}")
    if res.ok:
        print("OK - chain intact, nothing altered")
        return 0
    print("FAIL:")
    for p in res.problems:
        print(f"  - {p}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
