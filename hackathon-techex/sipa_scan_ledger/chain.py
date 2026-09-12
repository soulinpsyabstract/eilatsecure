"""Append-only, hash-chained history of scans. A business owner - or an
auditor, or a customer deciding whether to trust the report - can verify
this file was not edited after the fact, without trusting whoever ran the
scan."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .record import ScanRecord

GENESIS = "0" * 64
_PAYLOAD_KEYS = ("seq", "ts", "target", "scanned_at", "findings")


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_hash(prev_hash: str, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(_canonical({k: payload.get(k) for k in _PAYLOAD_KEYS}))
    return h.hexdigest()


class ScanLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._last_hash = GENESIS
        self._seq = 0
        if self.path.exists():
            self._replay()

    def _replay(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            self._last_hash = rec["hash"]
            self._seq = rec["seq"] + 1

    def append(self, record: ScanRecord) -> dict:
        payload = {
            "seq": self._seq,
            "ts": time.time(),
            "target": record.target,
            "scanned_at": record.scanned_at,
            "findings": [f.to_dict() for f in record.findings],
        }
        entry_hash = compute_hash(self._last_hash, payload)
        entry = {**payload, "prev_hash": self._last_hash, "hash": entry_hash}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._last_hash = entry_hash
        self._seq += 1
        return entry

    def append_many(self, records: list[ScanRecord]) -> list[dict]:
        return [self.append(r) for r in records]

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def history_for(self, target: str) -> list[ScanRecord]:
        """All scans of one target, in chain order - what diff_scans() compares."""
        return [
            ScanRecord.from_dict(e) for e in self.entries() if e["target"] == target
        ]
