"""Append-only signed ledger with hash chaining."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from nacl import signing


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass
class LedgerEntry:
    ts: str
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str
    signature: str


class SignedLedger:
    def __init__(self, path: Path, signer: signing.SigningKey) -> None:
        self.path = path
        self.signer = signer
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("\n")

    def append(self, event_type: str, payload: Dict[str, Any]) -> LedgerEntry:
        prev_hash = self.last_hash()
        core = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        entry_hash = hashlib.sha256(_canonical(core)).hexdigest()
        signature = base64.b64encode(self.signer.sign(entry_hash.encode("utf-8")).signature).decode("ascii")
        entry = {**core, "entry_hash": entry_hash, "signature": signature}
        with self.path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry, sort_keys=True) + "\n")
        return LedgerEntry(**entry)

    def last_hash(self) -> str:
        entries = self.read_all()
        return entries[-1]["entry_hash"] if entries else "genesis"

    def read_all(self) -> List[Dict[str, Any]]:
        rows = []
        with self.path.open("r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                rows.append(json.loads(line))
        return rows

    def verify_chain(self) -> bool:
        prev = "genesis"
        for row in self.read_all():
            core = {"ts": row["ts"], "event_type": row["event_type"], "payload": row["payload"], "prev_hash": row["prev_hash"]}
            if row["prev_hash"] != prev:
                return False
            if hashlib.sha256(_canonical(core)).hexdigest() != row["entry_hash"]:
                return False
            prev = row["entry_hash"]
        return True
