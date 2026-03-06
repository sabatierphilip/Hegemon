"""Append-only signed ledger with hash chaining."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import tempfile
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
    def __init__(self, path: Path, signer: signing.SigningKey, expected_owner: str | None = None) -> None:
        self.path = path
        self.signer = signer
        self.expected_owner = expected_owner
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        self._validate_permissions(self.path.parent, allowed_modes={0o700, 0o750})
        if not self.path.exists():
            with self.path.open("w", encoding="utf-8"):
                pass
            os.chmod(self.path, 0o600)
        self._validate_permissions(self.path, allowed_modes={0o600})
        if self.path.exists() and not self.verify_chain():
            import logging
            logging.getLogger(__name__).critical(
                "LEDGER INTEGRITY FAILURE: %s — chain or signature verification failed. Possible tampering detected.",
                self.path,
            )

    def _validate_permissions(self, target: Path, allowed_modes: set[int]) -> None:
        st = target.stat()
        mode = st.st_mode & 0o777
        if mode not in allowed_modes:
            raise PermissionError(f"unsafe permissions on {target}: {oct(mode)}")
        if self.expected_owner:
            expected_uid = pwd.getpwnam(self.expected_owner).pw_uid
            if st.st_uid != expected_uid:
                raise PermissionError(f"unsafe owner on {target}: uid={st.st_uid} expected={expected_uid}")

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
            fp.flush()
            os.fsync(fp.fileno())
        self._anchor_checkpoint(entry_hash)
        return LedgerEntry(**entry)

    def _anchor_checkpoint(self, entry_hash: str) -> None:
        anchor_path = self.path.with_suffix(self.path.suffix + ".anchor")
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "ledger": str(self.path),
            "entry_hash": entry_hash,
            "entries": len(self.read_all()),
        }
        fd, tmp_name = tempfile.mkstemp(prefix=anchor_path.name, dir=str(anchor_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                tmp.write(json.dumps(payload, sort_keys=True) + "\n")
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, anchor_path)
            os.chmod(anchor_path, 0o600)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

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
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    # tolerate interrupted final line, preserving prior chain continuity
                    break
        return rows

    def verify_chain(self) -> bool:
        verify_key = self.signer.verify_key
        prev = "genesis"
        for row in self.read_all():
            core = {
                "ts": row["ts"],
                "event_type": row["event_type"],
                "payload": row["payload"],
                "prev_hash": row["prev_hash"],
            }
            if row["prev_hash"] != prev:
                return False
            computed_hash = hashlib.sha256(_canonical(core)).hexdigest()
            if computed_hash != row["entry_hash"]:
                return False
            try:
                sig_bytes = base64.b64decode(row["signature"])
                verify_key.verify(row["entry_hash"].encode("utf-8"), sig_bytes)
            except Exception:
                return False
            prev = row["entry_hash"]
        return True
