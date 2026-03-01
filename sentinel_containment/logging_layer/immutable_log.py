from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ImmutableAuditLog:
    def __init__(self, path: Path = Path("logs/immutable_audit.log"), out_of_band_path: Path | None = None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        mirror = out_of_band_path or (Path(os.getenv("AUDIT_OUT_OF_BAND_PATH")) if os.getenv("AUDIT_OUT_OF_BAND_PATH") else None)
        self.out_of_band_path = mirror
        if self.out_of_band_path:
            self.out_of_band_path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "GENESIS"
        with self.path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1]).get("entry_hash", "GENESIS")

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        prev = self._last_hash()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
            "prev_hash": prev,
        }
        digest = hashlib.sha256(json.dumps(entry, sort_keys=True).encode("utf-8")).hexdigest()
        entry["entry_hash"] = digest
        serialized = json.dumps(entry)

        with self.path.open("a", encoding="utf-8") as f:
            f.write(serialized + "\n")
            f.flush()
            os.fsync(f.fileno())

        if self.out_of_band_path:
            with self.out_of_band_path.open("a", encoding="utf-8") as f:
                f.write(serialized + "\n")
                f.flush()
                os.fsync(f.fileno())

        return entry
