from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class NormalizedEvent:
    timestamp: str
    host: str
    user: str
    process: str
    action: str
    resource: str
    source_type: str
    metadata: dict[str, Any]

    @classmethod
    def from_raw(cls, source_type: str, payload: dict[str, Any]) -> "NormalizedEvent":
        return cls(
            timestamp=payload.get("timestamp", datetime.now(timezone.utc).isoformat()),
            host=payload.get("host", "unknown"),
            user=payload.get("user", "unknown"),
            process=payload.get("process", payload.get("service", "unknown")),
            action=payload.get("action", payload.get("event", "unknown")),
            resource=payload.get("resource", payload.get("target", "unknown")),
            source_type=source_type,
            metadata={k: v for k, v in payload.items() if k not in {"timestamp", "host", "user", "process", "action", "resource"}},
        )

    def to_opensearch_doc(self) -> dict[str, Any]:
        doc = asdict(self)
        doc["@timestamp"] = doc.pop("timestamp")
        # Keep metadata nested, but also expose scalar metadata keys at top-level
        # so simple rule engines can match on fields like `api_call_count`.
        for key, value in self.metadata.items():
            if key not in doc and isinstance(value, (str, int, float, bool)):
                doc[key] = value
        return doc
