from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel_containment.telemetry.schema import NormalizedEvent


class TelemetryIngestor:
    def __init__(self, output_path: Path = Path("data/telemetry_index.jsonl")):
        self.output_path = output_path

    def ingest(self, source_type: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        event = NormalizedEvent.from_raw(source_type, raw_event)
        doc = event.to_opensearch_doc()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(doc) + "\n")
        return doc

    def ingest_batch(self, source_type: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.ingest(source_type, e) for e in events]
