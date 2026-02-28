from __future__ import annotations

import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_containment.config import Settings
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import IngestionService


if __name__ == "__main__":
    cfg = Settings.load().data
    ingest_cfg = cfg.get("ingestion", {})

    ingestor = TelemetryIngestor(Path(ingest_cfg.get("index_path", "data/telemetry_index.jsonl")))
    service = IngestionService(
        ingestor=ingestor,
        syslog_host=ingest_cfg.get("syslog_host", "0.0.0.0"),
        syslog_port=int(ingest_cfg.get("syslog_port", 5514)),
        cloudtrail_path=Path(ingest_cfg.get("cloudtrail_file", "data/cloudtrail.jsonl")),
        network_flow_path=Path(ingest_cfg.get("network_flow_file", "data/network_flows.jsonl")),
        model_api_path=Path(ingest_cfg.get("model_api_file", "data/model_api.jsonl")),
    )

    state = {"stop": False}

    def _handle(*_: object) -> None:
        state["stop"] = True

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    service.start()
    print("Ingestion service started. Listening for syslog + JSONL file sources.")

    while not state["stop"]:
        time.sleep(1)

    service.stop()
    print("Ingestion service stopped.")
