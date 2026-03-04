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
from sentinel_containment.telemetry.sources import IngestionService, discover_live_file_sources


if __name__ == "__main__":
    cfg = Settings.load().data
    ingest_cfg = cfg.get("ingestion", {})

    ingestor = TelemetryIngestor(Path(ingest_cfg.get("index_path", "data/telemetry_index.jsonl")))
    extra_sources = {
        "host_kernel": Path(ingest_cfg.get("kernel_events_file", "data/kernel_events.jsonl")),
        "host_runtime": Path(ingest_cfg.get("runtime_events_file", "data/runtime_events.jsonl")),
        "host_osquery": Path(ingest_cfg.get("osquery_file", "data/osquery_events.jsonl")),
        "hypervisor": Path(ingest_cfg.get("hypervisor_events_file", "data/hypervisor_events.jsonl")),
        "counterclone": Path(ingest_cfg.get("counterclone_events_file", "data/counterclone_events.jsonl")),
    }
    extra_sources.update(discover_live_file_sources(extra_sources))
    service = IngestionService(
        ingestor=ingestor,
        syslog_host=ingest_cfg.get("syslog_host", "0.0.0.0"),
        syslog_port=int(ingest_cfg.get("syslog_port", 5514)),
        cloudtrail_path=Path(ingest_cfg.get("cloudtrail_file", "data/cloudtrail.jsonl")),
        network_flow_path=Path(ingest_cfg.get("network_flow_file", "data/network_flows.jsonl")),
        model_api_path=Path(ingest_cfg.get("model_api_file", "data/model_api.jsonl")),
        extra_sources=extra_sources,
        kernel_webhook_host=ingest_cfg.get("kernel_webhook_host", "0.0.0.0"),
        kernel_webhook_port=int(ingest_cfg.get("kernel_webhook_port", 5515)),
        kernel_webhook_path=ingest_cfg.get("kernel_webhook_path", "/kernel-event"),
        kernel_webhook_hmac_key=ingest_cfg.get("kernel_webhook_hmac_key") or settings.env("HEGEMON_KERNEL_WEBHOOK_HMAC_KEY", ""),
        kernel_webhook_hmac_required=bool(ingest_cfg.get("kernel_webhook_hmac_required", True)),
        kernel_webhook_hmac_max_skew_seconds=int(ingest_cfg.get("kernel_webhook_hmac_max_skew_seconds", 300)),
        counterclone_integrity_key=ingest_cfg.get("counterclone_integrity_key"),
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
