from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.main import run_cycle
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import IngestionService


class SentinelRuntime:
    """Single-process orchestrator for ingestion, detection, containment, and dashboard state."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.latest_state_path = Path(settings.get("latest_state_path", "data/latest_state.json"))

        ingest_cfg = settings.get("ingestion", {})
        telemetry_path = Path(
            settings.get("telemetry_index_path", ingest_cfg.get("index_path", "data/telemetry_index.jsonl"))
        )
        ingestor = TelemetryIngestor(telemetry_path)
        self.baseline = BehavioralBaseline(
            threshold=float(settings.get("anomaly_threshold", 2.0)),
            window=int(settings.get("baseline_window", 30)),
            min_history=int(settings.get("baseline_min_history", 5)),
        )
        self.rule_engine = RuleEngine(
            Path(settings.get("rules_path", "rules")),
            dedup_window_seconds=int(settings.get("alert_dedup_window_seconds", 300)),
        )
        self.correlator = AlertCorrelator()

        self.ingestion_service = IngestionService(
            ingestor=ingestor,
            syslog_host=ingest_cfg.get("syslog_host", "0.0.0.0"),
            syslog_port=int(ingest_cfg.get("syslog_port", 5514)),
            cloudtrail_path=Path(ingest_cfg.get("cloudtrail_file", "data/cloudtrail.jsonl")),
            network_flow_path=Path(ingest_cfg.get("network_flow_file", "data/network_flows.jsonl")),
            model_api_path=Path(ingest_cfg.get("model_api_file", "data/model_api.jsonl")),
        )

    def run_once(self) -> dict:
        state = run_cycle(self.settings, baseline=self.baseline, rules=self.rule_engine, correlator=self.correlator)
        self.latest_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.latest_state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return state

    def _cycle_loop(self) -> None:
        interval = int(self.settings.get("refresh_minutes", 5)) * 60
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(interval)

    def start(self) -> None:
        self.ingestion_service.start()
        cycle_thread = threading.Thread(target=self._cycle_loop, daemon=True)
        cycle_thread.start()
        self._threads.append(cycle_thread)

    def stop(self) -> None:
        self._stop.set()
        self.ingestion_service.stop()
        for t in self._threads:
            t.join(timeout=2)
