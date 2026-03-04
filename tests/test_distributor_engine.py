from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.security.distributor import SecurityDistributorEngine
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


def test_distributor_enriches_ingested_events(tmp_path: Path):
    telemetry_path = tmp_path / "telemetry.jsonl"
    distributor = SecurityDistributorEngine(risk_window_seconds=600)
    ingestor = TelemetryIngestor(telemetry_path, distributor_engine=distributor)

    payload = ingestor.ingest(
        "host_runtime",
        {
            "host": "node-a",
            "process": "agent-reader",
            "action": "file_read",
            "resource": "/etc/shadow",
            "collector_level": "runtime",
        },
    )

    assert payload["distributor"]["read_aware"] is True
    assert payload["distributor"]["sensitive_read"] is True
    assert payload["distributor"]["component"] == "node-a:agent-reader"


def test_runtime_exposes_distributor_snapshot(tmp_path: Path):
    rules = tmp_path / "rules"
    rules.mkdir()
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(rules),
        "peer_verification": {
            "interval_seconds": 1,
            "require_external_verifiers": False,
            "peer_ids": ["p1", "p2"],
            "checkpoint_quorum": 1,
            "checkpoint_signers": ["p1"],
            "replication_targets": ["notary-a"],
        },
        "ingestion": {
            "cloudtrail_file": str(tmp_path / "cloudtrail.jsonl"),
            "network_flow_file": str(tmp_path / "network_flows.jsonl"),
            "model_api_file": str(tmp_path / "model_api.jsonl"),
            "kernel_events_file": str(tmp_path / "kernel_events.jsonl"),
            "runtime_events_file": str(tmp_path / "runtime_events.jsonl"),
            "osquery_file": str(tmp_path / "osquery_events.jsonl"),
            "hypervisor_events_file": str(tmp_path / "hypervisor_events.jsonl"),
            "counterclone_events_file": str(tmp_path / "counterclone_events.jsonl"),
            "syslog_port": 0,
            "kernel_webhook_port": 0,
        },
    }
    runtime = SentinelRuntime(Settings(cfg))
    runtime.ingestor.ingest(
        "host_runtime",
        {
            "host": "node-a",
            "process": "agent-reader",
            "action": "read",
            "resource": "secret://token",
            "collector_level": "runtime",
        },
    )

    state = runtime.run_once()
    assert "distributor" in state
    assert state["distributor"]["total_reads"] >= 1
    runtime.ingestion_service.stop()
