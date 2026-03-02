from datetime import datetime, timedelta, timezone

from sentinel_containment.config import Settings
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.main import run_cycle
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


def test_graph_detector_builds_resource_edges_even_with_user_and_process():
    event = {
        "host": "h-1",
        "user": "alice",
        "process": "agent",
        "action": "model_invoke",
        "resource": "model://prod-a",
    }
    edges = GraphAnomalyDetector._event_edges(event)
    assert ("user:alice", "host:h-1", "accesses") in edges
    assert ("process:agent", "host:h-1", "runs_on") in edges
    assert ("host:h-1", "resource:model://prod-a", "model_invoke") in edges


def test_run_cycle_reports_multi_horizon_graph_summary(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    now = datetime.now(timezone.utc)
    ingestor.ingest(
        "model_api",
        {
            "host": "h-1",
            "user": "svc",
            "process": "gateway",
            "action": "model_invoke",
            "resource": "model-a",
            "timestamp": (now - timedelta(minutes=2)).isoformat(),
        },
    )
    ingestor.ingest(
        "model_api",
        {
            "host": "h-1",
            "user": "svc",
            "process": "gateway",
            "action": "network_send",
            "resource": "203.0.113.4",
            "timestamp": (now - timedelta(minutes=40)).isoformat(),
        },
    )

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "graph_horizons_minutes": [5, 30, 120],
            }
        )
    )

    assert [item["minutes"] for item in state["graph_horizon_summary"]] == [5, 30, 120]
    assert state["graph_horizon_summary"][0]["events"] >= 1
    assert "persistent_horizon_activity" in state
