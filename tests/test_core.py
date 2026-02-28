from datetime import datetime, timedelta, timezone

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.main import run_cycle
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import JSONLinesFileSource, parse_syslog_line


def test_asset_snapshot_contains_nodes(tmp_path):
    mapper = AssetMapper(CloudProviderAdapter(simulated=True), snapshot_path=tmp_path / "topology.json")
    snap = mapper.snapshot()
    assert snap["nodes"]


def test_rule_engine_deduplicates_with_cooldown(tmp_path):
    dedup_state = tmp_path / "dedup.json"
    engine = RuleEngine(cooldown_seconds=300, dedup_state_path=dedup_state)

    now = datetime.now(timezone.utc)
    event1 = {"host": "h1", "action": "model_invoke", "api_call_count": 900, "@timestamp": now.isoformat()}
    event2 = {
        "host": "h1",
        "action": "model_invoke",
        "api_call_count": 920,
        "@timestamp": (now + timedelta(seconds=60)).isoformat(),
    }
    event3 = {
        "host": "h1",
        "action": "model_invoke",
        "api_call_count": 950,
        "@timestamp": (now + timedelta(seconds=400)).isoformat(),
    }

    assert len(engine.evaluate(event1)) >= 1
    assert len(engine.evaluate(event2)) == 0
    assert len(engine.evaluate(event3)) >= 1


def test_baseline_mad_detects_after_training():
    baseline = BehavioralBaseline(threshold=2.0, window=14, min_history=5)
    host = "h1"
    for value in [100, 110, 95, 105, 108, 102]:
        baseline.update_and_detect(host, {"api_call_rate": value})

    anomalies = baseline.update_and_detect(host, {"api_call_rate": 800})
    assert anomalies
    assert anomalies[0].method in {"mad", "ratio"}


def test_correlator_uses_weighted_risk():
    correlator = AlertCorrelator(model_spike_weight=0.25, egress_weight=0.30, privilege_weight=0.45, correlation_bonus=10)

    class A:
        def __init__(self):
            self.rule = "Unauthorized IAM Privilege Changes"
            self.severity = 90
            self.event = {"host": "h1", "action": "iam_privilege_change", "api_call_count": 100, "egress_mb": 20}

    class B:
        def __init__(self):
            self.metric = "api_call_rate"
            self.current = 800
            self.avg = 100
            self.deviation_ratio = 8
            self.severity = 70

    result = correlator.correlate([A()], [B()])
    assert result is not None
    assert result.severity >= 60
    assert "iam_risk" in result.tags


def test_containment_two_person_approval(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(audit)
    denied = engine.execute("h1", 90, ["quarantine_host"], ["alice"])
    assert not denied.approved
    allowed = engine.execute("h1", 90, ["quarantine_host"], ["alice", "bob"])
    assert allowed.approved


def test_run_cycle_with_real_ingested_events(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    # Baseline training samples
    for v in [100, 110, 95, 105, 108, 102]:
        ingestor.ingest(
            "model_api",
            {
                "host": "prod-model-1",
                "user": "svc-prod",
                "process": "gateway",
                "action": "model_invoke",
                "resource": "model-a",
                "api_call_count": v,
                "egress_mb": 90,
                "gpu_cpu": 30,
            },
        )

    # Spike
    ingestor.ingest(
        "model_api",
        {
            "host": "prod-model-1",
            "user": "svc-prod",
            "process": "gateway",
            "action": "model_invoke",
            "resource": "model-a",
            "api_call_count": 900,
            "egress_mb": 950,
            "gpu_cpu": 97,
        },
    )

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "containment_severity_threshold": 70,
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_training_required": True,
                "baseline_min_history": 5,
            }
        )
    )

    assert state["events_processed"] == 7
    assert state["baseline_anomalies"]
    assert state["correlated"] is not None


def test_jsonl_source_and_syslog_parser(tmp_path):
    index_path = tmp_path / "index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    source_file = tmp_path / "cloudtrail.jsonl"
    source_file.write_text('{"host":"cloud-1","action":"iam_privilege_change","user":"unknown"}\n', encoding="utf-8")

    source = JSONLinesFileSource(source_file, "cloud_audit", ingestor)
    assert source.poll_once() == 1
    docs = ingestor.read_recent()
    assert docs and docs[0]["source_type"] == "cloud_audit"

    parsed = parse_syslog_line("<13>Jan 10 12:00:00 host1 sshd: Failed login")
    assert parsed["host"] == "host1"


def test_runtime_run_once_writes_latest_state(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    TelemetryIngestor(index_path).ingest(
        "model_api",
        {
            "host": "host-x",
            "action": "model_invoke",
            "api_call_count": 800,
            "egress_mb": 900,
            "gpu_cpu": 85,
        },
    )

    state_path = tmp_path / "latest_state.json"
    runtime = SentinelRuntime(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "latest_state_path": str(state_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "ingestion": {
                    "syslog_host": "127.0.0.1",
                    "syslog_port": 0,
                    "cloudtrail_file": str(tmp_path / "c.jsonl"),
                    "network_flow_file": str(tmp_path / "n.jsonl"),
                    "model_api_file": str(tmp_path / "m.jsonl"),
                },
            }
        )
    )

    state = runtime.run_once()
    assert state_path.exists()
    assert state["events_processed"] >= 1
