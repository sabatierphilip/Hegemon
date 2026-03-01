from pathlib import Path

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
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


def test_rule_engine_detects_excessive_calls():
    engine = RuleEngine()
    alerts = engine.evaluate({"action": "model_invoke", "api_call_count": 900})
    assert any("Excessive Model API Calls" == a.rule for a in alerts)


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
            }
        )
    )

    assert state["events_processed"] == 1
    assert state["correlated"] is not None
    assert state["baseline_ready"] is False
    assert state["containment"] is None


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


def test_rule_engine_dedup_window_suppresses_duplicates():
    engine = RuleEngine(dedup_window_seconds=300)
    event = {
        "@timestamp": "2024-01-01T00:00:00+00:00",
        "host": "prod-model-1",
        "action": "model_invoke",
        "api_call_count": 900,
    }
    first = engine.evaluate(event)
    second = engine.evaluate({**event, "@timestamp": "2024-01-01T00:02:00+00:00"})
    third = engine.evaluate({**event, "@timestamp": "2024-01-01T00:06:00+00:00"})

    assert first
    assert second == []
    assert third and third[0].dedup_hits == 2


def test_run_cycle_generates_baseline_anomalies_after_training(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    for _ in range(6):
        ingestor.ingest(
            "model_api",
            {
                "host": "prod-model-1",
                "action": "model_invoke",
                "api_call_count": 120,
                "egress_mb": 20,
                "gpu_cpu": 40,
            },
        )

    ingestor.ingest(
        "model_api",
        {
            "host": "prod-model-1",
            "action": "model_invoke",
            "api_call_count": 800,
            "egress_mb": 90,
            "gpu_cpu": 91,
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
                "baseline_min_history": 5,
            }
        )
    )

    assert state["baseline_ready"] is True
    assert state["baseline_anomalies"]


def test_correlator_privilege_weighting_beats_model_only():
    from sentinel_containment.detection.correlator import AlertCorrelator
    from sentinel_containment.detection.rule_engine import DetectionAlert

    correlator = AlertCorrelator()
    model_alert = DetectionAlert("Excessive Model API Calls", "desc", 70, {"host": "h1"})
    iam_alert = DetectionAlert("Unauthorized IAM Privilege Change", "desc", 70, {"host": "h1"})

    model_score = correlator.correlate([model_alert], [])
    iam_score = correlator.correlate([iam_alert], [])

    assert model_score is not None and iam_score is not None
    assert iam_score.severity > model_score.severity


def test_graph_detector_flags_novel_edges_after_warmup():
    detector = GraphAnomalyDetector(warmup_events=2)
    no_alerts_1 = detector.evaluate({"host": "h1", "user": "u1", "action": "model_invoke"})
    no_alerts_2 = detector.evaluate({"host": "h1", "process": "p1", "action": "process_start"})
    alerts = detector.evaluate({"host": "h9", "user": "intruder", "action": "iam_privilege_change"})

    assert no_alerts_1 == []
    assert no_alerts_2 == []
    assert alerts and "Graph edge outlier" in alerts[0].reason


def test_attack_sequence_detects_multistage_chain():
    model = AttackSequenceModel(chain_window_minutes=60)
    events = [
        {"host": "h1", "@timestamp": "2024-01-01T00:00:00+00:00", "action": "login_failure"},
        {"host": "h1", "@timestamp": "2024-01-01T00:03:00+00:00", "action": "container_spawn"},
        {"host": "h1", "@timestamp": "2024-01-01T00:05:00+00:00", "action": "iam_privilege_change"},
        {"host": "h1", "@timestamp": "2024-01-01T00:08:00+00:00", "action": "model_invoke"},
        {"host": "h1", "@timestamp": "2024-01-01T00:10:00+00:00", "action": "network_send", "egress_mb": 900},
    ]

    alerts = model.evaluate(events)
    assert alerts
    assert alerts[0].host == "h1"
    assert "exfiltration" in alerts[0].stages




def test_containment_simulation_before_quarantine(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(audit)
    result = engine.execute(
        "h2",
        85,
        ["disable_outbound_traffic", "quarantine_host"],
        ["alice", "bob"],
        simulation_mode=True,
        hard_quarantine_threshold=90,
        simulation_context={"blast_radius": {"impacted_hosts": ["h2"], "impacted_resources": ["model-a"]}},
    )

    assert result.approved
    assert "simulate_quarantine_host" in result.actions_executed
    assert "quarantine_host" not in result.actions_executed


def test_run_cycle_emits_graph_and_chain_outputs(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    samples = [
        {"host": "h1", "user": "alice", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "process": "runner", "action": "container_spawn", "resource": "container-A"},
        {"host": "h1", "user": "unknown", "action": "iam_privilege_change", "resource": "admin-role"},
        {"host": "h1", "action": "model_invoke", "resource": "model-a", "api_call_count": 700},
        {"host": "h1", "action": "network_send", "resource": "8.8.8.8", "egress_mb": 950},
        {"host": "h9", "user": "intruder", "action": "network_send", "resource": "9.9.9.9", "egress_mb": 980},
    ]
    for s in samples:
        ingestor.ingest("network_flow", s)

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "graph_warmup_events": 2,
                "attack_chain_window_minutes": 60,
            }
        )
    )

    assert state["graph_anomalies"]
    assert state["attack_chains"]
    assert state["credential_blast_radius"]["estimated_impact_score"] >= 30


def test_rule_engine_detects_distributed_near_threshold_burst():
    engine = RuleEngine(dedup_window_seconds=0)
    events = [
        {"@timestamp": "2024-01-01T00:00:00+00:00", "action": "model_invoke", "user": "u1", "api_call_count": 420},
        {"@timestamp": "2024-01-01T00:01:00+00:00", "action": "model_invoke", "user": "u2", "api_call_count": 430},
        {"@timestamp": "2024-01-01T00:02:00+00:00", "action": "model_invoke", "user": "u3", "api_call_count": 415},
        {"@timestamp": "2024-01-01T00:03:00+00:00", "action": "model_invoke", "user": "u4", "api_call_count": 450},
    ]
    alerts = []
    for event in events:
        alerts.extend(engine.evaluate(event))

    assert any(alert.rule == "Excessive Model API Calls" for alert in alerts)


def test_containment_approval_normalization_avoids_same_identity_double_vote(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(audit, identity_store={"alice": ["Alice", "alice@corp"]})
    denied = engine.execute("h1", 95, ["quarantine_host"], ["Alice", "alice@corp"])

    assert not denied.approved


def test_blast_radius_looks_at_resource_and_metadata_tokens():
    from sentinel_containment.containment.blast_radius import CredentialBlastRadiusAnalyzer

    analyzer = CredentialBlastRadiusAnalyzer()
    report = analyzer.analyze(
        [
            {
                "user": "svc1",
                "host": "h1",
                "action": "status_check",
                "resource": "prod-secret-vault",
                "metadata": {"target": "credential-bundle"},
            }
        ],
        {"edges": []},
    )

    assert report.compromised_credentials == ["svc1"]


def test_immutable_log_mirrors_to_out_of_band_sink(tmp_path):
    primary = tmp_path / "audit.log"
    mirror = tmp_path / "audit_oob.log"
    log = ImmutableAuditLog(primary, out_of_band_path=mirror)

    log.append("event", {"k": "v"})

    assert primary.exists() and mirror.exists()
    assert primary.read_text(encoding="utf-8") == mirror.read_text(encoding="utf-8")


def test_run_cycle_raises_honeypot_alert(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    ingestor.ingest(
        "model_api",
        {
            "host": "prod-model-1",
            "user": "svc-prod",
            "action": "status",
            "resource": "decoy://llm-admin",
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
                "honeypot_resources": ["decoy://llm-admin"],
                "baseline_min_history": 5,
            }
        )
    )

    assert state["honeypot_alerts"]
    assert state["candidate_severity"] >= 99
