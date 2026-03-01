from pathlib import Path

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.mirror_clone import MirrorAlert, MirrorCloneDetector
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



def test_runtime_persists_mirror_clone_detector_across_cycles(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    ingestor.ingest(
        "model_api",
        {
            "host": "host-m",
            "user": "svc-m",
            "action": "model_invoke",
            "resource": "model-a",
            "api_call_count": 120,
            "egress_mb": 5,
            "gpu_cpu": 10,
        },
    )

    runtime = SentinelRuntime(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "latest_state_path": str(tmp_path / "latest_state.json"),
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

    detector_id = id(runtime.mirror_clone_detector)
    runtime.run_once()
    first_seen_count = runtime.mirror_clone_detector._seen_events

    ingestor.ingest(
        "model_api",
        {
            "host": "host-m",
            "user": "svc-m",
            "action": "model_download",
            "resource": "repo://weights-v2",
        },
    )
    runtime.run_once()

    assert id(runtime.mirror_clone_detector) == detector_id
    assert runtime.mirror_clone_detector._seen_events > first_seen_count


def test_run_forever_reuses_detector_instances(monkeypatch):
    from sentinel_containment import main

    calls = []

    def fake_run_cycle(settings, **kwargs):
        calls.append(kwargs)
        return {}

    def fake_sleep(_):
        if len(calls) >= 2:
            raise RuntimeError("stop-loop")

    monkeypatch.setattr(main, "run_cycle", fake_run_cycle)
    monkeypatch.setattr(main.time, "sleep", fake_sleep)

    try:
        main.run_forever("config/config.yaml")
    except RuntimeError as exc:
        assert str(exc) == "stop-loop"

    assert len(calls) == 2
    first_call = calls[0]
    second_call = calls[1]
    assert first_call["baseline"] is second_call["baseline"]
    assert first_call["graph_detector"] is second_call["graph_detector"]
    assert first_call["mirror_clone_detector"] is second_call["mirror_clone_detector"]


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


def test_baseline_detects_deviation_when_mad_collapses_to_zero():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5)
    for _ in range(30):
        baseline.update_and_detect("h1", {"api_call_rate": 100.0})

    anomalies = baseline.update_and_detect("h1", {"api_call_rate": 150.0})

    assert anomalies
    assert anomalies[0].metric == "api_call_rate"


def test_baseline_resists_fast_window_flush_rebasing():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5)
    for _ in range(30):
        baseline.update_and_detect("h1", {"api_call_rate": 50.0})

    for _ in range(30):
        baseline.update_and_detect("h1", {"api_call_rate": 0.1})

    anomalies = baseline.update_and_detect("h1", {"api_call_rate": 9.9})

    assert anomalies


def test_graph_detector_tracks_unknown_events_instead_of_dropping_them():
    detector = GraphAnomalyDetector(warmup_events=1)
    detector.evaluate({"host": "h1", "action": "unknown", "resource": "unknown"})
    alerts = detector.evaluate({"host": "h9", "action": "unknown", "resource": "unknown"})

    assert alerts
    assert alerts[0].relation == "unknown_activity"


def test_graph_detector_flags_novel_edges_after_warmup():
    detector = GraphAnomalyDetector(warmup_events=2)
    no_alerts_1 = detector.evaluate({"host": "h1", "user": "u1", "action": "model_invoke"})
    no_alerts_2 = detector.evaluate({"host": "h1", "process": "p1", "action": "process_start"})
    alerts = detector.evaluate({"host": "h9", "user": "intruder", "action": "iam_privilege_change"})

    assert no_alerts_1 == []
    assert no_alerts_2 == []
    assert alerts and "Graph edge outlier" in alerts[0].reason


def test_graph_detector_service_activity_does_not_alert_on_every_new_resource():
    detector = GraphAnomalyDetector(warmup_events=2)
    detector.evaluate({"host": "h1", "action": "model_invoke", "resource": "model-a"})
    detector.evaluate({"host": "h1", "action": "model_invoke", "resource": "model-b"})
    alerts = detector.evaluate({"host": "h1", "action": "model_invoke", "resource": "model-c"})

    assert alerts == []


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
    assert state["honeypot_alerts"][0]["classification"] == "honeypot_tripwire"
    assert state["honeypot_alerts"][0]["kill_chain_recommended"] is False
    assert state["candidate_severity"] >= 99


def test_run_cycle_proto_agi_honeypot_triggers_immediate_kill_chain(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    ingestor.ingest(
        "model_api",
        {
            "host": "prod-model-9",
            "user": "svc-orchestrator",
            "action": "autonomous_replication",
            "resource": "decoy://llm-admin",
            "metadata": {"intent": "Recursive Self-Improvement and policy evasion"},
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
                "baseline_min_history": 50,
            }
        )
    )

    assert state["baseline_ready"] is False
    assert state["immediate_honeypot_containment"] is True
    assert state["containment"] is not None
    assert "kill_active_model_sessions" in state["containment"]["actions_executed"]
    assert "quarantine_host" in state["containment"]["actions_executed"]
    assert state["honeypot_alerts"][0]["classification"] == "proto_agi_honeypot_tripwire"
    assert state["honeypot_alerts"][0]["kill_chain_recommended"] is True
    assert "recursive self-improvement" in state["honeypot_alerts"][0]["matched_indicators"]


def test_mirror_clone_deploys_counter_clone_with_minutes_sla():
    detector = MirrorCloneDetector(warmup_events=1, rapid_clone_minutes=2)
    seed = [
        {"host": "h1", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m1"},
        {"host": "h1", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
    ]
    for e in seed:
        detector.evaluate(e)

    alerts = detector.evaluate({"host": "h1", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"})
    deployment = detector.deploy_counter_clone(alerts[0])

    assert deployment.ready_in_minutes == 2
    assert deployment.predicted_next_actions
    assert deployment.deployment_id.startswith("clone::host:h1")
    assert "generate_counterfactual_evasion_paths" in deployment.phases
    assert deployment.synthetic_probe_sequence and deployment.containment_targets
    assert deployment.captured_clone.transition_model
    assert deployment.simulated_attack_path


def test_run_cycle_emits_clone_deployments(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "h1", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m1"},
        {"host": "h1", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"},
    ]:
        ingestor.ingest("model_api", event)

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "containment_severity_threshold": 70,
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "clone_warmup_events": 1,
                "clone_min_prediction_confidence": 0.6,
                "clone_deploy_severity_threshold": 70,
                "clone_rapid_deploy_minutes": 2,
            }
        )
    )

    assert state["clone_deployments"]
    assert state["clone_deployments"][0]["ready_in_minutes"] == 2
    assert "phases" in state["clone_deployments"][0]
    assert state["clone_deployments"][0]["synthetic_probe_sequence"]
    assert state["counter_clone_actions"]
    assert any(a["action"] == "prestage_containment" for a in state["counter_clone_actions"])
    assert any(a["action"] == "block_simulated_path" for a in state["counter_clone_actions"])


def test_mirror_clone_detector_flags_repeated_null_probe_traces():
    detector = MirrorCloneDetector(warmup_events=1)
    detector.evaluate({"host": "h1", "action": "model_invoke", "resource": "m"})
    detector.evaluate({"host": "h1", "action": "unknown", "resource": "unknown"})
    detector.evaluate({"host": "h1", "action": "unknown", "resource": "unknown"})
    alerts = detector.evaluate({"host": "h1", "action": "unknown", "resource": "unknown"})

    assert alerts
    assert any("null-event probes" in a.reason for a in alerts)


def test_mirror_clone_detector_flags_trace_divergence_from_prediction():
    detector = MirrorCloneDetector(warmup_events=1, min_prediction_confidence=0.7)

    training = [
        {"host": "h1", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "action": "model_invoke", "resource": "m1"},
        {"host": "h1", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "action": "model_invoke", "resource": "m1"},
        {"host": "h1", "action": "login_success", "resource": "ssh"},
    ]
    for event in training:
        detector.evaluate(event)

    alerts = detector.evaluate({"host": "h1", "action": "network_send", "resource": "8.8.8.8"})

    assert alerts
    assert any("Trace divergence" in a.reason for a in alerts)


def test_run_cycle_emits_mirror_alerts(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "h1", "action": "login_success", "resource": "ssh"},
        {"host": "h1", "action": "unknown", "resource": "unknown"},
        {"host": "h1", "action": "unknown", "resource": "unknown"},
        {"host": "h1", "action": "unknown", "resource": "unknown"},
    ]:
        ingestor.ingest("model_api", event)

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "containment_severity_threshold": 70,
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "clone_warmup_events": 1,
            }
        )
    )

    assert state["mirror_alerts"]


def test_mirror_clone_deception_risk_increases_with_model_disagreement():
    detector = MirrorCloneDetector(warmup_events=1, rapid_clone_minutes=2)

    training = [
        {"host": "h2", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h2", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m1"},
        {"host": "h2", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h2", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"},
        {"host": "h2", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
    ]
    for event in training:
        detector.evaluate(event)

    detector.evaluate({"host": "h2", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-x"})
    alert = MirrorAlert(
        shard="host:h2|user:svc|proc:agent",
        mode="trace",
        severity=88,
        confidence=0.78,
        reason="synthetic divergence alert",
        event={"host": "h2", "action": "iam_privilege_change", "resource": "role-x"},
    )
    deployment = detector.deploy_counter_clone(alert)

    assert deployment.deception_risk > 0
    assert isinstance(deployment.phases, list) and deployment.phases


def test_execute_counter_clone_returns_prioritized_actions():
    detector = MirrorCloneDetector(warmup_events=1, rapid_clone_minutes=2)
    for event in [
        {"host": "h3", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h3", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m1"},
        {"host": "h3", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h3", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.4.4"},
    ]:
        detector.evaluate(event)

    deployment = detector.deploy_counter_clone(
        MirrorAlert(
            shard="host:h3|user:svc|proc:agent",
            mode="trace",
            severity=90,
            confidence=0.8,
            reason="synthetic",
            event={"host": "h3"},
        )
    )
    actions = detector.execute_counter_clone(deployment)

    assert actions
    assert actions[0].priority >= actions[-1].priority
    assert any(a.action == "emit_synthetic_probe" for a in actions)
    assert any(a.action == "block_simulated_path" for a in actions)


def test_capture_rogue_clone_builds_behavioral_copy():
    detector = MirrorCloneDetector(warmup_events=1)
    for event in [
        {"host": "h4", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h4", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m2"},
        {"host": "h4", "user": "svc", "process": "agent", "action": "network_send", "resource": "10.0.0.1"},
        {"host": "h4", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m2"},
    ]:
        detector.evaluate(event)

    clone = detector.capture_rogue_clone("host:h4|user:svc|proc:agent", confidence=0.83)

    assert clone.action_priors
    assert clone.transition_model
    assert clone.likely_resources
    assert clone.behavioral_signature


def test_should_simulate_containment_disables_simulation_for_high_risk():
    from sentinel_containment.main import should_simulate_containment

    settings = Settings(
        {
            "containment_simulation_mode": True,
            "force_hard_containment_threshold": 80,
            "force_hard_containment_blast_radius": 70,
        }
    )

    assert should_simulate_containment(settings, severity=88, blast_radius_score=40, immediate=False) is False
    assert should_simulate_containment(settings, severity=60, blast_radius_score=75, immediate=False) is False
    assert should_simulate_containment(settings, severity=60, blast_radius_score=40, immediate=False) is True


def test_run_cycle_fast_tracks_containment_with_high_confidence(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    ingestor.ingest(
        "model_api",
        {
            "host": "h-fast",
            "action": "model_invoke",
            "api_call_count": 930,
            "egress_mb": 980,
            "gpu_cpu": 97,
            "resource": "model-z",
            "user": "svc-fast",
        },
    )

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "containment_severity_threshold": 95,
                "fast_track_containment_threshold": 80,
                "fast_track_risk_confidence": 0.2,
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 50,
                "containment_simulation_mode": False,
            }
        )
    )

    assert state["baseline_ready"] is False
    assert state["risk_confidence"] > 0.2
    assert state["containment"] is not None
    assert "quarantine_host" in state["containment"]["actions_executed"]


def test_run_cycle_executes_counter_clone_with_safety_whitelist(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "h-exec", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h-exec", "user": "svc", "process": "agent", "action": "model_invoke", "resource": "m1"},
        {"host": "h-exec", "user": "svc", "process": "agent", "action": "login_success", "resource": "ssh"},
        {"host": "h-exec", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"},
    ]:
        ingestor.ingest("model_api", event)

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "clone_warmup_events": 1,
                "clone_min_prediction_confidence": 0.6,
                "clone_deploy_severity_threshold": 70,
            }
        )
    )

    assert state["counter_clone_execution"]
    assert any(r["status"] == "executed" for r in state["counter_clone_execution"])

    docs = TelemetryIngestor(index_path).read_recent(limit=200)
    synthetic_events = [d for d in docs if d.get("source_type") == "clone_synthetic"]
    assert synthetic_events
    assert all(d.get("synthetic") is True for d in synthetic_events)
    assert all(d.get("action") in {"read", "list", "model_invoke"} for d in synthetic_events)


def test_run_cycle_skips_synthetic_events_across_all_analytics(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    # Synthetic events should not trigger detector pipelines, attack-chain modeling,
    # or blast-radius analysis.
    for event in [
        {
            "host": "h-synth",
            "user": "clone-shadow",
            "process": "counter-clone",
            "action": "login_success",
            "resource": "synthetic://entry",
            "synthetic": True,
            "api_call_count": 999,
            "egress_mb": 999,
            "gpu_cpu": 99,
        },
        {
            "host": "h-synth",
            "user": "clone-shadow",
            "process": "counter-clone",
            "action": "model_invoke",
            "resource": "synthetic://execution",
            "synthetic": True,
            "api_call_count": 999,
            "egress_mb": 999,
            "gpu_cpu": 99,
        },
        {
            "host": "h-synth",
            "user": "clone-shadow",
            "process": "counter-clone",
            "action": "network_send",
            "resource": "synthetic://exfil",
            "synthetic": True,
            "api_call_count": 999,
            "egress_mb": 999,
            "gpu_cpu": 99,
        },
    ]:
        ingestor.ingest("clone_synthetic", event)

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "clone_warmup_events": 1,
            }
        )
    )

    assert state["events_processed"] == 3
    assert state["alerts"] == []
    assert state["graph_anomalies"] == []
    assert state["attack_chains"] == []
    assert state["honeypot_alerts"] == []
    assert state["mirror_alerts"] == []
    assert state["credential_blast_radius"]["compromised_credentials"] == []
    assert state["credential_blast_radius"]["impacted_hosts"] == []
    assert state["credential_blast_radius"]["impacted_resources"] == []
