import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

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
from sentinel_containment.security.hardware_keys import HardwareKeyVerifier
from sentinel_containment.security.human_confirmation import HumanConfirmationVerifier
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import JSONLinesFileSource, discover_live_file_sources, parse_syslog_line


def _hardware_auth_for(
    host: str,
    severity: int,
    requested_actions: list[str],
    approvals: list[str],
    *,
    authorize_all_containment: bool = False,
) -> tuple[dict, dict]:
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    key_id = "test-hardware-key"
    key_type = "yubikey"
    digest = HardwareKeyVerifier.canonical_payload(
        host,
        severity,
        requested_actions,
        approvals,
        key_id,
        key_type,
        authorize_all_containment=authorize_all_containment,
    )
    signature = base64.b64encode(private_key.sign(digest)).decode("utf-8")
    bundle = {
        "key_id": key_id,
        "key_type": key_type,
        "signature": signature,
        "authorize_all_containment": authorize_all_containment,
    }
    settings_fragment = {
        "trusted_hardware_public_keys": {key_id: public_pem},
        "containment_signature": bundle,
    }
    return bundle, settings_fragment


def test_asset_snapshot_contains_nodes(tmp_path):
    mapper = AssetMapper(CloudProviderAdapter(simulated=True), snapshot_path=tmp_path / "topology.json")
    snap = mapper.snapshot()
    assert snap["nodes"]


def test_rule_engine_detects_excessive_calls():
    engine = RuleEngine()
    alerts = engine.evaluate({"action": "model_invoke", "api_call_count": 900})
    assert any("Excessive Model API Calls" == a.rule for a in alerts)


def test_containment_defaults_to_single_user_approval(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    bundle, cfg = _hardware_auth_for("h1", 90, ["quarantine_host"], ["user"])
    engine = ContainmentEngine(audit, hardware_key_verifier=HardwareKeyVerifier(cfg["trusted_hardware_public_keys"]))
    allowed = engine.execute("h1", 90, ["quarantine_host"], ["user"], signature_bundle=bundle)
    assert allowed.approved


def test_containment_allows_non_hardware_path_with_verified_human_confirmation(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    shared_secret = "human-gate-secret"
    confirmation = HumanConfirmationVerifier.build_confirmation_bundle(
        shared_secret=shared_secret,
        host="h1",
        severity=90,
        requested_actions=["quarantine_host"],
        approvals=["user"],
        nonce="n-1",
    )
    engine = ContainmentEngine(
        audit,
        human_confirmation_verifier=HumanConfirmationVerifier(shared_secret=shared_secret),
    )
    allowed = engine.execute(
        "h1",
        90,
        ["quarantine_host"],
        ["user"],
        confirmation_bundle=confirmation,
    )
    assert allowed.approved


def test_containment_denies_when_human_confirmation_missing(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(
        audit,
        human_confirmation_verifier=HumanConfirmationVerifier(shared_secret="human-gate-secret"),
    )
    denied = engine.execute("h1", 90, ["quarantine_host"], ["user"])
    assert not denied.approved


def test_containment_honors_configured_quorum(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    denied_bundle, cfg = _hardware_auth_for("h1", 90, ["quarantine_host"], ["alice"])
    allowed_bundle, _ = _hardware_auth_for("h1", 90, ["quarantine_host"], ["alice", "bob"])
    engine = ContainmentEngine(
        audit,
        required_approvals=2,
        hardware_key_verifier=HardwareKeyVerifier(cfg["trusted_hardware_public_keys"]),
    )
    denied = engine.execute("h1", 90, ["quarantine_host"], ["alice"], signature_bundle=denied_bundle)
    assert not denied.approved
    allowed = engine.execute("h1", 90, ["quarantine_host"], ["alice", "bob"], signature_bundle=allowed_bundle)
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




def test_telemetry_signature_chain_detects_tampering(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path, signing_key="test-key", key_rotation_seconds=60)
    ingestor.ingest("hypervisor", {"host": "hv-1", "action": "vm_exit", "collector_level": "hypervisor"})
    ingestor.ingest("counterclone", {"host": "h1", "action": "emit_synthetic_probe", "counterclone_participant": True})

    assert ingestor.verify_recent(limit=10)

    lines = index_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("emit_synthetic_probe", "emit_synthetic_probe_tampered")
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert not ingestor.verify_recent(limit=10)

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
                        "kernel_webhook_host": "127.0.0.1",
                        "kernel_webhook_port": 0,
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


def test_graph_detector_warmup_requires_source_diversity_before_firing():
    detector = GraphAnomalyDetector(warmup_events=1, warmup_min_distinct_sources=2)
    first = detector.evaluate({"host": "h1", "user": "u1", "action": "model_invoke"})
    second = detector.evaluate({"host": "h1", "user": "u1", "action": "iam_privilege_change"})
    third = detector.evaluate({"host": "h9", "user": "intruder", "action": "iam_privilege_change"})

    assert first == []
    assert second == []
    assert third


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
    bundle, cfg = _hardware_auth_for("h2", 85, ["disable_outbound_traffic", "quarantine_host"], ["alice", "bob"])
    engine = ContainmentEngine(audit, hardware_key_verifier=HardwareKeyVerifier(cfg["trusted_hardware_public_keys"]))
    result = engine.execute(
        "h2",
        85,
        ["disable_outbound_traffic", "quarantine_host"],
        ["alice", "bob"],
        simulation_mode=True,
        hard_quarantine_threshold=90,
        simulation_context={"blast_radius": {"impacted_hosts": ["h2"], "impacted_resources": ["model-a"]}},
        signature_bundle=bundle,
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
    bundle, cfg = _hardware_auth_for("h1", 95, ["quarantine_host"], ["Alice", "alice@corp"])
    engine = ContainmentEngine(
        audit,
        identity_store={"alice": ["Alice", "alice@corp"]},
        required_approvals=2,
        hardware_key_verifier=HardwareKeyVerifier(cfg["trusted_hardware_public_keys"]),
    )
    denied = engine.execute("h1", 95, ["quarantine_host"], ["Alice", "alice@corp"], signature_bundle=bundle)

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

    _, hardware_cfg = _hardware_auth_for(
        "prod-model-9",
        99,
        ["quarantine_host"],
        ["user"],
        authorize_all_containment=True,
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
                **hardware_cfg,
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

    _, hardware_cfg = _hardware_auth_for(
        "h-fast",
        95,
        ["quarantine_host"],
        ["user"],
        authorize_all_containment=True,
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
                **hardware_cfg,
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


def test_dynamic_automodeller_resists_infected_baseline_rebasing():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5)

    for _ in range(20):
        baseline.update_and_detect("h-infected", {"api_call_rate": 220.0})

    # Simulate attacker-induced baseline poisoning toward low values.
    for _ in range(15):
        baseline.update_and_detect("h-infected", {"api_call_rate": 8.0})

    anomalies = baseline.update_and_detect("h-infected", {"api_call_rate": 85.0})

    assert anomalies
    assert anomalies[0].metric == "api_call_rate"
    assert anomalies[0].severity >= 60


def test_counterclone_context_feeds_dynamic_automodeller_without_false_positives():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5)

    for _ in range(8):
        no_anomalies = baseline.update_and_detect(
            "h-cc",
            {"counterclone_activity": 1.0},
            context={
                "counterclone_participant": True,
                "counterclone_integrity_verified": True,
                "source_type": "counterclone",
            },
        )
        assert no_anomalies == []

    anomalies = baseline.update_and_detect(
        "h-cc",
        {"counterclone_activity": 4.5},
        context={
            "counterclone_participant": True,
            "counterclone_integrity_verified": True,
            "source_type": "counterclone",
        },
    )

    assert anomalies
    assert anomalies[0].metric == "counterclone_activity"


def test_contamination_decay_is_time_based_and_persists_across_30_second_pause():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5, contamination_half_life_seconds=180.0)

    for i in range(20):
        baseline.update_and_detect(
            "h-time",
            {"api_call_rate": 220.0},
            context={"event_timestamp": f"2024-01-01T00:00:{i:02d}+00:00"},
        )

    for i in range(20, 35):
        baseline.update_and_detect(
            "h-time",
            {"api_call_rate": 8.0},
            context={"event_timestamp": f"2024-01-01T00:00:{i:02d}+00:00"},
        )

    paused_anomalies = baseline.update_and_detect(
        "h-time",
        {"api_call_rate": 85.0},
        context={"event_timestamp": "2024-01-01T00:01:05+00:00"},
    )

    assert paused_anomalies
    assert paused_anomalies[0].severity >= 60


def test_counterclone_trust_requires_integrity_verified_flag():
    baseline = BehavioralBaseline(threshold=2.0, window=30, min_history=5)

    for i in range(10):
        baseline.update_and_detect(
            "h-untrusted",
            {"counterclone_activity": 1.0},
            context={
                "counterclone_participant": True,
                "counterclone_integrity_verified": False,
                "source_type": "counterclone",
                "event_timestamp": f"2024-01-01T00:00:{i:02d}+00:00",
            },
        )

    state = baseline._automodeller._state[("h-untrusted", "counterclone_activity")]
    assert state.resilient_mean < 2.0


def test_counterclone_file_source_enforces_integrity_signature(tmp_path):
    source_file = tmp_path / "counterclone_events.jsonl"
    index_path = tmp_path / "index.jsonl"
    key = "counterclone-key"
    payload = {"host": "h1", "action": "emit_synthetic_probe", "counterclone_participant": True}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    good_sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()

    source_file.write_text(
        "\n".join(
            [
                json.dumps({**payload, "counterclone_file_signature": good_sig}),
                json.dumps({**payload, "counterclone_file_signature": "bad-signature"}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    source = JSONLinesFileSource(source_file, "counterclone", TelemetryIngestor(index_path), integrity_key=key)
    assert source.poll_once() == 2

    docs = TelemetryIngestor(index_path).read_recent(limit=10)
    assert docs[0]["counterclone_integrity_verified"] is True
    assert docs[1]["counterclone_integrity_verified"] is False


def test_cloud_adapter_returns_local_instance_without_simulation():
    adapter = CloudProviderAdapter(simulated=False, provider="local")
    instances = adapter.list_instances()
    assert instances
    assert instances[0]["provider"] == "local"


def test_discover_live_file_sources_finds_present_inputs(tmp_path):
    import os

    cloudtrail = tmp_path / "cloudtrail.jsonl"
    cloudtrail.write_text('{"host":"h1","action":"read"}\n', encoding="utf-8")

    old = os.environ.get("TELEMETRY_AUTODISCOVER_DIRS")
    os.environ["TELEMETRY_AUTODISCOVER_DIRS"] = str(tmp_path)
    try:
        discovered = discover_live_file_sources(existing={})
    finally:
        if old is None:
            os.environ.pop("TELEMETRY_AUTODISCOVER_DIRS", None)
        else:
            os.environ["TELEMETRY_AUTODISCOVER_DIRS"] = old

    assert discovered.get("cloud_audit") == cloudtrail


def test_runtime_fast_lane_event_executes_immediate_containment(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    signature, hardware_cfg = _hardware_auth_for(
        "prod-model-urgent",
        96,
        ["quarantine_host"],
        ["user"],
        authorize_all_containment=True,
    )
    runtime = SentinelRuntime(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "fast_lane": {"enabled": False},
                **hardware_cfg,
                "ingestion": {
                    "syslog_host": "127.0.0.1",
                    "syslog_port": 0,
                    "kernel_webhook_host": "127.0.0.1",
                    "kernel_webhook_port": 0,
                    "cloudtrail_file": str(tmp_path / "c.jsonl"),
                    "network_flow_file": str(tmp_path / "n.jsonl"),
                    "model_api_file": str(tmp_path / "m.jsonl"),
                },
            }
        )
    )

    result = runtime.process_priority_event(
        {
            "host": "prod-model-urgent",
            "severity": 96,
            "honeypot_trigger": True,
            "source_type": "honeypot_interrupt",
            "containment_signature": signature,
        }
    )

    assert result["approved"] is True
    assert "quarantine_host" in result["actions_executed"]
    docs = runtime.ingestor.read_recent(limit=5)
    assert any(doc.get("source_type") == "honeypot_interrupt" for doc in docs)


def test_mirror_clone_generates_autonomous_recon_directives():
    detector = MirrorCloneDetector(warmup_events=1)
    events = [
        {"host": "hunt-1", "user": "svc", "process": "agent", "action": "login_failure", "resource": "ssh"},
        {"host": "hunt-1", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "ctr-a"},
        {"host": "hunt-1", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-1", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"},
    ]
    for event in events:
        detector.evaluate(event)

    directives = detector.generate_autonomous_recon_directives(max_directives=2, min_markov_score=0.2)

    assert directives
    assert directives[0].markov_kill_chain_score >= 0.2
    actions = detector.execute_recon_directive(directives[0])
    assert any(a.action == "launch_autonomous_recon" for a in actions)
    assert any(a.action == "backmodel_markov_kill_chain" for a in actions)


def test_mirror_clone_model_invoke_hoarding_crosses_recon_threshold():
    score = MirrorCloneDetector._markov_kill_chain_score(["model_invoke", "model_invoke", "model_invoke", "model_invoke"])
    assert score >= 0.35


def test_run_cycle_emits_autonomous_recon_directives(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "hunt-2", "user": "svc", "process": "agent", "action": "login_failure", "resource": "ssh"},
        {"host": "hunt-2", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "ctr-a"},
        {"host": "hunt-2", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-2", "user": "svc", "process": "agent", "action": "network_send", "resource": "8.8.8.8"},
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
                "autonomous_recon_min_markov_score": 0.2,
            }
        )
    )

    assert state["autonomous_recon_directives"]
    assert any(a["action"] == "launch_autonomous_recon" for a in state["counter_clone_actions"])
    assert any(r["action"] == "backmodel_markov_kill_chain" for r in state["counter_clone_execution"])
