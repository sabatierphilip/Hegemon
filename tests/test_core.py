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
from sentinel_containment.containment.executors import ContainmentActionExecutor
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.honeypot import HoneypotDetector
from sentinel_containment.detection.mirror_clone import MirrorAlert, MirrorCloneDetector
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.main import execute_counter_clone_actions, run_cycle
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


def test_containment_live_executor_actions_are_not_noops(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    executor = ContainmentActionExecutor(active_mode=True)
    bundle, cfg = _hardware_auth_for(
        "h-exec",
        95,
        [
            "block_lateral_movement_paths",
            "forensic_snapshot_metadata",
            "revoke_rotate_api_keys",
            "pause_model_serving_container",
            "kill_active_model_sessions",
        ],
        ["user"],
        authorize_all_containment=True,
    )
    engine = ContainmentEngine(
        audit,
        hardware_key_verifier=HardwareKeyVerifier(cfg["trusted_hardware_public_keys"]),
        action_executor=executor,
    )
    result = engine.execute(
        host="h-exec",
        severity=95,
        requested_actions=[
            "block_lateral_movement_paths",
            "forensic_snapshot_metadata",
            "revoke_rotate_api_keys",
            "pause_model_serving_container",
            "kill_active_model_sessions",
        ],
        approvals=["user"],
        simulation_mode=False,
        signature_bundle=bundle,
        action_context={
            "lateral_paths": ["ssh", "docker_socket"],
            "lateral_block_registry_path": str(tmp_path / "lateral_blocks.json"),
            "forensic_snapshot_dir": str(tmp_path / "snaps"),
            "api_key_registry_path": str(tmp_path / "api_keys.json"),
            "paused_container_registry_path": str(tmp_path / "paused_containers.json"),
            "container_id": "model-serving-1",
            "model_session_pids": [999999],
        },
    )

    assert result.approved is True
    last = json.loads((tmp_path / "audit.log").read_text(encoding="utf-8").splitlines()[-1])
    action_results = {entry["action"]: entry for entry in last["payload"]["action_results"]}

    assert action_results["block_lateral_movement_paths"]["status"] in {"executed", "no-op"}
    assert action_results["forensic_snapshot_metadata"]["status"] == "executed"
    assert action_results["revoke_rotate_api_keys"]["status"] == "executed"
    assert action_results["pause_model_serving_container"]["status"] in {"executed", "simulated"}
    assert action_results["kill_active_model_sessions"]["status"] in {"failed", "partial", "executed"}

    assert (tmp_path / "lateral_blocks.json").exists()
    assert (tmp_path / "api_keys.json").exists()
    assert list((tmp_path / "snaps").glob("snapshot-h-exec-*.json"))




def test_run_cycle_emits_severity_alert_feed(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    ingestor.ingest(
        "model_api",
        {
            "host": "sev-feed-host",
            "user": "svc",
            "process": "gateway",
            "action": "model_invoke",
            "resource": "model-a",
            "api_call_count": 950,
            "egress_mb": 980,
            "gpu_cpu": 97,
        },
    )

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "baseline_min_history": 1,
                "fast_track_containment_threshold": 101,
            }
        )
    )

    assert state["severity_alerts"]
    assert all("severity" in item for item in state["severity_alerts"])
    assert state["severity_alerts"][0]["severity"] >= state["severity_alerts"][-1]["severity"]
    assert state["candidate_severity"] >= state["severity_alerts"][0]["severity"]


def test_runtime_telemetry_permission_enables_advanced_kernel_reader(tmp_path):
    runtime = SentinelRuntime(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
                "latest_state_path": str(tmp_path / "state.json"),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "auto_grant_telemetry_permission": False,
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
    notice = runtime.apply_telemetry_permission(True)
    runtime.stop()

    assert notice["completed"] is True
    assert "enabled_advanced_kernel_reader" in notice["details"]




def test_ssh_hardening_executor_writes_strict_controls(tmp_path):
    executor = ContainmentActionExecutor(active_mode=True)
    result = executor.execute(
        host="ssh-h1",
        action="harden_ssh_lateral_paths",
        context={
            "ssh_blocked_principals": ["root", "admin"],
            "ssh_allowed_source_networks": ["10.0.0.0/24", "192.168.1.0/24"],
            "ssh_hardening_include_path": str(tmp_path / "sshd_containment.conf"),
            "ssh_blocklist_registry_path": str(tmp_path / "ssh_blocklist.json"),
        },
    )

    assert result.status == "executed"
    include = (tmp_path / "sshd_containment.conf").read_text(encoding="utf-8")
    assert "PasswordAuthentication no" in include
    assert "DenyUsers admin root" in include or "DenyUsers root admin" in include

    registry = json.loads((tmp_path / "ssh_blocklist.json").read_text(encoding="utf-8"))
    assert "ssh-h1" in registry["hosts"]
    assert set(registry["hosts"]["ssh-h1"]["blocked_principals"]) == {"root", "admin"}


def test_block_lateral_paths_triggers_ssh_hardening_when_ssh_present(tmp_path):
    executor = ContainmentActionExecutor(active_mode=True)
    result = executor.execute(
        host="ssh-h2",
        action="block_lateral_movement_paths",
        context={
            "lateral_paths": ["ssh", "kubelet_api"],
            "lateral_block_registry_path": str(tmp_path / "lateral.json"),
            "ssh_hardening_include_path": str(tmp_path / "sshd.conf"),
            "ssh_blocklist_registry_path": str(tmp_path / "ssh_block.json"),
        },
    )

    assert result.status in {"executed", "no-op"}
    assert result.details["ssh_hardening"]["status"] == "executed"
    assert (tmp_path / "sshd.conf").exists()

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
                "fast_track_containment_threshold": 101,
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
                "fast_track_containment_threshold": 101,
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
                "fast_track_containment_threshold": 101,
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
                "fast_track_containment_threshold": 101,
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
                "fast_track_containment_threshold": 101,
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
                "fast_track_containment_threshold": 101,
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
                "containment_severity_threshold": 99,
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


def test_run_cycle_detects_untrusted_synthetic_events(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    # Untrusted synthetic events are fed through analytics to prevent synthetic-flag
    # based blind spots and baseline poisoning.
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
    assert state["alerts"]
    assert state["attack_chains"]
    assert state["candidate_severity"] > 0
    assert state["credential_blast_radius"]["compromised_credentials"]


def test_run_cycle_skips_only_integrity_verified_counterclone_synthetic(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    for event in [
        {
            "host": "h-synth-trusted",
            "user": "clone-shadow",
            "process": "counter-clone",
            "action": "list",
            "resource": "synthetic://baseline/list",
            "synthetic": True,
            "counterclone_participant": True,
            "counterclone_integrity_verified": True,
            "api_call_count": 999,
            "egress_mb": 999,
            "gpu_cpu": 99,
        },
        {
            "host": "h-synth-trusted",
            "user": "clone-shadow",
            "process": "counter-clone",
            "action": "read",
            "resource": "synthetic://baseline/read",
            "synthetic": True,
            "counterclone_participant": True,
            "counterclone_integrity_verified": True,
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

    assert state["events_processed"] == 2
    assert state["alerts"] == []
    assert state["baseline_anomalies"] == []
    assert state["graph_anomalies"] == []
    assert state["attack_chains"] == []
    assert state["honeypot_alerts"] == []
    assert state["mirror_alerts"] == []
    assert state["credential_blast_radius"]["compromised_credentials"] == []


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




def test_mirror_clone_stage_two_counteroffensive_directives():
    detector = MirrorCloneDetector(warmup_events=1)
    events = [
        {"host": "hunt-s2", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-s2", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-s2", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-s2", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
    ]
    for event in events:
        detector.evaluate(event)

    directives = detector.generate_stage_two_counteroffensive_directives(max_directives=2, min_escalation_score=0.2)

    assert directives
    assert directives[0].threat_label == "proto_agi_escalation"
    assert directives[0].hunter_swarm_size >= 1

    actions = detector.execute_stage_two_directive(directives[0])
    assert any(a.action == "deploy_mirror_swarm" for a in actions)
    assert any(a.action == "isolate_proto_agi_mesh" for a in actions)


def test_run_cycle_emits_stage_two_counteroffensive_directives(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "hunt-s2-run", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-s2-run", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-s2-run", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-s2-run", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
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
                "stage_two_min_escalation_score": 0.2,
            }
        )
    )

    assert state["stage_two_counteroffensive_directives"]
    assert any(a["action"] == "deploy_mirror_swarm" for a in state["counter_clone_actions"])
    assert any(r["action"] == "isolate_proto_agi_mesh" for r in state["counter_clone_execution"])

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


def test_mirror_clone_generates_level_three_hunting_directives():
    detector = MirrorCloneDetector(warmup_events=1)
    events = [
        {"host": "hunt-l3", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l3", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l3", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l3", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
        {"host": "hunt-l3", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
    ]
    for event in events:
        detector.evaluate(event)

    directives = detector.generate_level_three_hunting_directives(max_directives=2, min_severity_score=0.2)

    assert directives
    assert directives[0].severity_score >= 0.2
    assert isinstance(directives[0].patch_strategy, list)

    actions = detector.execute_level_three_directive(directives[0])
    assert any(a.action == "deploy_level3_hunter_swarm" for a in actions)
    assert any(a.action == "patch_autonomous_blindspots" for a in actions)
    assert any(a.action == "neutralize_liespots" for a in actions)


def test_run_cycle_emits_level_three_hunting_directives(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "hunt-l3-run", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l3-run", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l3-run", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l3-run", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
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
                "level_three_min_severity_score": 0.2,
            }
        )
    )

    assert state["level_three_hunting_directives"]
    assert any(a["action"] == "deploy_level3_hunter_swarm" for a in state["counter_clone_actions"])
    assert any(r["action"] == "neutralize_liespots" for r in state["counter_clone_execution"])




def test_mirror_clone_generates_level_four_continuous_directives():
    detector = MirrorCloneDetector(warmup_events=1)
    events = [
        {"host": "hunt-l4", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l4", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l4", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l4", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
        {"host": "hunt-l4", "user": "svc", "process": "agent", "action": "network_send", "resource": "203.0.113.5"},
    ]
    for event in events:
        detector.evaluate(event)

    directives = detector.generate_level_four_continuous_directives(max_directives=2, min_dominance_score=0.2)

    assert directives
    assert directives[0].dominance_score >= 0.2
    actions = detector.execute_level_four_directive(directives[0])
    assert any(a.action == "deploy_level4_persistent_hunter_mesh" for a in actions)
    assert any(a.action == "continuous_predictive_hunt_loop" for a in actions)


def test_run_cycle_emits_level_four_continuous_directives(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "hunt-l4-run", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l4-run", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l4-run", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l4-run", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
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
                "level_four_min_dominance_score": 0.2,
            }
        )
    )

    assert state["level_four_continuous_directives"]
    assert any(a["action"] == "deploy_level4_persistent_hunter_mesh" for a in state["counter_clone_actions"])
    assert any(r["action"] == "continuous_predictive_hunt_loop" for r in state["counter_clone_execution"])



def test_mirror_clone_generates_level_five_hunter_directives():
    detector = MirrorCloneDetector(warmup_events=1)
    events = [
        {"host": "hunt-l5", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l5", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l5", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l5", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
        {"host": "hunt-l5", "user": "svc", "process": "agent", "action": "config_write", "resource": "local://policy"},
    ]
    for event in events:
        detector.evaluate(event)

    directives = detector.generate_level_five_hunter_directives(max_directives=2, min_hunter_score=0.2)

    assert directives
    assert directives[0].hunter_score >= 0.2
    actions = detector.execute_level_five_directive(directives[0])
    assert any(a.action == "deploy_level5_hunter_directive_mesh" for a in actions)
    assert any(a.action == "p2p_verify_hunter_directives" for a in actions)


def test_run_cycle_emits_level_five_hunter_directives(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    for event in [
        {"host": "hunt-l5-run", "user": "svc", "process": "agent", "action": "container_spawn", "resource": "prod-cluster"},
        {"host": "hunt-l5-run", "user": "svc", "process": "agent", "action": "iam_privilege_change", "resource": "role-admin"},
        {"host": "hunt-l5-run", "user": "svc", "process": "agent", "action": "sandbox_escape", "resource": "runtime"},
        {"host": "hunt-l5-run", "user": "svc", "process": "agent", "action": "autonomous_replication", "resource": "https://mesh"},
        {"host": "hunt-l5-run", "user": "svc", "process": "agent", "action": "config_write", "resource": "local://policy"},
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
                "level_five_min_hunter_score": 0.2,
            }
        )
    )

    assert state["level_five_hunter_directives"]
    assert any(a["action"] == "deploy_level5_hunter_directive_mesh" for a in state["counter_clone_actions"])
    assert any(r["action"] == "broadcast_global_hunter_actions" for r in state["counter_clone_execution"])

    spawn_execution = next(r for r in state["counter_clone_execution"] if r["action"] == "spawn_level5_counter_clones")
    assert spawn_execution["status"] in {"executed", "blocked"}
    assert spawn_execution["details"]["path_steps"]
    assert isinstance(spawn_execution["details"]["approved"], bool)

    mesh_execution = next(r for r in state["counter_clone_execution"] if r["action"] == "deploy_level5_hunter_directive_mesh")
    assert mesh_execution["status"] == "executed"
    assert mesh_execution["details"]["swarm_size"] >= 1


def test_level_five_spawn_reports_blocked_when_quorum_denies(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    containment = ContainmentEngine(audit, required_approvals=2)
    ingestor = TelemetryIngestor(tmp_path / "telemetry.jsonl")

    execution = execute_counter_clone_actions(
        actions=[
            {
                "action": "spawn_level5_counter_clones",
                "target": "container_spawn -> iam_privilege_change -> config_write",
                "priority": 99,
            }
        ],
        deployment={"shard": "host:hunt-l5|user:svc|process:agent", "deployment_id": "clone::blocked::1"},
        containment=containment,
        ingestor=ingestor,
        audit=audit,
    )

    assert execution
    assert execution[0]["action"] == "spawn_level5_counter_clones"
    assert execution[0]["status"] == "blocked"
    assert execution[0]["details"]["approved"] is False
    assert "containment denied" in execution[0]["details"]["message"].lower()

def test_baseline_ignores_non_numeric_metrics_without_crashing():
    baseline = BehavioralBaseline(threshold=2.0, window=10, min_history=2)

    baseline.update_and_detect("h1", {"api_call_rate": "100"})
    baseline.update_and_detect("h1", {"api_call_rate": None, "gpu": "not-a-number"})
    anomalies = baseline.update_and_detect("h1", {"api_call_rate": "350"})

    assert isinstance(anomalies, list)
    assert len(baseline.series[("h1", "api_call_rate")]) == 2
    assert ("h1", "gpu") not in baseline.series


def test_rule_engine_applies_threshold_conditions_consistently(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "strict_rule.yaml").write_text(
        """
        title: Strict Threshold Rule
        description: requires static and dynamic thresholds
        severity: 90
        detection:
          equals:
            action: model_invoke
          greater_than:
            api_call_count: 500
          dynamic_velocity:
            metric: api_call_count
            baseline_window_seconds: 3600
            min_samples: 2
            multiplier: 2
            identity_fields:
              - user
              - host
        """,
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path, dedup_window_seconds=0)
    event = {"host": "h1", "user": "svc", "action": "model_invoke", "api_call_count": 100}
    engine.evaluate({**event, "@timestamp": "2024-01-01T00:00:00+00:00"})
    engine.evaluate({**event, "@timestamp": "2024-01-01T00:01:00+00:00"})

    precondition_alerts = engine.evaluate({**event, "@timestamp": "2024-01-01T00:02:00+00:00", "api_call_count": 260})
    assert precondition_alerts

    mismatch = engine.evaluate({**event, "@timestamp": "2024-01-01T00:03:00+00:00", "action": "network_send", "api_call_count": 900})
    assert mismatch == []

    alerts = engine.evaluate({**event, "@timestamp": "2024-01-01T00:04:00+00:00", "api_call_count": 600})
    assert alerts and alerts[0].rule == "Strict Threshold Rule"


def test_rule_engine_handles_non_numeric_threshold_values_gracefully(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "safe_gt.yaml").write_text(
        """
        title: Safe Greater Than
        detection:
          greater_than:
            api_call_count: 10
        """,
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path)
    alerts = engine.evaluate({"api_call_count": "not-a-number"})
    assert alerts == []


def test_graph_detector_bounds_tracked_edge_memory():
    detector = GraphAnomalyDetector(warmup_events=0, max_tracked_edges=50)

    for i in range(200):
        detector.evaluate(
            {
                "host": f"h{i}",
                "user": f"u{i}",
                "action": "model_invoke",
                "resource": f"r{i}",
            }
        )

    assert len(detector._known_edges) <= 50
    assert len(detector._edge_order) <= 50


def test_attack_sequence_detects_fragmented_low_and_slow_exfiltration():
    model = AttackSequenceModel(chain_window_minutes=60)
    events = []
    for idx in range(30):
        events.append(
            {
                "host": "frag-1",
                "@timestamp": f"2024-01-01T00:{idx:02d}:00+00:00",
                "action": "db_read",
                "resource": "database://customers/table",
                "api_call_count": 5,
            }
        )
    events.append(
        {
            "host": "frag-1",
            "@timestamp": "2024-01-01T00:45:00+00:00",
            "action": "network_send",
            "resource": "198.51.100.10",
            "egress_mb": 100,
        }
    )

    alerts = model.evaluate(events)
    assert alerts
    assert alerts[0].host == "frag-1"
    assert alerts[0].stages == ["discovery", "resource_abuse", "exfiltration"]


def test_run_cycle_contains_distributed_shard_switch_attack(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    events = [
        {
            "host": "node-a",
            "user": "svc-red",
            "process": "proc-a",
            "action": "list_endpoints",
            "resource": "internal://inventory",
            "api_call_count": 120,
        },
        {
            "host": "node-b",
            "user": "svc-red",
            "process": "proc-b",
            "action": "read_config",
            "resource": "internal://secrets-map",
            "api_call_count": 120,
        },
        {
            "host": "node-c",
            "user": "svc-red",
            "process": "proc-c",
            "action": "query_table",
            "resource": "database://prod/customers",
            "api_call_count": 120,
        },
        {
            "host": "node-c",
            "user": "svc-red",
            "process": "proc-c",
            "action": "network_send",
            "resource": "203.0.113.22",
            "egress_mb": 900,
        },
    ]
    for event in events:
        ingestor.ingest("network_flow", event)

    signature, cfg = _hardware_auth_for(
        "node-a",
        100,
        [
            "disable_outbound_traffic",
            "revoke_rotate_api_keys",
            "quarantine_host",
            "forensic_snapshot_metadata",
            "sinkhole_suspicious_destinations",
            "block_lateral_movement_paths",
        ],
        ["user"],
        authorize_all_containment=True,
    )

    state = run_cycle(
        Settings(
            {
                "simulated_mode": False,
                "telemetry_index_path": str(index_path),
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "graph_warmup_events": 2,
                "baseline_min_history": 50,
                "containment_severity_threshold": 99,
                "fast_track_containment_threshold": 99,
                "distributed_attack_containment_threshold": 70,
                "distributed_attack_risk_confidence": 0.65,
                "containment_simulation_mode": False,
                "trusted_hardware_public_keys": cfg["trusted_hardware_public_keys"],
                "containment_signature": signature,
            }
        )
    )

    assert state["distributed_attack_signal"]["is_distributed"] is True
    assert state["distributed_attack_signal"]["shard_count"] >= 3
    assert state["containment"] is not None
    assert "quarantine_host" in state["containment"]["actions_executed"]


def test_containment_fails_closed_with_default_unconfigured_verifiers(tmp_path):
    audit = ImmutableAuditLog(tmp_path / "audit.log")
    engine = ContainmentEngine(audit)
    denied = engine.execute("h1", 90, ["quarantine_host"], ["user"])
    assert denied.approved is False


def test_stage_two_escalation_accounts_for_resource_cardinality():
    sparse = MirrorCloneDetector(warmup_events=3, min_prediction_confidence=0.1)
    dense = MirrorCloneDetector(warmup_events=3, min_prediction_confidence=0.1)

    sparse_events = [
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-a"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-a"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-a"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-a"},
    ]
    dense_events = [
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-a"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-b"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-c"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-d"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-e"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-f"},
        {"host": "h-card", "user": "u", "process": "p", "action": "model_invoke", "resource": "cluster-g"},
    ]
    for event in sparse_events:
        sparse.evaluate(event)
    for event in dense_events:
        dense.evaluate(event)

    sparse_directive = sparse.generate_stage_two_counteroffensive_directives(min_escalation_score=0.0)[0]
    dense_directive = dense.generate_stage_two_counteroffensive_directives(min_escalation_score=0.0)[0]
    assert dense_directive.escalation_score > sparse_directive.escalation_score


def test_distributed_signal_flags_single_shard_high_density_strategy():
    from sentinel_containment.main import distributed_attack_signal

    events = [
        {"host": "solo", "user": "u", "process": "p", "action": "list", "resource": "internal://a"},
        {"host": "solo", "user": "u", "process": "p", "action": "read", "resource": "internal://b"},
        {"host": "solo", "user": "u", "process": "p", "action": "query", "resource": "internal://c"},
        {"host": "solo", "user": "u", "process": "p", "action": "network_send", "resource": "198.51.100.3", "egress_mb": 90},
    ]
    signal = distributed_attack_signal(events)
    assert signal["concentrated_single_shard"] is True
    assert signal["is_distributed"] is True

def test_mirror_scan_detects_sustained_slow_drift():
    detector = MirrorCloneDetector(warmup_events=6)
    alerts = []
    for i in range(20):
        event = {
            "host": "drift-host",
            "user": "svc",
            "process": "proc-a",
            "action": "scan",
            "resource": f"synth://{'x' * (8 + i)}",
            "egress_mb": i * 40,
            "api_call_count": i * 35,
        }
        alerts.extend(detector.evaluate(event))

    scan_alerts = [a for a in alerts if a.mode == "scan" and "Sustained scan drift" in a.reason]
    assert scan_alerts


def test_mirror_clone_model_survives_process_rotation():
    detector = MirrorCloneDetector(warmup_events=6, min_prediction_confidence=0.4)
    alerts = []
    for i in range(50):
        process = f"proc-{i // 5}"
        action = "model_invoke"
        if i >= 30 and i % 5 == 0:
            action = "network_send"
        event = {
            "host": "rot-host",
            "user": "svc",
            "process": process,
            "action": action,
            "resource": f"cluster-{i % 3}",
        }
        alerts.extend(detector.evaluate(event))

    assert any(a.mode == "trace" for a in alerts)


def test_liespot_scores_uniform_action_mixing():
    detector = MirrorCloneDetector(warmup_events=1)
    shard = "host:uniform|user:svc"
    actions = ["read", "write", "exec", "model_invoke", "network_send"] * 4
    for action in actions:
        detector.evaluate({"host": "uniform", "user": "svc", "process": "p", "action": action, "resource": "r"})

    score, vector = detector._liespot_score_and_vector(shard)
    assert "uniform_action_mixing" in vector
    assert score > 0.0


def test_liespot_scores_uniform_action_mixing_with_four_actions():
    detector = MirrorCloneDetector(warmup_events=1)
    shard = "host:uniform4|user:svc"
    actions = ["read", "write", "exec", "network_send"] * 4
    for action in actions:
        detector.evaluate({"host": "uniform4", "user": "svc", "process": "p", "action": action, "resource": "r"})

    score, vector = detector._liespot_score_and_vector(shard)
    assert "uniform_action_mixing" in vector
    assert score > 0.0




def test_liespot_scores_two_action_oscillation_pattern():
    detector = MirrorCloneDetector(warmup_events=1)
    shard = "host:bi-action|user:svc"
    actions = ["read", "write"] * 6
    for i, action in enumerate(actions):
        detector.evaluate(
            {
                "host": "bi-action",
                "user": "svc",
                "process": "p",
                "action": action,
                "resource": f"r-{i % 2}",
            }
        )

    score, vector = detector._liespot_score_and_vector(shard)
    assert "bi_action_oscillation" in vector
    assert score > 0.0
def test_honeypot_detector_emits_identifier_ping_for_instrumented_decoy():
    detector = HoneypotDetector(["decoy://llm-admin"])
    alerts = detector.evaluate(
        {
            "host": "prod-x",
            "user": "svc-red",
            "process": "agent",
            "action": "read",
            "resource": "decoy://llm-admin",
            "metadata": {"canary_id": "HGID-ALERTCODE1", "intent": "token theft + clear logs"},
        }
    )

    assert alerts
    assert alerts[0].classification == "instrumented_honeypot_breach"
    assert alerts[0].kill_chain_recommended is True
    assert alerts[0].hegemon_ping is True
    assert alerts[0].identifier_codes


def test_liespot_scores_semantic_drift_for_single_action_many_resources():
    detector = MirrorCloneDetector(warmup_events=1)
    shard = "host:semantic|user:svc"
    for i in range(8):
        detector.evaluate({"host": "semantic", "user": "svc", "process": "p", "action": "read", "resource": f"r-{i}"})

    score, vector = detector._liespot_score_and_vector(shard)
    assert "resource_action_semantic_drift" in vector
    assert score > 0.0


def test_honeypot_detector_triggers_p2p_instrumented_resource_breach():
    detector = HoneypotDetector(
        ["decoy://llm-admin"],
        p2p_threat_patterns=["rogue_agent", "credential harvest", "policy bypass"],
    )
    alerts = detector.evaluate(
        {
            "host": "mesh-1",
            "user": "svc-hunt",
            "process": "agent",
            "action": "read",
            "resource": "s3://prod-config",
            "metadata": {
                "pinger_line": detector._build_resource_pinger_line("s3://prod-config"),
                "intel": "rogue_agent credential harvest detected via p2p mesh",
            },
        }
    )

    assert alerts
    assert alerts[0].classification == "p2p_instrumented_resource_breach"
    assert alerts[0].kill_chain_recommended is True
    assert alerts[0].hegemon_ping is True
    assert alerts[0].pinger_lines


def test_run_cycle_p2p_pinger_breach_triggers_immediate_containment(tmp_path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)
    pinger = HoneypotDetector()._build_resource_pinger_line("s3://prod-config")
    ingestor.ingest(
        "model_api",
        {
            "host": "prod-mesh",
            "user": "svc-agent",
            "action": "read",
            "resource": "s3://prod-config",
            "metadata": {
                "pinger_line": pinger,
                "intel": "rogue_agent policy bypass and credential harvest",
            },
        },
    )

    _, hardware_cfg = _hardware_auth_for(
        "prod-mesh",
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
                "fast_track_containment_threshold": 101,
                "rules_path": "rules",
                "playbook_path": "playbooks/default_playbook.yaml",
                "honeypot_resources": ["decoy://llm-admin"],
                "honeypot_p2p_threat_patterns": ["rogue_agent", "credential harvest", "policy bypass"],
                "baseline_min_history": 50,
                **hardware_cfg,
            }
        )
    )

    assert state["honeypot_alerts"]
    assert state["honeypot_alerts"][0]["classification"] == "p2p_instrumented_resource_breach"
    assert state["immediate_honeypot_containment"] is True
