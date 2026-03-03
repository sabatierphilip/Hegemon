from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime


def test_runtime_disables_fast_lane_when_tls_files_missing(tmp_path: Path):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
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
        "fast_lane": {
            "enabled": True,
            "server_cert_path": str(tmp_path / "missing-server.crt"),
            "server_key_path": str(tmp_path / "missing-server.key"),
            "client_ca_cert_path": str(tmp_path / "missing-client-ca.crt"),
        },
    }
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))

    assert runtime.fast_lane_server is None
    runtime.ingestion_service.stop()


def test_runtime_defaults_to_autonomous_mode_and_bootstraps_keys(tmp_path: Path):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "trusted_hardware_public_keys": {},
        "human_required_default": False,
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
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))

    human_gate = runtime.get_human_gate_status()
    assert human_gate["human_required"] is False

    telemetry = runtime.get_telemetry_setup_notice()
    assert telemetry["completed"] is True
    assert telemetry["granted"] is True

    hardware = runtime.get_hardware_key_setup_notice()
    assert hardware["completed"] is True
    assert runtime.settings.get("containment_signature") is None
    assert "operator_signature_required" in hardware["details"]
    runtime.ingestion_service.stop()
