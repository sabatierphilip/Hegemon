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


def _base_cfg(tmp_path: Path) -> dict:
    return {
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
    }


def test_preflight_warning_emitted_when_autoconfig_disabled(tmp_path: Path):
    cfg = _base_cfg(tmp_path)
    cfg.update(
        {
            "auto_configure_hardware_keys_on_startup": False,
            "trusted_hardware_public_keys": {},
            "hardware_key_fail_closed": True,
            "human_confirmation_fail_closed": False,
        }
    )
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))
    readiness = runtime.get_readiness_status()

    assert readiness["containment_ready"] is False
    assert "HARD WARNING" in readiness["startup_warning"]
    assert readiness["key_policy_ready"] is False
    runtime.ingestion_service.stop()


def test_incident_drill_passes_with_default_autonomous_keys(tmp_path: Path):
    cfg = _base_cfg(tmp_path)
    cfg.update(
        {
            "trusted_hardware_public_keys": {},
            "human_confirmation_fail_closed": False,
        }
    )
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))
    payload = runtime.run_incident_drill()

    assert payload["approved"] is True
    assert "quarantine_host" in payload["actions_executed"]
    runtime.ingestion_service.stop()


def test_runtime_defaults_containment_live_mode_enabled(tmp_path: Path):
    cfg = _base_cfg(tmp_path)
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))

    assert runtime.get_containment_live_mode_status()["containment_live_mode"] is True
    assert runtime.containment.action_executor.active_mode is True
    assert runtime.fast_lane_containment.action_executor.active_mode is True
    runtime.ingestion_service.stop()
