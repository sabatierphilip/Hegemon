from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime


def test_runtime_applies_single_permission_for_dynamic_telemetry(tmp_path: Path):
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
            "dynamic_system_poll_seconds": 0.05,
            "syslog_port": 0,
            "kernel_webhook_port": 0,
        },
    }
    (tmp_path / "rules").mkdir()
    runtime = SentinelRuntime(Settings(cfg))
    notice = runtime.apply_telemetry_permission(True)

    assert notice["required"] is True
    assert notice["granted"] is True
    assert notice["completed"] is True
    assert any(item == "enabled_dynamic_system_runtime" for item in notice["details"])
    runtime.ingestion_service.stop()
