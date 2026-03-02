from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app, set_runtime


def test_permission_api_applies_notice(tmp_path: Path):
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
    }
    (tmp_path / "rules").mkdir()
    runtime = SentinelRuntime(Settings(cfg))
    set_runtime(runtime)

    client = app.test_client()
    response = client.post("/api/telemetry/permission", json={"granted": True})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["granted"] is True
    assert payload["completed"] is True

    runtime.ingestion_service.syslog_server.server_close()
    runtime.ingestion_service.kernel_webhook_server.server_close()


def test_containment_decision_api_executes_and_releases(tmp_path: Path):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "containment_live_mode": False,
        "containment_signature": {},
        "containment_confirmation": {},
        "hardware_key_fail_closed": False,
        "human_confirmation_fail_closed": False,
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
    runtime._containment_decision = {
        "pending": True,
        "host": "host-a",
        "severity": 88,
        "reason": "malware_or_rogue_agent_detected",
        "simulation": {"actions_executed": ["simulate_quarantine_host"]},
        "recommended_actions": ["disable_outbound_traffic", "quarantine_host"],
        "hold_active": True,
    }
    runtime._holding_hosts.add("host-a")
    set_runtime(runtime)

    client = app.test_client()

    execute_response = client.post("/api/containment/decision", json={"execute": True})
    assert execute_response.status_code == 200
    execute_payload = execute_response.get_json()
    assert execute_payload["executed"] is True
    assert "disable_outbound_traffic" in execute_payload["actions_executed"]
    assert runtime.get_containment_decision_status()["pending"] is False

    runtime._containment_decision = {
        "pending": True,
        "host": "host-b",
        "severity": 70,
        "reason": "malware_or_rogue_agent_detected",
        "simulation": {"actions_executed": ["simulate_quarantine_host"]},
        "recommended_actions": ["disable_outbound_traffic", "quarantine_host"],
        "hold_active": True,
    }
    runtime._holding_hosts.add("host-b")

    release_response = client.post("/api/containment/decision", json={"execute": False})
    assert release_response.status_code == 200
    release_payload = release_response.get_json()
    assert release_payload["released"] is True
    assert release_payload["executed"] is False

    runtime.ingestion_service.syslog_server.server_close()
    runtime.ingestion_service.kernel_webhook_server.server_close()
