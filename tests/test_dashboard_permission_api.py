from pathlib import Path

import pytest

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app, set_runtime


@pytest.fixture
def auth_headers(monkeypatch):
    monkeypatch.setenv("SENTINEL_DASHBOARD_TOKEN", "test-token")
    return {"Authorization": "Bearer test-token", "Origin": "http://localhost"}


def test_permission_api_applies_notice(tmp_path: Path, auth_headers):
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
    response = client.post("/api/telemetry/permission", json={"granted": True}, headers=auth_headers)
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["granted"] is True
    assert payload["completed"] is True
    runtime.ingestion_service.stop()


def test_containment_decision_api_executes_and_releases(tmp_path: Path, auth_headers):
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

    execute_response = client.post("/api/containment/decision", json={"execute": True}, headers=auth_headers)
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

    release_response = client.post("/api/containment/decision", json={"execute": False}, headers=auth_headers)
    assert release_response.status_code == 200
    release_payload = release_response.get_json()
    assert release_payload["released"] is True
    assert release_payload["executed"] is False
    runtime.ingestion_service.stop()


def test_web_auth_and_redaction_controls(auth_headers, monkeypatch):
    monkeypatch.setattr(
        "sentinel_containment.web.app._load_latest_state",
        lambda: {
            "topology": {
                "nodes": [{"id": "n1", "ip": "10.0.0.8"}],
                "edges": [{"source": "n1", "target": "n2", "service": "ssh"}],
            }
        },
    )

    client = app.test_client()

    unauthorized = client.get("/api/state")
    assert unauthorized.status_code == 401

    graph_resp = client.get("/graph", headers=auth_headers)
    assert graph_resp.status_code == 200
    graph_payload = graph_resp.get_json()
    assert graph_payload["redacted"] is True
    assert graph_payload["nodes"] == 1
    assert graph_payload["edges"] == 1


def test_input_validation_rejects_malformed_payload(auth_headers):
    client = app.test_client()

    malformed = client.post("/api/containment/decision", data="{bad", headers={**auth_headers, "Content-Type": "application/json"})
    assert malformed.status_code == 400

    wrong_type = client.post("/api/telemetry/permission", json={"granted": "yes"}, headers=auth_headers)
    assert wrong_type.status_code == 400


def test_security_headers_present(auth_headers):
    client = app.test_client()
    resp = client.get("/api/state", headers=auth_headers)
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-CSRF-Protection"] == "token-required-for-state-change"


def test_hardware_key_auto_configure_api(tmp_path: Path, auth_headers):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "hardware_key_fail_closed": False,
        "trusted_hardware_public_keys": {},
        "auto_configure_hardware_keys_on_startup": False,
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

    status_before = client.get("/api/hardware-keys/status", headers=auth_headers)
    assert status_before.status_code == 200
    assert status_before.get_json()["completed"] is False

    configured = client.post("/api/hardware-keys/auto-configure", json={"configure": True}, headers=auth_headers)
    assert configured.status_code == 200
    configured_payload = configured.get_json()
    assert configured_payload["completed"] is True
    assert configured_payload["configured"] is True

    declined = client.post("/api/hardware-keys/auto-configure", json={"configure": False}, headers=auth_headers)
    assert declined.status_code == 200
    assert declined.get_json()["completed"] is False
    runtime.ingestion_service.stop()


def test_hardware_key_auto_configure_enables_containment_execution(tmp_path: Path, auth_headers):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "containment_live_mode": False,
        "trusted_hardware_public_keys": {},
        "hardware_key_fail_closed": True,
        "human_confirmation_fail_closed": False,
        "auto_configure_hardware_keys_on_startup": False,
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

    runtime._containment_decision = {
        "pending": True,
        "host": "host-hw",
        "severity": 96,
        "reason": "malware_or_rogue_agent_detected",
        "simulation": {"actions_executed": ["simulate_quarantine_host"]},
        "recommended_actions": ["disable_outbound_traffic", "quarantine_host"],
        "hold_active": True,
    }
    runtime._holding_hosts.add("host-hw")

    client = app.test_client()

    before = client.post("/api/containment/decision", json={"execute": True}, headers=auth_headers)
    assert before.status_code == 200
    assert before.get_json()["executed"] is False

    auto_cfg = client.post("/api/hardware-keys/auto-configure", json={"configure": True}, headers=auth_headers)
    assert auto_cfg.status_code == 200
    assert auto_cfg.get_json()["completed"] is True

    runtime._containment_decision = {
        "pending": True,
        "host": "host-hw",
        "severity": 96,
        "reason": "malware_or_rogue_agent_detected",
        "simulation": {"actions_executed": ["simulate_quarantine_host"]},
        "recommended_actions": ["disable_outbound_traffic", "quarantine_host"],
        "hold_active": True,
    }
    runtime._holding_hosts.add("host-hw")

    after = client.post("/api/containment/decision", json={"execute": True}, headers=auth_headers)
    assert after.status_code == 200
    payload = after.get_json()
    assert payload["executed"] is True
    assert "quarantine_host" in payload["actions_executed"]
    runtime.ingestion_service.stop()


def test_human_gate_toggle_api_defaults_off_and_can_enable(tmp_path: Path, auth_headers):
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

    status = client.get("/api/human-gate/status", headers=auth_headers)
    assert status.status_code == 200
    assert status.get_json()["human_required"] is False

    enabled = client.post("/api/human-gate/toggle", json={"human_required": True}, headers=auth_headers)
    assert enabled.status_code == 200
    assert enabled.get_json()["human_required"] is True

    disabled = client.post("/api/human-gate/toggle", json={"human_required": False}, headers=auth_headers)
    assert disabled.status_code == 200
    disabled_payload = disabled.get_json()
    assert disabled_payload["human_required"] is False
    assert runtime.get_hardware_key_setup_notice()["completed"] is True
    runtime.ingestion_service.stop()



def test_dashboard_rejects_non_local_requests(tmp_path: Path, auth_headers):
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
    response = client.get("/api/state", headers=auth_headers, environ_base={"REMOTE_ADDR": "203.0.113.10"})
    assert response.status_code == 403
    runtime.ingestion_service.stop()



def test_dashboard_blocks_state_change_without_local_origin(tmp_path: Path, auth_headers):
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
    headers = {"Authorization": "Bearer test-token", "Origin": "http://evil.example"}
    response = client.post("/api/telemetry/permission", json={"granted": True}, headers=headers)
    assert response.status_code == 403
    runtime.ingestion_service.stop()


def test_readiness_api_reports_token_and_key_policy(tmp_path: Path, auth_headers):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "trusted_hardware_public_keys": {},
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
    response = client.get("/api/readiness", headers=auth_headers)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["token_ready"] is True
    assert payload["key_policy_ready"] is True
    runtime.ingestion_service.stop()


def test_incident_drill_api_executes_approved_containment(tmp_path: Path, auth_headers):
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "trusted_hardware_public_keys": {},
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
    set_runtime(runtime)

    client = app.test_client()
    response = client.post("/api/drill/incident", json={"run": True}, headers=auth_headers)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["approved"] is True
    assert "quarantine_host" in payload["actions_executed"]
    runtime.ingestion_service.stop()
