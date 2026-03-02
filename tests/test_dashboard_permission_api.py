from pathlib import Path

import pytest

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web.app import app, set_runtime


@pytest.fixture
def auth_headers(monkeypatch):
    monkeypatch.setenv("SENTINEL_DASHBOARD_TOKEN", "test-token")
    return {"Authorization": "Bearer test-token"}


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

    runtime.ingestion_service.syslog_server.server_close()
    runtime.ingestion_service.kernel_webhook_server.server_close()


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

    runtime.ingestion_service.syslog_server.server_close()
    runtime.ingestion_service.kernel_webhook_server.server_close()


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
