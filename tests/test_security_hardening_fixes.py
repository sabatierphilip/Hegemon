import json
import hashlib
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from sentinel_containment.containment.executors import ContainmentActionExecutor
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.telemetry.sources import parse_syslog_line


def test_immutable_log_reads_out_of_band_env_var(monkeypatch, tmp_path: Path):
    primary = tmp_path / "audit.log"
    mirror = tmp_path / "audit_oob.log"
    monkeypatch.setenv("AUDIT_OUT_OF_BAND_PATH", str(mirror))

    log = ImmutableAuditLog(primary)
    log.append("event", {"ok": True})

    assert mirror.exists()
    assert primary.read_text(encoding="utf-8") == mirror.read_text(encoding="utf-8")


def test_immutable_log_disables_same_path_mirroring(tmp_path: Path):
    primary = tmp_path / "audit.log"
    log = ImmutableAuditLog(primary, out_of_band_path=primary)

    log.append("event", {"same": True})
    entries = [line for line in primary.read_text(encoding="utf-8").splitlines() if line]
    assert len(entries) == 1


def test_sinkhole_destinations_idempotent_and_validated(tmp_path: Path):
    hosts_path = tmp_path / "hosts"
    hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    executor = ContainmentActionExecutor(active_mode=True)
    first = executor.execute(
        host="h1",
        action="sinkhole_suspicious_destinations",
        context={
            "hosts_override_path": str(hosts_path),
            "destinations": ["evil.example", "bad_domain!!"],
            "sinkhole_ip": "127.0.0.1",
        },
    )
    second = executor.execute(
        host="h1",
        action="sinkhole_suspicious_destinations",
        context={
            "hosts_override_path": str(hosts_path),
            "destinations": ["evil.example"],
            "sinkhole_ip": "127.0.0.1",
        },
    )

    assert first.status == "executed"
    assert second.status == "no-op"
    contents = hosts_path.read_text(encoding="utf-8")
    assert contents.count("127.0.0.1 evil.example") == 1


def test_parse_syslog_line_handles_rfc3164_format():
    parsed = parse_syslog_line("<13>Jan 10 12:00:00 host1 sshd[123]: Failed login for user")
    assert parsed["host"] == "host1"
    assert parsed["process"] == "sshd"
    assert parsed["action"] == "syslog_event"
    assert "Failed login" in parsed["message"]


def test_autohardware_key_bootstrap_creates_sealed_pair(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

    key_path = tmp_path / "data" / "auto_hardware_ed25519.pem"
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "auto_hardware_private_key_path": str(key_path),
        "auto_hardware_persist_private_key": True,
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
    seal_path = key_path.with_suffix(".pem.seal")

    assert key_path.exists()
    assert seal_path.exists()
    seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
    assert seal_payload["private_key_sha256"]
    assert seal_payload["public_key_sha256"]
    runtime.ingestion_service.stop()


def test_autohardware_key_rejects_tampered_sealed_private_key(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

    key_path = tmp_path / "data" / "auto_hardware_ed25519.pem"
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "auto_hardware_private_key_path": str(key_path),
        "auto_hardware_persist_private_key": True,
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
    runtime.ingestion_service.stop()

    key_path.write_text("tampered", encoding="utf-8")

    cfg_tampered = json.loads(json.dumps(cfg))
    cfg_tampered.pop("containment_signature", None)
    cfg_tampered["trusted_hardware_public_keys"] = {}
    with pytest.raises(RuntimeError, match="integrity check failed"):
        SentinelRuntime(Settings(cfg_tampered))


def test_autohardware_default_does_not_persist_private_key_or_bypass(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

    key_path = tmp_path / "data" / "auto_hardware_ed25519.pem"
    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "auto_hardware_private_key_path": str(key_path),
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

    assert not key_path.exists()
    assert runtime.settings.get("containment_signature") is None
    notice = runtime.get_hardware_key_setup_notice()
    assert "operator_signature_required" in notice["details"]
    runtime.ingestion_service.stop()



def test_web_local_request_rejects_spoofed_xff_without_trusted_proxy(monkeypatch):
    from sentinel_containment.web import app as web_app

    monkeypatch.setattr(web_app, "_TRUSTED_REVERSE_PROXIES", set())
    with web_app.app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "203.0.113.10"}, headers={"X-Forwarded-For": "127.0.0.1"}):
        assert web_app._is_local_request() is False


def test_web_local_request_allows_trusted_proxy_with_loopback_xff(monkeypatch):
    from sentinel_containment.web import app as web_app

    monkeypatch.setattr(web_app, "_TRUSTED_REVERSE_PROXIES", {"203.0.113.5"})
    with web_app.app.test_request_context("/", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}, headers={"X-Forwarded-For": "127.0.0.1"}):
        assert web_app._is_local_request() is True


def test_runtime_uses_single_containment_engine(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

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

    assert runtime.fast_lane_containment is runtime.containment
    runtime.ingestion_service.stop()


def test_peer_mesh_advertisement_uses_stable_key(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

    cfg = {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "peer_advertisement": {"enabled": True, "peer_urls": []},
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

    runtime._advertise_peer_mesh()
    first_payload = runtime._peer_advertisement_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    runtime._advertise_peer_mesh()
    second_payload = runtime._peer_advertisement_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    assert first_payload == second_payload
    runtime.ingestion_service.stop()


def test_ssh_containment_defaults_to_strict_host_key_checking():
    executor = ContainmentActionExecutor(active_mode=False)
    result = executor.execute(
        host="host-a",
        action="execute_remote_ssh_containment",
        context={"remote_host": "example.internal", "containment_commands": ["snapshot"]},
    )

    assert result.status == "simulated"
    assert "StrictHostKeyChecking=yes" in result.details["command"]
    assert "UserKnownHostsFile=" in result.details["command"]


def test_runtime_writes_latest_state_atomically(tmp_path: Path):
    from sentinel_containment.config import Settings
    from sentinel_containment.runtime import SentinelRuntime

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

    runtime._write_latest_state({"candidate_severity": 90, "alerts": []})

    assert json.loads(runtime.latest_state_path.read_text(encoding="utf-8"))["candidate_severity"] == 90
    assert list(runtime.latest_state_path.parent.glob("*.tmp")) == []
    runtime.ingestion_service.stop()


def test_immutable_log_hash_chain_survives_concurrent_appends(tmp_path: Path):
    primary = tmp_path / "audit.log"
    log = ImmutableAuditLog(primary)

    def _worker(idx: int) -> None:
        for n in range(20):
            log.append("event", {"worker": idx, "n": n})

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    entries = [json.loads(line) for line in primary.read_text(encoding="utf-8").splitlines() if line]
    assert len(entries) == 80
    prev = "GENESIS"
    for entry in entries:
        assert entry["prev_hash"] == prev
        raw = {
            "timestamp": entry["timestamp"],
            "event_type": entry["event_type"],
            "payload": entry["payload"],
            "prev_hash": entry["prev_hash"],
        }
        expected = hashlib.sha256(json.dumps(raw, sort_keys=True).encode("utf-8")).hexdigest()
        assert entry["entry_hash"] == expected
        prev = entry["entry_hash"]
