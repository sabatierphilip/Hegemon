import json
from pathlib import Path

import pytest

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
