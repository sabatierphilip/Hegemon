import json
from pathlib import Path

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
