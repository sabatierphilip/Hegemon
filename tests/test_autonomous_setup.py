from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime
from sentinel_containment.web import app as web_app


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


def test_dashboard_token_auto_bootstraps_without_manual_setup(tmp_path: Path, monkeypatch):
    token_path = tmp_path / "dashboard.token"
    monkeypatch.delenv("SENTINEL_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("SENTINEL_DASHBOARD_TOKEN_FILE", str(token_path))

    token = web_app._api_token()

    assert token
    assert token_path.exists()
    assert token_path.read_text(encoding="utf-8").strip() == token


def test_notification_dispatch_records_channels(tmp_path: Path):
    cfg = _base_cfg(tmp_path)
    cfg["notifications"] = {"webhook_url": "https://example.invalid/hook", "smtp_host": "smtp.invalid"}
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))

    runtime._dispatch_webhook_notification = lambda event: True  # type: ignore[method-assign]
    runtime._dispatch_smtp_notification = lambda event: False  # type: ignore[method-assign]

    out = runtime._dispatch_notifications({"severity": 90, "host": "h1"})

    assert out == {"webhook": True, "smtp": False}
    runtime.ingestion_service.stop()


def test_peer_mesh_advertisement_can_be_disabled(tmp_path: Path):
    cfg = _base_cfg(tmp_path)
    cfg["peer_mesh_advertisement"] = {"enabled": False}
    (tmp_path / "rules").mkdir()

    runtime = SentinelRuntime(Settings(cfg))

    out = runtime._advertise_peer_mesh()

    assert out["enabled"] is False
    assert out["sent"] == 0
    runtime.ingestion_service.stop()
