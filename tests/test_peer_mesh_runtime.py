from pathlib import Path

from sentinel_containment.config import Settings
from sentinel_containment.runtime import SentinelRuntime


def _runtime_cfg(tmp_path: Path) -> dict:
    return {
        "telemetry_index_path": str(tmp_path / "telemetry_index.jsonl"),
        "latest_state_path": str(tmp_path / "latest_state.json"),
        "rules_path": str(tmp_path / "rules"),
        "peer_verification": {
            "interval_seconds": 1,
            "require_external_verifiers": False,
            "peer_ids": ["p1", "p2", "p3"],
            "checkpoint_quorum": 2,
            "checkpoint_signers": ["p1", "p2", "p3"],
            "replication_targets": ["notary-a", "notary-b"],
            "checkpoint_require_sequential": True,
        },
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


def test_runtime_emits_p2p_checkpoint_in_state(tmp_path: Path):
    (tmp_path / "rules").mkdir()
    runtime = SentinelRuntime(Settings(_runtime_cfg(tmp_path)))

    state = runtime.run_once()
    assert "p2p_checkpoint" in state
    payload = state["p2p_checkpoint"]
    assert payload["accepted"] is True
    assert payload["quorum_met"] is True
    assert payload["checkpoint"]["seq_no"] >= 1
    assert payload["observed_notaries"] >= 2

    runtime.ingestion_service.stop()
