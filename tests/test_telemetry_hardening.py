import json
from pathlib import Path

from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import JSONLinesFileSource


def test_ingestor_flags_rogue_file_access_and_core_verification(tmp_path: Path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path, signing_key="test-key", key_rotation_seconds=60)

    ingestor.ingest(
        "host_kernel",
        {
            "host": "node-a",
            "process": "proto-agent-runtime",
            "action": "file_read",
            "resource": "/etc/shadow",
            "collector_level": "runtime",
        },
    )
    ingestor.ingest(
        "counterclone",
        {
            "host": "node-a",
            "process": "counterclone-sensor",
            "action": "emit_synthetic_probe",
            "resource": "control-plane",
            "collector_level": "counterclone",
            "counterclone_participant": True,
            "counterclone_integrity_verified": True,
        },
    )

    docs = ingestor.read_recent(limit=10)
    kernel_event = docs[0]
    counterclone_event = docs[1]

    assert kernel_event["collector_level_verified"] is True
    assert kernel_event["verification"]["rogue_file_access_suspected"] is True
    assert kernel_event["verification"]["protected_path_touched"] is True
    assert counterclone_event["verification"]["core_telemetry_verified"] is True
    assert ingestor.verify_recent(limit=10)


def test_jsonl_source_marks_world_writable_sources_unverified(tmp_path: Path):
    index_path = tmp_path / "telemetry_index.jsonl"
    ingestor = TelemetryIngestor(index_path)

    source_path = tmp_path / "kernel_events.jsonl"
    source_path.write_text(json.dumps({"host": "h1", "action": "file_read", "resource": "/etc/passwd"}) + "\n", encoding="utf-8")
    source_path.chmod(0o666)

    source = JSONLinesFileSource(source_path, "host_kernel", ingestor)
    processed = source.poll_once()

    assert processed == 1
    doc = ingestor.read_recent(limit=1)[0]
    assert doc["verification"]["collector_file_guard_verified"] is False
