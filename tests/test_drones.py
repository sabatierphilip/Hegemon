from pathlib import Path
import json

import pytest

from sentinel_containment.controlplane import DroneBehaviour, DroneNode, HegemonControlPlane


def _mini_behaviour() -> DroneBehaviour:
    return DroneBehaviour(
        behaviour_id="brain-mini",
        name="mini",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="control", kind="self_terminate", label="Stop", params={}, position={"x": 1.0, "y": 1.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="test",
        is_brain_preset=False,
    )


def test_assemble_launch_and_terminate_drone(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone(
        name="TestDrone",
        tier="controlled",
        mission="custom",
        behaviour=_mini_behaviour(),
        autonomy_level="observe",
        actor="tester",
    )
    assert drone.status == "ready"
    launched = cp.launch_drone(drone.drone_id, actor="tester")
    assert launched.status in {"active", "terminated"}
    terminated = cp.terminate_drone(drone.drone_id, actor="tester")
    assert terminated.status == "terminated"


def test_controlled_command_dispatch_and_autonomous_block(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    controlled = cp.assemble_drone("Ctl", "controlled", "custom", _mini_behaviour(), actor="tester")
    queued = cp.send_drone_command(controlled.drone_id, "00000011", {}, actor="tester")
    assert queued["queued"] is True
    assert queued["command"] == "report"

    with pytest.raises(ValueError):
        cp.send_drone_command(controlled.drone_id, "report", {}, actor="tester")

    auto = cp.assemble_drone("Auto", "autonomous", "custom", _mini_behaviour(), actor="tester")
    with pytest.raises(ValueError):
        cp.send_drone_command(auto.drone_id, "00000011", {}, actor="tester")


def test_safety_constraint_external_host_requires_observe(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    with pytest.raises(ValueError):
        cp.assemble_drone(
            name="Bad",
            tier="controlled",
            mission="custom",
            behaviour=_mini_behaviour(),
            target_host="unregistered.external",
            autonomy_level="enforce",
            actor="tester",
        )


def test_ttl_expiry_terminates_drone(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    behaviour = DroneBehaviour(
        behaviour_id="ttl",
        name="ttl",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="control", kind="wait", label="Wait", params={"seconds": 10}, position={"x": 1.0, "y": 1.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="c", node_type="control", kind="self_terminate", label="Stop", params={}, position={"x": 2.0, "y": 2.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="ttl",
    )
    drone = cp.assemble_drone("TTL", "controlled", "custom", behaviour, ttl_seconds=1, checkin_interval_seconds=1)
    cp.launch_drone(drone.drone_id, actor="tester")
    import time

    time.sleep(6)
    assert cp.drones[drone.drone_id].status == "terminated"


def test_delete_drone_restrictions(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    controlled = cp.assemble_drone("CtlDel", "controlled", "custom", _mini_behaviour(), actor="tester")
    deleted = cp.delete_drone(controlled.drone_id, actor="tester")
    assert deleted["deleted"] is True

    autonomous = cp.assemble_drone("AutoDel", "autonomous", "custom", _mini_behaviour(), actor="tester")
    with pytest.raises(ValueError):
        cp.delete_drone(autonomous.drone_id, actor="tester")


def test_drone_is_compiled_to_binary_blueprint(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("BinaryPrime", "controlled", "custom", _mini_behaviour(), actor="tester")
    assert drone.binary_blueprint
    assert set(drone.binary_blueprint).issubset({"0", "1"})
    assert len(drone.binary_blueprint) > 128
    assert "00000011" in drone.supported_binary_actions




def test_drone_payload_is_compiled_to_binary_and_embedded(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    payload = {"task": "collect", "targets": ["10.0.0.10", "10.0.0.11"], "depth": 2}
    drone = cp.assemble_drone("Carrier", "tethered", "custom", _mini_behaviour(), payload=payload, actor="tester")
    assert drone.payload == payload
    assert drone.payload_binary
    assert set(drone.payload_binary).issubset({"0", "1"})
    source = cp.decode_drone_source(drone.drone_id)
    assert "PAYLOAD_BIN" in source
    assert "PAYLOAD_JSON" in source

def test_available_binary_action_catalog(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    actions = cp.available_drone_actions()
    assert any(row["binary"] == "00000011" and row["action"] == "report" for row in actions)
    assert len(actions) >= 10


def test_blob_roundtrip_and_source_decode(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("Blobber", "tethered", "custom", _mini_behaviour(), autonomy_level="contain", actor="tester")
    assert drone.binary_blob == ""
    assert drone.blob_path
    assert Path(drone.blob_path).exists()
    source = cp.decode_drone_source(drone.drone_id)
    assert "DRONE_ID" in source
    assert drone.drone_id in source


def test_autonomous_drone_launches_detached_from_hegemon_io(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("FreeAuto", "autonomous", "custom", _mini_behaviour(), actor="tester")
    cp.launch_drone(drone.drone_id, actor="tester")

    proc = cp._drone_processes[drone.drone_id]
    assert proc.stdout is None
    assert proc.stderr is None


def test_deadrop_polling_merges_payload(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("Dropper", "autonomous", "custom", _mini_behaviour(), actor="tester")
    key_hex = cp._drone_private_keys[drone.drone_id]
    payload = {"findings": ["f1"], "telemetry": [{"message": "hi"}]}
    raw = json.dumps(payload).encode("utf-8")
    key = bytes.fromhex(key_hex[:32])
    key_cycle = (key * (len(raw) // len(key) + 1))[:len(raw)]
    encrypted = bytes(a ^ b for a, b in zip(raw, key_cycle))
    sig = __import__("hmac").new(bytes.fromhex(key_hex[:64]), encrypted, __import__("hashlib").sha256).hexdigest()
    envelope = __import__("base64").b64encode(json.dumps({"sig": sig, "data": __import__("base64").b64encode(encrypted).decode()}).encode()).decode()
    Path(drone.deadrop_path).write_text(envelope, encoding="utf-8")
    cp._poll_deadrop(drone.drone_id)
    assert "f1" in cp.drones[drone.drone_id].findings


def test_drone_blob_is_stored_as_separate_file(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("FileBlob", "controlled", "custom", _mini_behaviour(), actor="tester")
    assert drone.binary_blob == ""
    assert drone.blob_path
    blob_file = Path(drone.blob_path)
    assert blob_file.exists()
    assert blob_file.read_text(encoding="utf-8").strip()


def test_compiled_drone_source_supports_looping_constructs(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    loop_behaviour = DroneBehaviour(
        behaviour_id="loop-mini",
        name="loop-mini",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="control", kind="repeat", label="Repeat", params={"target_node_id": "b", "max_iterations": 2}, position={"x": 1.0, "y": 1.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="c", node_type="control", kind="while_condition", label="While", params={"condition_key": "findings_count", "operator": "<", "threshold": 1, "target_node_id": "d"}, position={"x": 2.0, "y": 2.0}, edges_out=["e"], edge_labels={}),
            DroneNode(node_id="d", node_type="control", kind="wait", label="Wait", params={"seconds": 1}, position={"x": 3.0, "y": 3.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="e", node_type="control", kind="self_terminate", label="Stop", params={}, position={"x": 4.0, "y": 4.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="loop",
        is_brain_preset=False,
    )
    drone = cp.assemble_drone("Looper", "tethered", "custom", loop_behaviour, actor="tester")
    source = cp.decode_drone_source(drone.drone_id)
    assert "if kind in ('repeat', 'loop'):" in source
    assert "if kind in ('loop_until', 'while_condition'):" in source
