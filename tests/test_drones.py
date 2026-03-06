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


def test_available_binary_action_catalog(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    actions = cp.available_drone_actions()
    assert any(row["binary"] == "00000011" and row["action"] == "report" for row in actions)
    assert len(actions) >= 10


def test_blob_roundtrip_and_source_decode(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("Blobber", "tethered", "custom", _mini_behaviour(), autonomy_level="contain", actor="tester")
    assert drone.binary_blob
    source = cp.decode_drone_source(drone.drone_id)
    assert "DRONE_ID" in source
    assert drone.drone_id in source


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
