from pathlib import Path

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
    queued = cp.send_drone_command(controlled.drone_id, "report", {}, actor="tester")
    assert queued["queued"] is True

    auto = cp.assemble_drone("Auto", "autonomous", "custom", _mini_behaviour(), actor="tester")
    with pytest.raises(ValueError):
        cp.send_drone_command(auto.drone_id, "report", {}, actor="tester")


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
