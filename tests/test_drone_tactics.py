from pathlib import Path
import threading

from sentinel_containment.controlplane import DroneBehaviour, DroneNode, HegemonControlPlane
from sentinel_containment.drone_tactics import (
    LateralMovementDesigner,
    IntruderConfrontationDesigner,
    normalize_target_host,
    normalize_ip,
    clamp,
)


def _mini_behaviour() -> DroneBehaviour:
    return DroneBehaviour(
        behaviour_id="brain-mini-tactics",
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


def test_lateral_designer_candidate_ports_and_service_inference():
    d = LateralMovementDesigner()
    ports = d.build_candidate_ports("winrm", 5986)
    assert ports[0] == 5986
    assert 5985 in ports
    services = d.infer_services([5985, 445, 22, 80], {5985: "winrm", 445: "SMB", 22: "OpenSSH", 80: "HTTP/1.1"})
    assert services[5985] == "winrm"
    assert services[445] == "smb"
    assert services[22] == "ssh"
    assert services[80] == "http"


def test_lateral_designer_design_plan_generates_chain_and_recommendations():
    d = LateralMovementDesigner()
    plan = d.design_plan(
        source_host="10.0.0.2",
        target_host="10.0.0.44",
        method="ssh_hop",
        seed_port=22,
        observed_open_ports=[22, 443],
        observed_banners={22: "OpenSSH_9.5", 443: "HTTPS gateway"},
        mesh_hosts=["10.0.0.5", "10.0.1.10", "10.0.2.25"],
        host_roles={"10.0.0.5": "domain_controller", "10.0.1.10": "db", "10.0.2.25": "workstation"},
        host_trust={"10.0.0.2": 0.2, "10.0.0.44": 0.65},
        host_anomaly={"10.0.0.2": 0.1, "10.0.0.44": 0.4},
    )
    assert plan.target == "10.0.0.44"
    assert plan.method == "ssh_hop"
    assert plan.confidence >= 0.0
    assert plan.detection_risk >= 0.0
    assert isinstance(plan.recommendations, list)
    assert "selected_chain" in plan.telemetry
    assert "host_opportunities" in plan.telemetry


def test_countermeasure_designer_outputs_phase_telemetry_and_rollback():
    d = IntruderConfrontationDesigner()
    plan = d.design_plan(
        target="10.0.0.77",
        strategy="counter-lateral-quarantine",
        intruder_score=0.82,
        lateral_pressure=0.71,
        endpoint_criticality=0.88,
        confidence=0.63,
        active_sessions=7,
    )
    assert plan.target == "10.0.0.77"
    assert plan.risk_score > 0.0
    assert plan.containment_strength > 0.0
    assert set(plan.phases.keys()) == {"prepare", "contain", "recover"}
    assert len(plan.phases["contain"]) >= 3
    assert len(plan.rollback_steps) >= 3
    assert "phase_actions" in plan.telemetry
    assert "operator_brief" in plan.telemetry


def test_normalization_helpers_are_stable():
    assert normalize_target_host(" localhost ") == "127.0.0.1"
    assert normalize_target_host("10.1.2.3") == "10.1.2.3"
    assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert normalize_ip("not-an-ip") == "not-an-ip"
    assert clamp(10.0) == 1.0
    assert clamp(-3.0) == 0.0
    assert clamp(0.2) == 0.2


def test_controlplane_execute_node_lateral_move_uses_designer_payload(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("SophPivot", "autonomous", "custom", _mini_behaviour(), autonomy_level="enforce", actor="tester")
    node = DroneNode(
        node_id="lm",
        node_type="action",
        kind="lateral_move",
        label="Lateral",
        params={"host": "127.0.0.1", "port": 22, "method": "ssh_hop"},
        position={"x": 0, "y": 0},
        edges_out=[],
        edge_labels={},
    )
    nxt = cp._execute_node(drone, node, {"lm": node}, {}, threading.Event(), 0.0)
    assert nxt is None
    assert any(fid.startswith("pivot-") for fid in drone.findings)
    assert any("designed chain=" in row.get("message", "") for row in drone.telemetry)
    telemetry_rows = [row for row in drone.telemetry if "pivot_telemetry" in row]
    assert telemetry_rows
    assert "recommendations" in telemetry_rows[-1]["pivot_telemetry"]
    assert "pivot_execution" in telemetry_rows[-1]


def test_controlplane_execute_node_countermeasure_uses_designer_payload(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("SophCM", "autonomous", "custom", _mini_behaviour(), autonomy_level="enforce", actor="tester")
    node = DroneNode(
        node_id="cm",
        node_type="action",
        kind="countermeasure",
        label="Counter",
        params={
            "target": "10.0.0.66",
            "strategy": "active-containment",
            "active_sessions": 8,
            "lateral_pressure": 0.73,
            "criticality": 0.87,
        },
        position={"x": 0, "y": 0},
        edges_out=[],
        edge_labels={},
    )
    nxt = cp._execute_node(drone, node, {"cm": node}, {}, threading.Event(), 0.0)
    assert nxt is None
    assert any(fid.startswith("countermeasure-active-containment") for fid in drone.findings)
    rows = [row for row in drone.telemetry if "countermeasure_telemetry" in row]
    assert rows
    telemetry = rows[-1]["countermeasure_telemetry"]
    assert telemetry["strategy"] == "active-containment"
    assert telemetry["phase_stats"]["contain"]["count"] >= 3
