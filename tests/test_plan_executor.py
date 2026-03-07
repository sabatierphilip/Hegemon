from pathlib import Path

from sentinel_containment.controlplane import DroneBehaviour, DroneNode, HegemonControlPlane
from sentinel_containment.plan_executor import SophisticatedBinaryPlanExecutor


def _behaviour_with_rag_report() -> DroneBehaviour:
    return DroneBehaviour(
        behaviour_id="brain-rag",
        name="rag-report",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="intel", kind="local_intel_match", label="RAG", params={}, position={"x": 1.0, "y": 0.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="c", node_type="report", kind="send_report", label="Report", params={}, position={"x": 2.0, "y": 0.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="rag",
    )


def test_sophisticated_executor_blob_roundtrip_and_execution():
    executor = SophisticatedBinaryPlanExecutor()
    blob = executor.build_blob(
        plan=[
            {"id": "s1", "opcode": "visit_node", "kind": "on_launch"},
            {"id": "s2", "opcode": "collect_context", "query": "intel"},
            {"id": "s3", "opcode": "emit_report", "summary": "done"},
            {"id": "s4", "opcode": "set_flag", "key": "complete", "value": True},
        ],
        rag_context=["intel snapshot: healthy", "network baseline"],
    )

    decoded = executor.decode_blob(blob)
    assert decoded["kind"] == "binary_executor"
    assert decoded["engine"] == "sophisticated_plan_executor_v1"

    result = executor.execute_blob(blob)
    assert result["success"] is True
    assert result["steps_total"] == 4
    assert result["flags"]["complete"] is True


def test_assemble_drone_injects_binary_executor_payload(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone(
        "PlanCat",
        "controlled",
        "custom",
        _behaviour_with_rag_report(),
        actor="tester",
        payload={"rag_context": ["intel breadcrumbs", "dns anomaly map"]},
        runtime={"rag": {"context": ["historical intel", "fleet topology"]}},
    )

    payload = drone.payload
    assert isinstance(payload, dict)
    assert payload.get("plan_executor_engine") == "sophisticated_plan_executor_v1"
    assert isinstance(payload.get("plan"), list) and len(payload["plan"]) >= 4

    runtime = drone.runtime
    assert runtime.get("plan_executor", {}).get("kind") == "binary_executor"
    blob = runtime["plan_executor"]["blob_b64"]
    result = SophisticatedBinaryPlanExecutor().execute_blob(blob)
    assert result["success"] is True
    assert result["steps_ok"] == result["steps_total"]
