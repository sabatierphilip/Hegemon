from pathlib import Path
import json
import hashlib
import hmac
import os
import base64
import zlib
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pytest

from sentinel_containment.controlplane import DroneBehaviour, DroneNode, HegemonControlPlane
from sentinel_containment.drone_compiler import DroneBlobCompiler, deploy_blob_remote, launch_blob_locally


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
    assert "PRIVATE_KEY_HEX" not in source
    assert "HG_DRONE_KEY_HEX" in source


def test_autonomous_drone_launches_detached_from_hegemon_io(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("FreeAuto", "autonomous", "custom", _mini_behaviour(), actor="tester")
    assert drone.deadrop_path.endswith("/deadrop")
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
    nonce = os.urandom(12)
    aes_key = hashlib.sha256(bytes.fromhex(key_hex[:64])).digest()
    aad = f"{drone.drone_id}:deadrop:v3:aes-256-gcm".encode()
    encrypted = AESGCM(aes_key).encrypt(nonce, raw, aad)
    sig = hmac.new(bytes.fromhex(key_hex[:64]), encrypted, hashlib.sha256).hexdigest()
    envelope = base64.b64encode(json.dumps({
        "v": 3,
        "alg": "AES-256-GCM",
        "aad": base64.b64encode(aad).decode(),
        "sig": sig,
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(encrypted).decode(),
    }).encode()).decode()
    Path(drone.deadrop_path).parent.mkdir(parents=True, exist_ok=True)
    Path(drone.deadrop_path).write_text(envelope, encoding="utf-8")
    cp._poll_deadrop(drone.drone_id)
    assert "f1" in cp.drones[drone.drone_id].findings


def test_deadrop_polling_rejects_unencrypted_payload_shape(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("DropperPlain", "autonomous", "custom", _mini_behaviour(), actor="tester")
    envelope = base64.b64encode(json.dumps({"findings": ["f1"], "telemetry": [{"message": "hi"}]}).encode()).decode()
    Path(drone.deadrop_path).parent.mkdir(parents=True, exist_ok=True)
    Path(drone.deadrop_path).write_text(envelope, encoding="utf-8")
    cp._poll_deadrop(drone.drone_id)
    assert "f1" not in cp.drones[drone.drone_id].findings


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


def test_compiler_embedded_intel_uses_python_literals_for_booleans(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("BoolIntel", "controlled", "custom", _mini_behaviour(), actor="tester")
    key_hex = cp._drone_private_keys[drone.drone_id]

    source = DroneBlobCompiler()._render_script(
        drone,
        key_hex,
        {
            "vuln_sigs": [{"id": "sig-1", "enabled": True}],
            "attack_patterns": [{"pattern": "dns tunnel", "active": False}],
            "port_risk": {"443": {"critical": True}},
        },
    )

    assert "EMBEDDED_VULN_SIGS = [{'id': 'sig-1', 'enabled': True}]" in source
    assert "EMBEDDED_ATTACK_PATTERNS = [{'pattern': 'dns tunnel', 'active': False}]" in source
    assert "EMBEDDED_PORT_RISK = {'443': {'critical': True}}" in source


def test_compiled_ping_host_supports_payload_and_tcp_fallback(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    ping_behaviour = DroneBehaviour(
        behaviour_id="ping-msg",
        name="ping-msg",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="action", kind="ping_host", label="Ping", params={"host": "127.0.0.1", "message": "HEGEMON:TEST_1:RALDORONESQUE", "fallback_port": 443}, position={"x": 1.0, "y": 1.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="c", node_type="control", kind="self_terminate", label="Stop", params={}, position={"x": 2.0, "y": 2.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="ping msg",
        is_brain_preset=False,
    )
    drone = cp.assemble_drone("PingMsg", "controlled", "custom", ping_behaviour, actor="tester")
    source = cp.decode_drone_source(drone.drone_id)

    assert "message = str(params.get('message', '') or '')" in source
    assert "ping_cmd.extend(['-p', hex_payload])" in source
    assert "socket.create_connection((host, fallback_port), timeout=2)" in source


def test_sample_drone_catalog_and_assemble(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    catalog = cp.drone_sample_catalog()
    assert any(row["sample_id"] == "gnat-light" for row in catalog)

    drone = cp.assemble_sample_drone("gnat-light", destination="10.10.10.0/24", actor="tester")
    assert drone.target_network == "10.10.10.0/24"
    assert drone.behaviour.behaviour_id == "brain-pinger-basic"


def test_assemble_sample_squad_routes_are_embedded(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    built = cp.assemble_sample_squad(
        nodes=[
            {"id": "n1", "sample_id": "carrier-relay", "destination": "10.0.1.0/24"},
            {"id": "n2", "sample_id": "gnat-light", "destination": "10.0.2.0/24"},
        ],
        links=[{"from_id": "n1", "to_id": "n2"}],
        actor="tester",
    )
    assert len(built) == 2
    source = next(d for d in built if d.payload.get("squad_node_id") == "n1")
    assert source.payload.get("route_targets")


def test_launch_blob_locally_uses_binary_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("LocalBin", "controlled", "custom", _mini_behaviour(), actor="tester")
    blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
    key_hex = cp._drone_private_keys[drone.drone_id]

    popen_calls: list[list[str]] = []

    class _DummyPopen:
        def __init__(self, argv, **_kwargs):
            popen_calls.append(list(argv))

    monkeypatch.setattr("sentinel_containment.drone_compiler.subprocess.Popen", _DummyPopen)

    launch_blob_locally(blob_b64, key_hex, tmp_path)

    assert popen_calls
    launched_path = Path(popen_calls[0][-1])
    assert launched_path.suffix == ".bin"
    assert launched_path.exists()
    assert launched_path.name.startswith("drone_")
    token = launched_path.stem.split("drone_", 1)[1]
    assert 8 <= len(token) <= 20
    assert not (tmp_path / "drone.py").exists()


def test_deploy_blob_remote_uses_binary_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone("RemoteBin", "controlled", "custom", _mini_behaviour(), actor="tester")
    blob_b64 = Path(drone.blob_path).read_text(encoding="utf-8").strip()
    key_hex = cp._drone_private_keys[drone.drone_id]

    run_calls: list[list[str]] = []

    class _DummyCompleted:
        def __init__(self, stdout: str = "1234\n"):
            self.stdout = stdout
            self.stderr = ""

    def _fake_run(cmd, **_kwargs):
        run_calls.append(list(cmd))
        return _DummyCompleted()

    monkeypatch.setattr("sentinel_containment.drone_compiler.subprocess.run", _fake_run)

    result = deploy_blob_remote(blob_b64, key_hex, "example.com", "/tmp/id_rsa", "/opt/hegemon")

    assert result["remote_path"].endswith(".bin")
    remote_name = Path(result["remote_path"]).name
    assert remote_name.startswith("drone_")
    random_token = remote_name.rsplit(".", 1)[0].split("_", 2)[-1]
    assert 8 <= len(random_token) <= 20
    assert any("drone_" in part and part.endswith(".bin") for part in run_calls[0])
    assert any(".bin" in part for part in run_calls[1])



def test_compiler_respects_runtime_ring_levels(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone(
        "Ringed",
        "controlled",
        "custom",
        _mini_behaviour(),
        actor="tester",
        runtime={"execution": {"ring_level": 1}, "telemetry": {"kernel_feed": {"provider": "ebpf"}}},
    )
    source = cp.decode_drone_source(drone.drone_id)

    assert drone.compiler_ring == 1
    assert "RING_LEVEL = 1" in source
    assert "Ring 1 micro-kernel envelope armed" in source


def test_spawn_child_drone_accepts_nested_child_graph(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    parent_behaviour = DroneBehaviour(
        behaviour_id="parent-child",
        name="parent-child",
        nodes=[
            DroneNode(node_id="a", node_type="trigger", kind="on_launch", label="On Launch", params={}, position={"x": 0.0, "y": 0.0}, edges_out=["b"], edge_labels={}),
            DroneNode(node_id="b", node_type="action", kind="spawn_child_drone", label="Spawn", params={}, position={"x": 1.0, "y": 0.0}, edges_out=["c"], edge_labels={}),
            DroneNode(node_id="c", node_type="control", kind="self_terminate", label="Stop", params={}, position={"x": 2.0, "y": 0.0}, edges_out=[], edge_labels={}),
        ],
        created_at="2026-01-01T00:00:00+00:00",
        author="tester",
        description="parent",
        is_brain_preset=False,
    )

    runtime = {
        "child_graph": {
            "nodes": [
                {"id": "ca", "type": "trigger", "data": {"kind": "on_launch", "label": "On Launch", "params": {}}, "position": {"x": 0, "y": 0}},
                {"id": "cb", "type": "action", "data": {"kind": "emit_alert", "label": "Emit", "params": {"message": "child"}}, "position": {"x": 100, "y": 0}},
            ],
            "edges": [{"source": "ca", "target": "cb"}],
        }
    }

    drone = cp.assemble_drone("Parent", "autonomous", "custom", parent_behaviour, actor="tester", runtime=runtime)
    source = cp.decode_drone_source(drone.drone_id)
    match = re.search(r"CHILD_DRONE_BLOB = '([^']*)'", source)
    assert match is not None
    child_blob = match.group(1)
    assert child_blob

    child_source = zlib.decompress(base64.b64decode(child_blob.encode())).decode()
    assert "kind': 'emit_alert'" in child_source


def test_compose_behaviour_from_graph_maps_edges(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    behaviour = cp._compose_behaviour_from_graph(
        [
            {"id": "a", "type": "trigger", "data": {"kind": "on_launch", "label": "Launch", "params": {}}},
            {"id": "b", "type": "action", "data": {"kind": "send_report", "label": "Report", "params": {"severity": "info"}}},
        ],
        [{"source": "a", "target": "b", "label": "next"}],
        behaviour_id="graph-beh",
        name="graph-beh",
    )

    assert behaviour.behaviour_id == "graph-beh"
    node_a = next(n for n in behaviour.nodes if n.node_id == "a")
    assert node_a.edges_out == ["b"]
    assert node_a.edge_labels.get("b") == "next"


def test_spawn_child_drone_uses_randomized_bin_name(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    drone = cp.assemble_drone(
        "ChildRun",
        "autonomous",
        "custom",
        _mini_behaviour(),
        actor="tester",
        autonomy_level="enforce",
        runtime={
            "child_drone_blob": base64.b64encode(zlib.compress("print(\'child\')\n".encode("utf-8"))).decode("ascii"),
        },
    )
    source = cp.decode_drone_source(drone.drone_id)
    assert '_script_random_bin_name("child")' in source


def test_seeded_brains_include_lateral_and_confrontation_elements(tmp_path: Path):
    cp = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    ghost = cp.drone_brains["brain-ghost-hunter"]
    watcher = cp.drone_brains["brain-watcher"]

    ghost_kinds = {n.kind for n in ghost.nodes}
    watcher_kinds = {n.kind for n in watcher.nodes}

    assert "lateral_move" in ghost_kinds
    assert "credential_probe" in ghost_kinds
    assert "confront_intruder" in ghost_kinds
    assert "lateral_move" in watcher_kinds
    assert "confront_intruder" in watcher_kinds
