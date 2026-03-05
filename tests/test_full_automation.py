from __future__ import annotations

from sentinel_containment.controlplane import AutoPatchPolicy, HegemonControlPlane
from sentinel_containment.discovery import NetworkDiscoveryEngine
from sentinel_containment.security.peer_mesh import PeerMeshNode
from cryptography.hazmat.primitives.asymmetric import ed25519


def test_agent_enrollment_flow():
    cp = HegemonControlPlane()
    endpoint = cp.add_endpoint(
        {
            "endpoint_id": "ep-agent-1",
            "host_name": "agent-host",
            "os": "linux",
            "kernel": "6.8",
            "enrollment_method": "agent",
            "installed_packages": {"openssl": "3"},
        },
        actor="test",
    )
    assert endpoint.endpoint_id == "ep-agent-1"
    assert cp.endpoints["ep-agent-1"].installed_packages["openssl"] == "3"


def test_discovery_sweep_mock():
    cp = HegemonControlPlane()
    engine = NetworkDiscoveryEngine(cp)
    engine.last_hosts = [{"host": "10.0.0.9", "friendly": False}]
    status = engine.status()
    assert status["discovered_hosts"] == 1


def test_auto_patch_policy_enforcement():
    cp = HegemonControlPlane()
    cp.auto_patch_policy = AutoPatchPolicy(max_auto_cvss=7.0, max_auto_risk_score=7.0, auto_apply_delay_seconds=0)
    ep = cp.add_endpoint({"endpoint_id": "ep-a", "host_name": "h", "os": "linux", "kernel": "1"}, actor="t")
    finding = cp.create_finding(
        {
            "endpoint_id": ep.endpoint_id,
            "cve": "CVE-2026-0001",
            "cvss": 6.0,
            "exploit_availability": 4.0,
            "topological_impact": 4.0,
            "asset_value": 5.0,
            "trust_level": 5.0,
            "evidence": [],
            "suggested_remediations": ["upgrade openssl to latest"],
        },
        actor="t",
    )
    proposal = cp.generate_patch_proposal(finding.finding_id, actor="t")
    out = cp.run_auto_patch_cycle(now=100)
    assert out["approved"] >= 1
    assert cp.patch_proposals[proposal.proposal_id].status == "deployed_canary"


def test_peer_quorum_with_mock_peers():
    node = PeerMeshNode("node-a", "http://127.0.0.1:9", ed25519.Ed25519PrivateKey.generate())
    node.register_peer({"instance_id": "node-b", "url": "http://127.0.0.1:9", "public_key": "x"})
    result = node.p2p_verify_hunter_directives({"directive": "test"}, quorum=1)
    assert result["quorum_met"] is False


def test_notification_dispatch():
    rate = {}
    host = "h1"
    now = 1000
    should_send = now - rate.get(host, 0) >= 600
    assert should_send
    rate[host] = now
    assert not (1001 - rate.get(host, 0) >= 600)
