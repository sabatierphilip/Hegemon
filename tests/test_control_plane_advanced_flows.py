from pathlib import Path

import control_plane_service as cps
from sentinel_containment.controlplane import HegemonControlPlane


def _client(tmp_path: Path):
    cps.CONTROL_PLANE = HegemonControlPlane(ledger_path=tmp_path / "ledger.jsonl")
    return cps.app.test_client()


def test_friend_endpoint_vulnerability_and_patch_flow(tmp_path: Path):
    client = _client(tmp_path)

    friend = client.post(
        "/friends",
        json={
            "actor": "admin-1",
            "name": "Firmware Admin",
            "identity_type": "user",
            "identity_method": "public_key_upload",
            "capabilities": ["approve_firmware"],
            "expiry": "2030-01-01T00:00:00Z",
        },
    )
    assert friend.status_code == 201
    friend_payload = friend.get_json()
    assert friend_payload["status"] == "pending"
    assert friend_payload["approvals_required"] == 2

    approve_friend_1 = client.post(f"/friends/{friend_payload['friend_id']}/approve", json={"approver": "admin-2"})
    assert approve_friend_1.status_code == 200
    assert approve_friend_1.get_json()["status"] == "pending"

    approve_friend_2 = client.post(f"/friends/{friend_payload['friend_id']}/approve", json={"approver": "admin-3"})
    assert approve_friend_2.status_code == 200
    assert approve_friend_2.get_json()["status"] == "active"

    endpoint = client.post(
        "/endpoints",
        json={
            "actor": "ops-1",
            "host_name": "prod-app-1",
            "endpoint_type": "on-prem",
            "os": "ubuntu",
            "kernel": "6.8",
            "hypervisor": "kvm",
            "firmware_baseline": "1.0.4",
            "sbom_status": "valid",
            "enrollment_method": "mdm",
        },
    )
    assert endpoint.status_code == 201
    endpoint_id = endpoint.get_json()["endpoint_id"]

    finding = client.post(
        "/vulnerabilities",
        json={
            "actor": "scanner",
            "endpoint_id": endpoint_id,
            "cve": "CVE-2026-0001",
            "cvss": 9.8,
            "exploit_availability": 8.0,
            "topological_impact": 7.5,
            "asset_value": 9.2,
            "trust_level": 6.0,
            "evidence": [{"type": "sbom_match", "package": "openssl"}],
            "suggested_remediations": ["upgrade openssl to 3.0.18"],
        },
    )
    assert finding.status_code == 201
    finding_payload = finding.get_json()
    assert finding_payload["risk_score"] > 0

    proposal_resp = client.post("/patch-proposals/generate", json={"finding_id": finding_payload["finding_id"], "actor": "mtre"})
    assert proposal_resp.status_code == 201
    proposal = proposal_resp.get_json()
    assert proposal["approvals_required"] == 2
    assert proposal["graph_path_before"][-1]["node"] == "CVE-2026-0001"
    assert "reasoning" in proposal and proposal["reasoning"]

    apply_before = client.post(f"/patch-proposals/{proposal['proposal_id']}/apply", json={"actor": "admin-1"})
    assert apply_before.status_code == 400

    approve_1 = client.post(f"/patch-proposals/{proposal['proposal_id']}/approve", json={"approver": "admin-1"})
    assert approve_1.status_code == 200
    assert approve_1.get_json()["status"] == "pending_review"

    approve_2 = client.post(f"/patch-proposals/{proposal['proposal_id']}/approve", json={"approver": "admin-2"})
    assert approve_2.status_code == 200
    assert approve_2.get_json()["status"] == "approved"

    apply_after = client.post(f"/patch-proposals/{proposal['proposal_id']}/apply", json={"actor": "admin-2"})
    assert apply_after.status_code == 200
    assert apply_after.get_json()["status"] == "deployed_canary"

    preview = client.get("/ui/control-plane")
    assert preview.status_code == 200
    assert "Hegemon Control Plane Preview" in preview.get_data(as_text=True)

    graph = client.get("/entity-graph")
    assert graph.status_code == 200
    graph_payload = graph.get_json()
    assert len(graph_payload["nodes"]) >= 3
    assert any(e["type"] == "patched_by" for e in graph_payload["edges"])

    audit = client.get("/audit/ledger")
    assert audit.status_code == 200
    assert audit.get_json()["health"]["chain_valid"] is True


def test_disable_friend_flags_prior_patch_approvals(tmp_path: Path):
    client = _client(tmp_path)
    friend = client.post(
        "/friends",
        json={
            "actor": "admin-1",
            "name": "Patch Approver",
            "identity_type": "user",
            "identity_method": "public_key_upload",
            "capabilities": ["approve_patches"],
            "expiry": "2030-01-01T00:00:00Z",
        },
    )
    friend_id = friend.get_json()["friend_id"]

    endpoint = client.post(
        "/endpoints",
        json={
            "actor": "ops-1",
            "host_name": "prod-app-2",
            "endpoint_type": "on-prem",
            "os": "ubuntu",
            "kernel": "6.8",
            "sbom_status": "valid",
            "enrollment_method": "mdm",
        },
    )
    endpoint_id = endpoint.get_json()["endpoint_id"]
    finding = client.post(
        "/vulnerabilities",
        json={
            "actor": "scanner",
            "endpoint_id": endpoint_id,
            "cve": "CVE-2026-0002",
            "cvss": 8.8,
            "exploit_availability": 7.0,
            "topological_impact": 6.5,
            "asset_value": 8.2,
            "trust_level": 6.0,
        },
    )
    proposal = client.post("/patch-proposals/generate", json={"finding_id": finding.get_json()["finding_id"], "actor": "mtre"}).get_json()
    client.post(f"/patch-proposals/{proposal['proposal_id']}/approve", json={"approver": friend_id})

    disabled = client.post(f"/friends/{friend_id}/disable", json={"actor": "admin-1"})
    assert disabled.status_code == 200

    audit = client.get("/audit/ledger").get_json()["entries"]
    revoke_entries = [e for e in audit if e.get("event_type") == "friend.revoked"]
    assert revoke_entries
    assert proposal["proposal_id"] in revoke_entries[-1]["payload"]["flagged_pending_patch_approvals"]


def test_app_store_endpoint_requires_signature(tmp_path: Path):
    client = _client(tmp_path)
    resp = client.post(
        "/endpoints",
        json={
            "actor": "ops-1",
            "host_name": "steam-package",
            "endpoint_type": "app-store-package",
            "os": "windows",
            "kernel": "nt",
            "sbom_status": "valid",
            "enrollment_method": "store-agent",
        },
    )
    assert resp.status_code == 400
    assert "publisher_signature" in resp.get_json()["message"]


def test_friendly_store_and_app_management_defaults_and_add(tmp_path: Path):
    client = _client(tmp_path)
    stores = client.get('/friendly-stores')
    assert stores.status_code == 200
    store_payload = stores.get_json()
    assert any(s['store_id'] == 'store-windows' for s in store_payload)
    assert any(s['store_id'] == 'store-apple' for s in store_payload)

    add_store = client.post('/friendly-stores', json={
        'actor': 'admin-1',
        'store_id': 'store-internal',
        'name': 'Internal Signed Store',
        'icon': '🏢',
        'platform': 'linux',
    })
    assert add_store.status_code == 201

    add_app = client.post('/friendly-apps', json={
        'actor': 'admin-1',
        'app_id': 'app-observability-agent',
        'name': 'Observability Agent',
        'icon': '📈',
        'store_id': 'store-internal',
        'publisher': 'Acme Security',
        'version': '4.3.1',
    })
    assert add_app.status_code == 201

    apps = client.get('/friendly-apps')
    assert apps.status_code == 200
    assert any(a['app_id'] == 'app-observability-agent' for a in apps.get_json())
