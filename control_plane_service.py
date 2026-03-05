"""Control-plane service with Phase 6-style order issuance and transparency log."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request
from nacl import encoding, signing

from hegemon_agent import build_order_digest, sign_payload, verify_signature
from sentinel_containment.controlplane import HegemonControlPlane

app = Flask(__name__)
TELEMETRY: List[Dict[str, Any]] = []
SETTINGS: Dict[str, Any] = {"autonomous_containment_enabled": True}
TRANSPARENCY_LOG: List[Dict[str, Any]] = []
CONTROL_SIGNERS: List[signing.SigningKey] = [signing.SigningKey.generate() for _ in range(3)]
CONTROL_PLANE = HegemonControlPlane()


@app.post("/telemetry")
def ingest_telemetry():
    body = request.get_json(force=True, silent=False)
    telemetry = body.get("telemetry")
    signature = body.get("signature")
    pubkey = body.get("pubkey")
    if not telemetry or not signature or not pubkey:
        return jsonify({"status": "error", "error": "missing telemetry/signature/pubkey"}), 400

    verify_key = signing.VerifyKey(pubkey.encode("utf-8"), encoder=encoding.Base64Encoder)
    if not verify_signature(telemetry, signature, verify_key):
        return jsonify({"status": "error", "error": "invalid telemetry signature"}), 403

    TELEMETRY.append(body)
    return jsonify({"status": "ok", "received": len(TELEMETRY)})


@app.get("/telemetry")
def list_telemetry():
    return jsonify(TELEMETRY)


@app.get("/dashboard/settings")
def get_settings():
    return jsonify(SETTINGS)


@app.post("/dashboard/settings")
def update_settings():
    body = request.get_json(force=True, silent=False)
    if "autonomous_containment_enabled" in body:
        SETTINGS["autonomous_containment_enabled"] = bool(body["autonomous_containment_enabled"])
    return jsonify(SETTINGS)


@app.post("/transparency/decisions")
def publish_decision():
    body = request.get_json(force=True, silent=False)
    TRANSPARENCY_LOG.append(body)
    return jsonify({"status": "logged", "size": len(TRANSPARENCY_LOG)})


@app.get("/transparency/decisions")
def list_decisions():
    return jsonify(TRANSPARENCY_LOG)


def generate_order(
    operator_signers: List[signing.SigningKey],
    human_hmac_key: str,
    required_quorum: int,
    target_host: str,
    pid: int,
    checkpoint: str = "genesis",
) -> Dict[str, Any]:
    order = {
        "actions": [{"type": "kill_process", "pid": pid}],
        "target_hosts": [target_host],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": secrets.token_hex(12),
        "policy_id": "containment-default",
        "checkpoint": checkpoint,
    }
    order["digest"] = build_order_digest(order)

    signatures = [sign_payload(order, signer) for signer in operator_signers]
    human_payload = {
        "operator_id": "operator-1",
        "nonce": "human-nonce-1",
        "order_digest": order["digest"],
    }
    human_token = hmac.new(
        human_hmac_key.encode("utf-8"),
        json.dumps(human_payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "order": order,
        "signatures": signatures,
        "required_quorum": required_quorum,
        "human_confirmation": {
            "operator_id": human_payload["operator_id"],
            "nonce": human_payload["nonce"],
            "hmac": human_token,
        },
    }




@app.post("/approvals/module")
def sign_module_manifest():
    manifest = request.get_json(force=True, silent=False)
    canonical = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = base64.b64encode(CONTROL_SIGNERS[0].sign(canonical).signature).decode("ascii")
    return jsonify({"control_signature": signature})


@app.post("/orders/containment")
def issue_order_endpoint():
    body = request.get_json(force=True, silent=False)
    target_host = body.get("target_host", "localhost")
    pid = int(body.get("pid", 12345))
    quorum = int(body.get("quorum", 2))
    checkpoint = body.get("checkpoint", "genesis")
    human_hmac_key = body.get("human_hmac_key", "dev-human-secret")
    order = generate_order(CONTROL_SIGNERS[:quorum], human_hmac_key, quorum, target_host, pid, checkpoint)
    return jsonify(order)


def export_public_keys(prefix: str = "control") -> None:
    for i, signer in enumerate(CONTROL_SIGNERS):
        Path(f"{prefix}_{i}.pub").write_bytes(signer.verify_key.encode(encoder=encoding.Base64Encoder))


@app.get("/friends")
def list_friends():
    return jsonify([CONTROL_PLANE.as_dict(v) for v in CONTROL_PLANE.friends.values()])


@app.post("/friends")
def add_friend():
    body = request.get_json(force=True, silent=False)
    actor = body.get("actor", "system")
    friend = CONTROL_PLANE.add_friend(body, actor)
    return jsonify(CONTROL_PLANE.as_dict(friend)), 201


@app.post("/friends/<friend_id>/disable")
def disable_friend(friend_id: str):
    body = request.get_json(force=True, silent=True) or {}
    actor = body.get("actor", "system")
    if friend_id not in CONTROL_PLANE.friends:
        return jsonify({"error": "not_found"}), 404
    friend = CONTROL_PLANE.disable_friend(friend_id, actor)
    return jsonify(CONTROL_PLANE.as_dict(friend))


@app.get("/endpoints")
def list_endpoints():
    return jsonify([CONTROL_PLANE.as_dict(v) for v in CONTROL_PLANE.endpoints.values()])


@app.post("/endpoints")
def add_endpoint():
    body = request.get_json(force=True, silent=False)
    actor = body.get("actor", "system")
    try:
        endpoint = CONTROL_PLANE.add_endpoint(body, actor)
    except (ValueError, KeyError) as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(CONTROL_PLANE.as_dict(endpoint)), 201


@app.post("/vulnerabilities")
def create_vulnerability():
    body = request.get_json(force=True, silent=False)
    actor = body.get("actor", "scanner")
    try:
        finding = CONTROL_PLANE.create_finding(body, actor)
    except (KeyError, ValueError) as exc:
        return jsonify({"error": "invalid_request", "message": str(exc)}), 400
    return jsonify(CONTROL_PLANE.as_dict(finding)), 201


@app.get("/vulnerabilities")
def list_vulnerabilities():
    return jsonify([CONTROL_PLANE.as_dict(v) for v in CONTROL_PLANE.findings.values()])


@app.post("/patch-proposals/generate")
def generate_patch_proposal_endpoint():
    body = request.get_json(force=True, silent=False)
    actor = body.get("actor", "mtre")
    finding_id = body.get("finding_id")
    if finding_id not in CONTROL_PLANE.findings:
        return jsonify({"error": "finding_not_found"}), 404
    proposal = CONTROL_PLANE.generate_patch_proposal(finding_id, actor)
    return jsonify(CONTROL_PLANE.as_dict(proposal)), 201


@app.get("/patch-proposals")
def list_patch_proposals():
    return jsonify([CONTROL_PLANE.as_dict(v) for v in CONTROL_PLANE.patch_proposals.values()])


@app.post("/patch-proposals/<proposal_id>/approve")
def approve_patch(proposal_id: str):
    body = request.get_json(force=True, silent=False)
    approver = body.get("approver", "operator-unknown")
    if proposal_id not in CONTROL_PLANE.patch_proposals:
        return jsonify({"error": "not_found"}), 404
    proposal = CONTROL_PLANE.approve_patch(proposal_id, approver)
    return jsonify(CONTROL_PLANE.as_dict(proposal))


@app.post("/patch-proposals/<proposal_id>/apply")
def apply_patch(proposal_id: str):
    body = request.get_json(force=True, silent=False)
    actor = body.get("actor", "operator")
    if proposal_id not in CONTROL_PLANE.patch_proposals:
        return jsonify({"error": "not_found"}), 404
    try:
        proposal = CONTROL_PLANE.apply_patch(proposal_id, actor)
    except ValueError as exc:
        return jsonify({"error": "precondition_failed", "message": str(exc)}), 400
    return jsonify(CONTROL_PLANE.as_dict(proposal))


@app.get("/entity-graph")
def entity_graph():
    return jsonify(CONTROL_PLANE.export_graph())


@app.get("/audit/ledger")
def audit_ledger():
    return jsonify({"health": CONTROL_PLANE.ledger_health(), "entries": CONTROL_PLANE.audit_log()})

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--emit-order", action="store_true")
    args = parser.parse_args()

    if args.emit_order:
        export_public_keys()
        order = generate_order(CONTROL_SIGNERS[:2], "dev-human-secret", 2, "localhost", 12345)
        Path("containment_order.json").write_text(json.dumps(order, indent=2))
        print("Wrote containment_order.json and control_*.pub keys")
        return 0

    ssl_context = (args.tls_cert, args.tls_key) if args.tls_cert and args.tls_key else None
    app.run(host="0.0.0.0", port=args.port, ssl_context=ssl_context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
