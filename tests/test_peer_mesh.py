import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sentinel_containment.security.peer_mesh import FriendlyPeerRegistry, PeerVerificationMesh


def test_peer_mesh_detects_tampered_peer_key():
    mesh = PeerVerificationMesh({"a": "ka", "b": "kb", "c": "kc"}, max_clock_skew_seconds=999999)

    now = time.time()
    healthy = mesh.run_attestation_cycle(now=now)
    assert healthy.ok is True
    assert healthy.verified_pairs == 6

    tampered = mesh.run_attestation_cycle(now=now, observed_peer_keys={"b": "evil-key"})
    assert tampered.ok is False
    assert any(f["responder"] == "b" and f["reason"] == "signature_mismatch" for f in tampered.failures)


def test_friendly_registry_requires_single_user_and_signature():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    registry = FriendlyPeerRegistry("user", {"user-key": public_pem})

    denied = registry.enroll(
        requested_by="intruder",
        software_id="friendly-sim",
        peer_key="mesh-k1",
        endpoints=["10.0.0.9:9443"],
        signature_bundle=None,
    )
    assert denied.accepted is False

    digest = FriendlyPeerRegistry.canonical_enrollment_payload(
        requested_by="user",
        software_id="friendly-sim",
        peer_key="mesh-k1",
        endpoints=["10.0.0.9:9443"],
    )
    signature = base64.b64encode(private_key.sign(digest)).decode("utf-8")
    allowed = registry.enroll(
        requested_by="user",
        software_id="friendly-sim",
        peer_key="mesh-k1",
        endpoints=["10.0.0.9:9443"],
        signature_bundle={"key_id": "user-key", "signature": signature},
    )
    assert allowed.accepted is True
    assert allowed.record is not None
    assert allowed.record["guard_patrol"] == "enabled"
    assert registry.patrol_targets()[0]["software_id"] == "friendly-sim"
