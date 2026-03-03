import base64
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sentinel_containment.security.peer_mesh import (
    CloudAttestationVerifier,
    FriendlyPeerRegistry,
    MeshCheckpointLedger,
    PeerVerificationMesh,
    TPMQuoteVerifier,
)


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


def test_peer_mesh_requires_external_attestation_verifiers():
    mesh = PeerVerificationMesh(
        {"a": "ka", "b": "kb"},
        max_clock_skew_seconds=999999,
        external_verifiers=[
            TPMQuoteVerifier({"a": "pcr-a", "b": "pcr-b"}),
            CloudAttestationVerifier(["aws-nitro"], required_nonce_prefix="hegemon"),
        ],
    )

    healthy = mesh.run_attestation_cycle(
        external_attestations={
            "a": {
                "tpm_quote": {"measurement": "pcr-a"},
                "cloud_attestation": {"issuer": "aws-nitro", "nonce": "hegemon-1", "workload": "a"},
            },
            "b": {
                "tpm_quote": {"measurement": "pcr-b"},
                "cloud_attestation": {"issuer": "aws-nitro", "nonce": "hegemon-2", "workload": "b"},
            },
        }
    )
    assert healthy.ok is True
    assert healthy.external_verification

    tampered = mesh.run_attestation_cycle(
        external_attestations={
            "a": {
                "tpm_quote": {"measurement": "pcr-a"},
                "cloud_attestation": {"issuer": "aws-nitro", "nonce": "hegemon-1", "workload": "a"},
            },
            "b": {
                "tpm_quote": {"measurement": "forged"},
                "cloud_attestation": {"issuer": "rogue", "nonce": "xxx", "workload": "b"},
            },
        }
    )
    assert tampered.ok is False
    assert any("tpm_quote:tpm_measurement_mismatch" in f["reason"] for f in tampered.failures)
    assert any("cloud_attestation:untrusted_cloud_issuer" in f["reason"] for f in tampered.failures)


def test_checkpoint_ledger_requires_quorum_and_monotonic_seq_with_replay_protection():
    mesh = PeerVerificationMesh({"a": "ka", "b": "kb", "c": "kc"})
    ledger = MeshCheckpointLedger(mesh, quorum_size=2, replication_targets=["ra", "rb"])

    chk1 = ledger.create_checkpoint(entries=[{"k": 1}], signer_ids=["a", "b"])
    ok1 = ledger.validate_checkpoint(chk1)
    assert ok1.accepted is True
    assert ok1.quorum_met is True

    # Replay same checkpoint must fail for seq regression/nonce replay
    replay = ledger.validate_checkpoint(chk1)
    assert replay.accepted is False
    assert any(reason in replay.reasons for reason in ["seq_replay_or_regression", "nonce_replay_detected"])

    # Gap in seq must be rejected when sequential mode is on
    chk_gap = ledger.create_checkpoint(entries=[{"k": 2}], signer_ids=["a", "b"])
    chk_gap = chk_gap.__class__(
        seq_no=chk_gap.seq_no + 1,
        epoch=chk_gap.epoch,
        nonce=chk_gap.nonce,
        created_at=chk_gap.created_at,
        prev_checkpoint_hash=chk_gap.prev_checkpoint_hash,
        merkle_root=chk_gap.merkle_root,
        entry_count=chk_gap.entry_count,
        signer_ids=chk_gap.signer_ids,
        signatures=chk_gap.signatures,
        replication_targets=chk_gap.replication_targets,
    )
    res_gap = ledger.validate_checkpoint(chk_gap)
    assert res_gap.accepted is False
    assert "seq_gap_detected" in res_gap.reasons


def test_checkpoint_ledger_rejects_revoked_signer_and_detects_split_brain():
    mesh = PeerVerificationMesh({"a": "ka", "b": "kb", "c": "kc"})
    ledger = MeshCheckpointLedger(mesh, quorum_size=2)

    chk1 = ledger.create_checkpoint(entries=[{"x": 1}], signer_ids=["a", "b"])
    assert ledger.validate_checkpoint(chk1).accepted is True

    ledger.revoke_peer("b", "compromised")
    chk2 = ledger.create_checkpoint(entries=[{"x": 2}], signer_ids=["a", "b"])
    res2 = ledger.validate_checkpoint(chk2)
    assert res2.accepted is False
    assert any(reason.startswith("revoked_signer:b") for reason in res2.reasons)

    # Simulate split-brain gossip for same seq_no with different checkpoint hash
    chk3 = ledger.create_checkpoint(entries=[{"x": 3}], signer_ids=["a", "c"])
    assert ledger.validate_checkpoint(chk3).accepted is True
    alt = ledger.create_checkpoint(entries=[{"x": 999}], signer_ids=["a", "c"])
    alt = alt.__class__(
        seq_no=chk3.seq_no,
        epoch=chk3.epoch,
        nonce=alt.nonce,
        created_at=alt.created_at,
        prev_checkpoint_hash=chk3.prev_checkpoint_hash,
        merkle_root=alt.merkle_root,
        entry_count=alt.entry_count,
        signer_ids=alt.signer_ids,
        signatures=alt.signatures,
        replication_targets=alt.replication_targets,
    )
    gossip = ledger.gossip_observe(alt, source_peer="peer-z")
    assert "split_brain_checkpoint_detected" in gossip.reasons
