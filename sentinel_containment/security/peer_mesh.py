from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa


@dataclass
class PeerAttestationResult:
    ok: bool
    verified_pairs: int
    failures: list[dict[str, Any]]
    external_verification: list[dict[str, Any]]


@dataclass
class MeshCheckpoint:
    seq_no: int
    epoch: int
    nonce: str
    created_at: int
    prev_checkpoint_hash: str
    merkle_root: str
    entry_count: int
    signer_ids: list[str]
    signatures: dict[str, str]
    replication_targets: list[str]

    @property
    def checkpoint_hash(self) -> str:
        payload = {
            "seq_no": self.seq_no,
            "epoch": self.epoch,
            "nonce": self.nonce,
            "created_at": self.created_at,
            "prev_checkpoint_hash": self.prev_checkpoint_hash,
            "merkle_root": self.merkle_root,
            "entry_count": self.entry_count,
            "signer_ids": sorted(self.signer_ids),
            "replication_targets": sorted(self.replication_targets),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@dataclass
class CheckpointValidationResult:
    accepted: bool
    reasons: list[str]
    quorum_met: bool
    verified_signers: list[str]
    observed_notaries: int


class ExternalAttestationVerifier(ABC):
    provider_name: str

    @abstractmethod
    def verify(self, peer_id: str, evidence: dict[str, Any] | None) -> tuple[bool, str]:
        raise NotImplementedError


class TPMQuoteVerifier(ExternalAttestationVerifier):
    provider_name = "tpm_quote"

    def __init__(self, trusted_measurements: dict[str, str]):
        self._trusted_measurements = {str(k): str(v).strip().lower() for k, v in trusted_measurements.items()}

    def verify(self, peer_id: str, evidence: dict[str, Any] | None) -> tuple[bool, str]:
        trusted_measurement = self._trusted_measurements.get(peer_id)
        if not trusted_measurement:
            return False, "missing_trusted_tpm_reference"
        measurement = str((evidence or {}).get("measurement", "")).strip().lower()
        if not measurement:
            return False, "missing_tpm_measurement"
        if not hmac.compare_digest(measurement, trusted_measurement):
            return False, "tpm_measurement_mismatch"
        return True, "verified"


class CloudAttestationVerifier(ExternalAttestationVerifier):
    provider_name = "cloud_attestation"

    def __init__(self, trusted_issuers: list[str], required_nonce_prefix: str = "hegemon"):
        self._trusted_issuers = {str(i).strip().lower() for i in trusted_issuers if str(i).strip()}
        self._required_nonce_prefix = str(required_nonce_prefix).strip().lower()

    def verify(self, peer_id: str, evidence: dict[str, Any] | None) -> tuple[bool, str]:
        issuer = str((evidence or {}).get("issuer", "")).strip().lower()
        nonce = str((evidence or {}).get("nonce", "")).strip().lower()
        workload = str((evidence or {}).get("workload", "")).strip()
        if not issuer:
            return False, "missing_cloud_issuer"
        if issuer not in self._trusted_issuers:
            return False, "untrusted_cloud_issuer"
        if not nonce.startswith(self._required_nonce_prefix):
            return False, "invalid_cloud_nonce"
        if workload != peer_id:
            return False, "workload_mismatch"
        return True, "verified"


@dataclass
class FriendlyEnrollmentResult:
    accepted: bool
    message: str
    record: dict[str, Any] | None = None


class PeerVerificationMesh:
    """Dynamic HMAC-backed peer attestation mesh for runtime process integrity."""

    def __init__(
        self,
        process_keys: dict[str, str],
        max_clock_skew_seconds: int = 30,
        external_verifiers: list[ExternalAttestationVerifier] | None = None,
    ):
        self._process_keys = dict(process_keys)
        self._max_clock_skew_seconds = max(5, int(max_clock_skew_seconds))
        self._external_verifiers = list(external_verifiers or [])

    @property
    def process_ids(self) -> list[str]:
        return sorted(self._process_keys)

    def add_or_update_peer(self, peer_id: str, peer_key: str) -> None:
        self._process_keys[str(peer_id)] = str(peer_key)

    def remove_peer(self, peer_id: str) -> None:
        self._process_keys.pop(str(peer_id), None)

    def sign_peer_payload(self, peer_id: str, payload: dict[str, Any]) -> str:
        secret = self._process_keys.get(peer_id, "").encode("utf-8")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(secret, canonical, hashlib.sha256).hexdigest()

    def verify_peer_signature(self, peer_id: str, payload: dict[str, Any], signature: str) -> bool:
        expected = self.sign_peer_payload(peer_id, payload)
        return hmac.compare_digest(expected, str(signature).strip())

    def verify_external_peer(self, peer_id: str, evidence_bundle: dict[str, dict[str, Any]] | None) -> tuple[bool, list[dict[str, Any]]]:
        if not self._external_verifiers:
            return True, []
        failures = []
        for verifier in self._external_verifiers:
            evidence = (evidence_bundle or {}).get(verifier.provider_name)
            verified, reason = verifier.verify(peer_id, evidence)
            if not verified:
                failures.append({"peer_id": peer_id, "provider": verifier.provider_name, "reason": reason})
        return not failures, failures

    def run_attestation_cycle(
        self,
        now: float | None = None,
        observed_peer_keys: dict[str, str] | None = None,
        external_attestations: dict[str, dict[str, dict[str, Any]]] | None = None,
    ) -> PeerAttestationResult:
        ts = float(now if now is not None else time.time())
        peers = self.process_ids
        observed_keys = observed_peer_keys or {}
        failures: list[dict[str, Any]] = []
        external_verification: list[dict[str, Any]] = []
        verified_pairs = 0
        peer_external_evidence = external_attestations or {}
        for challenger in peers:
            for responder in peers:
                if challenger == responder:
                    continue
                challenge = {
                    "challenger": challenger,
                    "responder": responder,
                    "nonce": hashlib.sha256(f"{challenger}:{responder}:{ts}".encode("utf-8")).hexdigest()[:20],
                    "timestamp": int(ts),
                    "scope": "hegemon_p2p_attestation",
                }
                expected = self.sign_peer_payload(responder, challenge)
                observed_key = observed_keys.get(responder, self._process_keys[responder])
                observed_canonical = json.dumps(challenge, sort_keys=True, separators=(",", ":")).encode("utf-8")
                observed = hmac.new(str(observed_key).encode("utf-8"), observed_canonical, hashlib.sha256).hexdigest()
                verified_pairs += 1
                if not hmac.compare_digest(expected, observed):
                    failures.append({"challenger": challenger, "responder": responder, "reason": "signature_mismatch"})

                age = abs(time.time() - challenge["timestamp"])
                if age > self._max_clock_skew_seconds:
                    failures.append({"challenger": challenger, "responder": responder, "reason": "clock_skew_exceeded"})

        for responder in peers:
            evidence_for_peer = peer_external_evidence.get(responder, {})
            for verifier in self._external_verifiers:
                evidence = evidence_for_peer.get(verifier.provider_name)
                verified, reason = verifier.verify(responder, evidence)
                verdict = {
                    "responder": responder,
                    "provider": verifier.provider_name,
                    "verified": verified,
                    "reason": reason,
                }
                external_verification.append(verdict)
                if not verified:
                    failures.append(
                        {
                            "challenger": "external_verifier",
                            "responder": responder,
                            "reason": f"{verifier.provider_name}:{reason}",
                        }
                    )
        return PeerAttestationResult(
            ok=not failures,
            verified_pairs=verified_pairs,
            failures=failures,
            external_verification=external_verification,
        )


class MeshCheckpointLedger:
    """Quorum-signed, anti-replay P2P checkpoint ledger with gossip cross-notarization."""

    def __init__(
        self,
        mesh: PeerVerificationMesh,
        quorum_size: int,
        replication_targets: list[str] | None = None,
        max_nonce_age_seconds: int = 900,
        require_sequential: bool = True,
    ):
        self._mesh = mesh
        self._quorum_size = max(1, int(quorum_size))
        self._replication_targets = sorted({str(x).strip() for x in (replication_targets or []) if str(x).strip()})
        self._max_nonce_age_seconds = max(60, int(max_nonce_age_seconds))
        self._require_sequential = require_sequential
        self._last_seq_no = 0
        self._last_checkpoint_hash = "GENESIS"
        self._seen_nonces: dict[str, int] = {}
        self._seq_hash_index: dict[int, str] = {}
        self._notaries_by_hash: dict[str, set[str]] = {}
        self._revoked_peers: dict[str, dict[str, Any]] = {}
        self._epoch = 1

    @property
    def epoch(self) -> int:
        return self._epoch

    def revoke_peer(self, peer_id: str, reason: str, revoked_at: int | None = None) -> None:
        peer = str(peer_id).strip()
        if not peer:
            return
        self._revoked_peers[peer] = {"reason": str(reason), "revoked_at": int(revoked_at or time.time()), "epoch": self._epoch}

    def rotate_peer_key(self, peer_id: str, new_key: str, advance_epoch: bool = True) -> None:
        self._mesh.add_or_update_peer(str(peer_id).strip(), str(new_key).strip())
        if advance_epoch:
            self._epoch += 1

    @staticmethod
    def _hash_leaf(entry: Any) -> str:
        raw = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _merkle_root(self, entries: list[dict[str, Any]]) -> str:
        if not entries:
            return hashlib.sha256(b"empty").hexdigest()
        level = [self._hash_leaf(item) for item in entries]
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            next_level: list[str] = []
            for i in range(0, len(level), 2):
                next_level.append(hashlib.sha256(f"{level[i]}:{level[i+1]}".encode("utf-8")).hexdigest())
            level = next_level
        return level[0]

    def _checkpoint_payload(self, checkpoint: MeshCheckpoint) -> dict[str, Any]:
        return {
            "scope": "hegemon_p2p_checkpoint",
            "seq_no": checkpoint.seq_no,
            "epoch": checkpoint.epoch,
            "nonce": checkpoint.nonce,
            "created_at": checkpoint.created_at,
            "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
            "merkle_root": checkpoint.merkle_root,
            "entry_count": checkpoint.entry_count,
            "replication_targets": sorted(checkpoint.replication_targets),
        }

    def create_checkpoint(
        self,
        entries: list[dict[str, Any]],
        signer_ids: list[str],
        attestation_bundle: dict[str, dict[str, dict[str, Any]]] | None = None,
        replication_targets: list[str] | None = None,
        nonce: str | None = None,
    ) -> MeshCheckpoint:
        ts = int(time.time())
        seq_no = self._last_seq_no + 1
        checkpoint = MeshCheckpoint(
            seq_no=seq_no,
            epoch=self._epoch,
            nonce=str(nonce or hashlib.sha256(f"{seq_no}:{ts}:{len(entries)}".encode("utf-8")).hexdigest()[:24]),
            created_at=ts,
            prev_checkpoint_hash=self._last_checkpoint_hash,
            merkle_root=self._merkle_root(entries),
            entry_count=len(entries),
            signer_ids=sorted({str(s).strip() for s in signer_ids if str(s).strip()}),
            signatures={},
            replication_targets=sorted({str(x).strip() for x in (replication_targets or self._replication_targets) if str(x).strip()}),
        )
        payload = self._checkpoint_payload(checkpoint)
        for signer in checkpoint.signer_ids:
            if signer in self._revoked_peers:
                continue
            attested, _ = self._mesh.verify_external_peer(signer, (attestation_bundle or {}).get(signer))
            if not attested:
                continue
            checkpoint.signatures[signer] = self._mesh.sign_peer_payload(signer, payload)
        return checkpoint

    def validate_checkpoint(
        self,
        checkpoint: MeshCheckpoint,
        attestation_bundle: dict[str, dict[str, dict[str, Any]]] | None = None,
        observe_state: bool = True,
        source_peer: str | None = None,
    ) -> CheckpointValidationResult:
        reasons: list[str] = []
        verified_signers: list[str] = []

        if checkpoint.epoch != self._epoch:
            reasons.append("epoch_mismatch")

        expected_seq = self._last_seq_no + 1
        if self._require_sequential and checkpoint.seq_no != expected_seq:
            if checkpoint.seq_no > expected_seq:
                reasons.append("seq_gap_detected")
            else:
                reasons.append("seq_replay_or_regression")

        now_ts = int(time.time())
        if abs(now_ts - checkpoint.created_at) > self._max_nonce_age_seconds:
            reasons.append("checkpoint_stale")

        nonce_seen_ts = self._seen_nonces.get(checkpoint.nonce)
        if nonce_seen_ts is not None and checkpoint.seq_no <= self._last_seq_no:
            reasons.append("nonce_replay_detected")

        if checkpoint.prev_checkpoint_hash != self._last_checkpoint_hash and checkpoint.seq_no > 1:
            reasons.append("prev_hash_mismatch")

        payload = self._checkpoint_payload(checkpoint)
        for signer in checkpoint.signer_ids:
            if signer in self._revoked_peers:
                reasons.append(f"revoked_signer:{signer}")
                continue
            signature = checkpoint.signatures.get(signer)
            if not signature:
                continue
            if not self._mesh.verify_peer_signature(signer, payload, signature):
                reasons.append(f"invalid_signature:{signer}")
                continue
            attested, failures = self._mesh.verify_external_peer(signer, (attestation_bundle or {}).get(signer))
            if not attested:
                reasons.extend(f"attestation_failed:{f['provider']}:{signer}" for f in failures)
                continue
            verified_signers.append(signer)

        quorum_met = len(set(verified_signers)) >= self._quorum_size
        if not quorum_met:
            reasons.append("quorum_not_met")

        checkpoint_hash = checkpoint.checkpoint_hash
        notary_set = self._notaries_by_hash.setdefault(checkpoint_hash, set())
        for signer in verified_signers:
            notary_set.add(signer)
        if source_peer:
            notary_set.add(str(source_peer))

        prior_hash = self._seq_hash_index.get(checkpoint.seq_no)
        if prior_hash and prior_hash != checkpoint_hash:
            reasons.append("split_brain_checkpoint_detected")

        accepted = quorum_met and not reasons
        if observe_state and accepted:
            self._last_seq_no = checkpoint.seq_no
            self._last_checkpoint_hash = checkpoint_hash
            self._seq_hash_index[checkpoint.seq_no] = checkpoint_hash
            self._seen_nonces[checkpoint.nonce] = checkpoint.created_at
            cutoff = now_ts - self._max_nonce_age_seconds
            self._seen_nonces = {k: v for k, v in self._seen_nonces.items() if v >= cutoff}

        return CheckpointValidationResult(
            accepted=accepted,
            reasons=sorted(set(reasons)),
            quorum_met=quorum_met,
            verified_signers=sorted(set(verified_signers)),
            observed_notaries=len(notary_set),
        )

    def gossip_observe(self, checkpoint: MeshCheckpoint, source_peer: str) -> CheckpointValidationResult:
        return self.validate_checkpoint(checkpoint, observe_state=False, source_peer=source_peer)


class FriendlyPeerRegistry:
    """User-only cryptographically verified friendly software enrollment."""

    def __init__(self, enrollment_user: str, trusted_user_public_keys: dict[str, str] | None = None):
        self._enrollment_user = str(enrollment_user).strip().lower()
        self._trusted_user_public_keys = trusted_user_public_keys or {}
        self._friendlies: dict[str, dict[str, Any]] = {}

    @staticmethod
    def canonical_enrollment_payload(
        *,
        requested_by: str,
        software_id: str,
        peer_key: str,
        endpoints: list[str],
    ) -> bytes:
        payload = {
            "scope": "friendly_enrollment",
            "requested_by": str(requested_by).strip().lower(),
            "software_id": str(software_id).strip(),
            "peer_key": str(peer_key).strip(),
            "endpoints": sorted(str(x).strip() for x in endpoints),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).digest()

    def _verify_signature(self, bundle: dict[str, Any], digest: bytes) -> bool:
        key_id = str(bundle.get("key_id", "")).strip()
        signature_b64 = str(bundle.get("signature", "")).strip()
        pem = self._trusted_user_public_keys.get(key_id)
        if not key_id or not signature_b64 or not pem:
            return False
        try:
            signature = base64.b64decode(signature_b64)
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, digest)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
            else:
                return False
        except (ValueError, TypeError, InvalidSignature):
            return False
        return True

    def enroll(
        self,
        *,
        requested_by: str,
        software_id: str,
        peer_key: str,
        endpoints: list[str],
        signature_bundle: dict[str, Any] | None,
    ) -> FriendlyEnrollmentResult:
        normalized_user = str(requested_by).strip().lower()
        if normalized_user != self._enrollment_user:
            return FriendlyEnrollmentResult(False, "only configured user can enroll friendly software")
        if not signature_bundle:
            return FriendlyEnrollmentResult(False, "cryptographic signature required for friendly enrollment")

        digest = self.canonical_enrollment_payload(
            requested_by=requested_by,
            software_id=software_id,
            peer_key=peer_key,
            endpoints=endpoints,
        )
        if not self._verify_signature(signature_bundle, digest):
            return FriendlyEnrollmentResult(False, "friendly enrollment signature verification failed")

        record = {
            "software_id": software_id,
            "peer_key": peer_key,
            "endpoints": [str(e) for e in endpoints],
            "requested_by": normalized_user,
            "enrolled_at": int(time.time()),
            "guard_patrol": "enabled",
        }
        self._friendlies[software_id] = record
        return FriendlyEnrollmentResult(True, "friendly software enrolled and patrol scheduled", record)

    def patrol_targets(self) -> list[dict[str, Any]]:
        return [dict(v) for v in self._friendlies.values()]
