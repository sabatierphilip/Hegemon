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


class ExternalAttestationVerifier(ABC):
    """Provider contract for out-of-band node attestation verification."""

    provider_name: str

    @abstractmethod
    def verify(self, peer_id: str, evidence: dict[str, Any] | None) -> tuple[bool, str]:
        raise NotImplementedError


class TPMQuoteVerifier(ExternalAttestationVerifier):
    """Validates TPM quote-like measurements against expected digests."""

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
    """Validates cloud-native attestation claims from trusted issuers."""

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

    def _sign(self, peer_id: str, payload: dict[str, Any]) -> str:
        secret = self._process_keys.get(peer_id, "").encode("utf-8")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(secret, canonical, hashlib.sha256).hexdigest()

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
                expected = self._sign(responder, challenge)
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
