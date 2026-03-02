from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding

_ALLOWED_HARDWARE_KEY_TYPES = {"yubikey", "tpm"}


@dataclass
class SignatureVerificationResult:
    allowed: bool
    message: str


class HardwareKeyVerifier:
    """Verify containment authorization signatures from hardware-backed keys.

    Trusted key material is supplied as key_id -> PEM encoded public key.
    """

    def __init__(self, trusted_public_keys: dict[str, str] | None = None, fail_closed: bool = True):
        self._trusted_public_keys = trusted_public_keys or {}
        self._fail_closed = bool(fail_closed)

    @property
    def configured(self) -> bool:
        return bool(self._trusted_public_keys)

    @property
    def enabled(self) -> bool:
        return self._fail_closed or self.configured

    @staticmethod
    def canonical_payload(
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        key_id: str,
        key_type: str,
        authorize_all_containment: bool = False,
    ) -> bytes:
        payload = {"key_id": str(key_id), "key_type": str(key_type).strip().lower(), "scope": "containment_execute"}
        if not authorize_all_containment:
            payload.update({
                "approvals": sorted(str(a).strip().lower() for a in approvals),
                "host": str(host),
                "requested_actions": sorted(str(a) for a in requested_actions),
                "severity": int(severity),
            })
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).digest()

    def verify(
        self,
        *,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        signature_bundle: dict[str, Any] | None,
    ) -> SignatureVerificationResult:
        if not signature_bundle:
            if not self._trusted_public_keys:
                return SignatureVerificationResult(False, "containment blocked: no trusted hardware keys configured")
            return SignatureVerificationResult(False, "containment signature required")

        key_id = str(signature_bundle.get("key_id", "")).strip()
        key_type = str(signature_bundle.get("key_type", "")).strip().lower()
        signature_b64 = str(signature_bundle.get("signature", "")).strip()

        if not key_id or not signature_b64:
            return SignatureVerificationResult(False, "missing hardware key metadata")
        if key_type not in _ALLOWED_HARDWARE_KEY_TYPES:
            return SignatureVerificationResult(False, "unsupported hardware key type")

        pem = self._trusted_public_keys.get(key_id)
        if not pem:
            return SignatureVerificationResult(False, "untrusted hardware key id")

        authorize_all_containment = bool(signature_bundle.get("authorize_all_containment", False))
        digest = self.canonical_payload(
            host,
            severity,
            requested_actions,
            approvals,
            key_id,
            key_type,
            authorize_all_containment=authorize_all_containment,
        )
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return SignatureVerificationResult(False, "invalid signature encoding")

        try:
            public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                public_key.verify(signature, digest)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, digest, ec.ECDSA(hashes.SHA256()))
            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
            else:
                return SignatureVerificationResult(False, "unsupported public key algorithm")
        except (InvalidSignature, ValueError, TypeError):
            return SignatureVerificationResult(False, "signature verification failed")

        return SignatureVerificationResult(True, "hardware signature verified")
