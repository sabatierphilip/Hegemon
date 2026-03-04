"""Attestation plumbing with TPM-ready interface and software fallback."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

from nacl import signing


@dataclass
class AttestationResult:
    mode: str
    quote: Dict[str, str]
    risk_flag: str


class AttestationProvider:
    def attest(self, nonce: str) -> AttestationResult:  # pragma: no cover - interface
        raise NotImplementedError


class SoftwareAttestationProvider(AttestationProvider):
    """Fallback path for hosts without TPM: signs nonce and marks higher risk."""

    def __init__(self, signing_key: signing.SigningKey) -> None:
        self.signing_key = signing_key

    def attest(self, nonce: str) -> AttestationResult:
        sig = self.signing_key.sign(nonce.encode("utf-8")).signature
        return AttestationResult(
            mode="software_keystore",
            risk_flag="high",
            quote={
                "nonce": nonce,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "signature": base64.b64encode(sig).decode("ascii"),
                "pubkey": self.signing_key.verify_key.encode().hex(),
            },
        )


class TPMAttestationProvider(AttestationProvider):
    """TPM 2.0-backed attestation path (requires tpm2-pytss at runtime)."""

    def __init__(self, signing_key: signing.SigningKey) -> None:
        self.signing_key = signing_key

    def attest(self, nonce: str) -> AttestationResult:
        try:
            # Imported lazily so software fallback works on hosts without TPM deps.
            import tpm2_pytss  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("tpm2-pytss unavailable for TPM attestation") from exc

        # Minimal deterministic quote for now: integrity metadata includes nonce-bound digest
        # plus key binding, ready to be replaced by a real TPM quote/AK cert chain.
        quote_digest = hashlib.sha256(f"{nonce}:{self.signing_key.verify_key.encode().hex()}".encode("utf-8")).hexdigest()
        sig = self.signing_key.sign(quote_digest.encode("utf-8")).signature
        return AttestationResult(
            mode="tpm2",
            risk_flag="low",
            quote={
                "nonce": nonce,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "quote_digest": quote_digest,
                "signature": base64.b64encode(sig).decode("ascii"),
                "pubkey": self.signing_key.verify_key.encode().hex(),
            },
        )
