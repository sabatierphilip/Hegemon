"""Attestation plumbing with TPM-ready interface and software fallback."""
from __future__ import annotations

import base64
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
