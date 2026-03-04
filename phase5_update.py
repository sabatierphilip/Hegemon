"""Phase 5 secure update workflow primitives."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Sequence

from nacl import exceptions as nacl_exceptions, signing

from signed_ledger import SignedLedger


class UpdateSecurityError(RuntimeError):
    pass


@dataclass
class UpdateManifest:
    version: str
    package_path: str
    sha256: str
    reproducible_fingerprint: str


class SecureUpdater:
    def __init__(self, trusted_verify_keys: Sequence[signing.VerifyKey], ledger: SignedLedger) -> None:
        self.trusted_verify_keys = trusted_verify_keys
        self.ledger = ledger

    def load_manifest(self, manifest_path: Path) -> Dict[str, str]:
        return json.loads(manifest_path.read_text())

    def verify_signed_manifest(self, manifest: Dict[str, str], signature_b64: str) -> None:
        payload = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        for vk in self.trusted_verify_keys:
            try:
                vk.verify(payload, signature)
                return
            except nacl_exceptions.BadSignatureError:
                continue
        raise UpdateSecurityError("manifest signature invalid")

    def verify_package(self, package_path: Path, expected_sha256: str) -> None:
        digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
        if digest != expected_sha256:
            raise UpdateSecurityError("package checksum mismatch")

    def verify_reproducible_fingerprint(self, package_path: Path, expected_fingerprint: str) -> None:
        # Baseline approach: deterministic fingerprint over package bytes.
        fingerprint = hashlib.sha256(("repro:" + hashlib.sha256(package_path.read_bytes()).hexdigest()).encode("utf-8")).hexdigest()
        if fingerprint != expected_fingerprint:
            raise UpdateSecurityError("reproducible fingerprint mismatch")

    def atomic_swap(self, package_path: Path, target_binary: Path, backup_path: Path) -> None:
        backup_path.write_bytes(target_binary.read_bytes())
        os.replace(package_path, target_binary)

    def apply_update(self, manifest: Dict[str, str], signature_b64: str, target_binary: Path, backup_path: Path) -> None:
        self.verify_signed_manifest(manifest, signature_b64)
        pkg = Path(manifest["package_path"])
        self.verify_package(pkg, manifest["sha256"])
        self.verify_reproducible_fingerprint(pkg, manifest["reproducible_fingerprint"])
        self.atomic_swap(pkg, target_binary, backup_path)
        self.ledger.append("update_applied", {"version": manifest["version"], "target": str(target_binary)})
