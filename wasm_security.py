"""Signed WASM module lifecycle for Phase 3."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

from nacl import exceptions as nacl_exceptions, signing

from signed_ledger import SignedLedger

ALLOWED_HOST_ABI = {"read_telemetry", "emit_event", "request_action"}


@dataclass
class WasmManifest:
    module_id: str
    version: str
    capabilities: List[str]
    required_abi: List[str]


class WasmSecurityError(RuntimeError):
    pass


class WasmModuleLoader:
    def __init__(self, trusted_verify_keys: Sequence[signing.VerifyKey], allowed_capabilities: Sequence[str], ledger: SignedLedger) -> None:
        self.trusted_verify_keys = trusted_verify_keys
        self.allowed_capabilities = set(allowed_capabilities)
        self.ledger = ledger

    def load_signed_module(self, wasm_path: Path, manifest_path: Path, signature_path: Path) -> WasmManifest:
        manifest = self._read_manifest(manifest_path)
        module_bytes = wasm_path.read_bytes()
        signature = base64.b64decode(signature_path.read_text().strip())

        digest = hashlib.sha256(module_bytes).hexdigest()
        self._verify_signature(digest.encode("utf-8"), signature)
        self._validate_manifest(manifest)

        self.ledger.append(
            "wasm_module_load",
            {
                "module_id": manifest.module_id,
                "version": manifest.version,
                "capabilities": manifest.capabilities,
                "wasm_sha256": digest,
            },
        )
        return manifest

    def _read_manifest(self, manifest_path: Path) -> WasmManifest:
        payload = json.loads(manifest_path.read_text())
        return WasmManifest(
            module_id=payload["module_id"],
            version=payload["version"],
            capabilities=payload.get("capabilities", []),
            required_abi=payload.get("required_abi", []),
        )

    def _verify_signature(self, message: bytes, signature: bytes) -> None:
        for verifier in self.trusted_verify_keys:
            try:
                verifier.verify(message, signature)
                return
            except nacl_exceptions.BadSignatureError:
                continue
        raise WasmSecurityError("module signature validation failed")

    def _validate_manifest(self, manifest: WasmManifest) -> None:
        denied = [cap for cap in manifest.capabilities if cap not in self.allowed_capabilities]
        if denied:
            raise WasmSecurityError(f"unauthorized capabilities: {denied}")
        unknown_abi = [abi for abi in manifest.required_abi if abi not in ALLOWED_HOST_ABI]
        if unknown_abi:
            raise WasmSecurityError(f"unknown host ABI requested: {unknown_abi}")
        if "request_action" in manifest.required_abi and "containment_execute" not in manifest.capabilities:
            raise WasmSecurityError("request_action ABI requires containment_execute capability")
