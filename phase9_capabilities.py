"""Phase 9 adaptive runtime capability lifecycle for signed WASM modules."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence

from nacl import exceptions as nacl_exceptions, signing

from signed_ledger import SignedLedger
from wasm_security import WasmManifest, WasmModuleLoader, WasmSecurityError


class CapabilityLifecycleError(RuntimeError):
    pass


@dataclass
class ModuleRecord:
    module_id: str
    version: str
    capabilities: List[str]
    wasm_sha256: str
    build_fingerprint: str
    revoked: bool = False


class CapabilityRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"modules": {}}, indent=2))

    def load(self) -> Dict[str, Any]:
        return json.loads(self.path.read_text())

    def save(self, data: Dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True))

    def upsert_module(self, record: ModuleRecord) -> None:
        data = self.load()
        data.setdefault("modules", {})[record.module_id] = {
            "module_id": record.module_id,
            "version": record.version,
            "capabilities": record.capabilities,
            "wasm_sha256": record.wasm_sha256,
            "build_fingerprint": record.build_fingerprint,
            "revoked": record.revoked,
        }
        self.save(data)

    def revoke(self, module_id: str) -> None:
        data = self.load()
        modules = data.setdefault("modules", {})
        if module_id in modules:
            modules[module_id]["revoked"] = True
            self.save(data)

    def is_revoked(self, module_id: str) -> bool:
        data = self.load()
        return bool(data.get("modules", {}).get(module_id, {}).get("revoked", False))

    def module_record(self, module_id: str) -> Dict[str, Any]:
        return self.load().get("modules", {}).get(module_id, {})


class Phase9CapabilityManager:
    def __init__(
        self,
        loader: WasmModuleLoader,
        registry: CapabilityRegistry,
        ledger: SignedLedger,
        control_verify_keys: Sequence[signing.VerifyKey],
        human_hmac_key: str,
        peer_revocation_endpoints: Sequence[str] = (),
    ) -> None:
        self.loader = loader
        self.registry = registry
        self.ledger = ledger
        self.control_verify_keys = control_verify_keys
        self.human_hmac_key = human_hmac_key
        self.peer_revocation_endpoints = list(peer_revocation_endpoints)

    def _verify_control_approval(self, manifest: Dict[str, Any], control_signature_b64: str) -> None:
        sig = base64.b64decode(control_signature_b64)
        canonical = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
        for vk in self.control_verify_keys:
            try:
                vk.verify(canonical, sig)
                return
            except nacl_exceptions.BadSignatureError:
                continue
        raise CapabilityLifecycleError("control-plane approval signature invalid")

    def _verify_human_approval(self, manifest: Dict[str, Any], operator_id: str, nonce: str, human_hmac_hex: str) -> None:
        payload = {
            "operator_id": operator_id,
            "nonce": nonce,
            "manifest_digest": hashlib.sha256(
                json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest(),
        }
        expected = hmac.new(
            self.human_hmac_key.encode("utf-8"),
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, human_hmac_hex):
            raise CapabilityLifecycleError("human approval HMAC invalid")

    def install_signed_module(
        self,
        wasm_path: Path,
        manifest_path: Path,
        module_signature_path: Path,
        control_signature_b64: str,
        operator_id: str,
        nonce: str,
        human_hmac_hex: str,
    ) -> WasmManifest:
        manifest_payload = json.loads(manifest_path.read_text())
        self._verify_control_approval(manifest_payload, control_signature_b64)
        self._verify_human_approval(manifest_payload, operator_id, nonce, human_hmac_hex)

        try:
            manifest = self.loader.load_signed_module(wasm_path, manifest_path, module_signature_path)
        except WasmSecurityError as exc:
            raise CapabilityLifecycleError(str(exc)) from exc

        module_bytes = wasm_path.read_bytes()
        wasm_sha256 = hashlib.sha256(module_bytes).hexdigest()
        build_fingerprint = hashlib.sha256(("build:" + wasm_sha256).encode("utf-8")).hexdigest()

        record = ModuleRecord(
            module_id=manifest.module_id,
            version=manifest.version,
            capabilities=manifest.capabilities,
            wasm_sha256=wasm_sha256,
            build_fingerprint=build_fingerprint,
            revoked=False,
        )
        self.registry.upsert_module(record)
        self.ledger.append(
            "phase9_module_installed",
            {
                "module_id": record.module_id,
                "version": record.version,
                "capabilities": record.capabilities,
                "build_fingerprint": record.build_fingerprint,
            },
        )
        return manifest

    def request_capability(self, module_id: str, capability: str) -> bool:
        if self.registry.is_revoked(module_id):
            self.ledger.append("phase9_capability_denied", {"module_id": module_id, "capability": capability, "reason": "revoked"})
            return False
        rec = self.registry.module_record(module_id)
        allowed = capability in rec.get("capabilities", [])
        self.ledger.append(
            "phase9_capability_request",
            {"module_id": module_id, "capability": capability, "allowed": allowed},
        )
        return allowed

    def revoke_module(self, module_id: str) -> None:
        self.registry.revoke(module_id)
        self.ledger.append("phase9_module_revoked", {"module_id": module_id})

    def broadcast_revocation(self, module_id: str) -> List[Dict[str, Any]]:
        # Keep standard-library only here; agent can replace with requests-based broadcaster if desired.
        payload = {"module_id": module_id, "revoked": True}
        results = [{"endpoint": ep, "payload": payload, "status": "queued"} for ep in self.peer_revocation_endpoints]
        self.ledger.append("phase9_revocation_broadcast", {"module_id": module_id, "peers": self.peer_revocation_endpoints})
        return results
