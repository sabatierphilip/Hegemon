"""Hegemon Agent (Phase 6 baseline with deep Phase 4/5/6 execution).

Includes:
- Phase 4 kernel-adjacent telemetry manager (safe vectors, signed admission)
- Phase 5 secure update verifier/scaffold
- Phase 6 quorum + causality verification and transparency publication
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import signal
import socket
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import psutil
import requests
from nacl import encoding, exceptions as nacl_exceptions, signing

from attestation import SoftwareAttestationProvider
from kernel_telemetry import KernelTelemetryConfig, KernelTelemetryManager
from phase5_update import SecureUpdater
from phase6_controlplane import Phase6OrderVerifier, TransparencyPublisher
from phase7_containment import ContainmentPolicyEngine, ContainmentPolicyError
from phase9_capabilities import CapabilityRegistry, Phase9CapabilityManager, CapabilityLifecycleError
from secure_key_store import SecureKeyStore, storage_backend_name
from signed_ledger import SignedLedger
from wasm_security import WasmModuleLoader

LOGGER = logging.getLogger("hegemon_agent")


class SecurityError(RuntimeError):
    """Raised when a security control fails."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_order_digest(order_doc: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(order_doc)).hexdigest()


class KeyManager:
    """Handles Ed25519 key creation and loading backed by secure keystore."""

    def __init__(self, private_key_path: Path, public_key_path: Path, keystore: SecureKeyStore) -> None:
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.keystore = keystore

    def generate_if_missing(self) -> None:
        if self.private_key_path.exists() and self.public_key_path.exists():
            return
        signing_key = signing.SigningKey.generate()
        verify_key = signing_key.verify_key
        encoded_priv = signing_key.encode(encoder=encoding.Base64Encoder)
        self.private_key_path.write_bytes(encoded_priv)
        os.chmod(self.private_key_path, 0o600)
        self.public_key_path.write_bytes(verify_key.encode(encoder=encoding.Base64Encoder))
        self.keystore.store_secret("agent_ed25519_private", encoded_priv)
        LOGGER.info("Generated keypair (backend=%s)", storage_backend_name())

    def load_signing_key(self) -> signing.SigningKey:
        try:
            return signing.SigningKey(self.keystore.load_secret("agent_ed25519_private"), encoder=encoding.Base64Encoder)
        except Exception:  # noqa: BLE001
            return signing.SigningKey(self.private_key_path.read_bytes(), encoder=encoding.Base64Encoder)


def sign_payload(payload: Dict[str, Any], signer: signing.SigningKey) -> str:
    return base64.b64encode(signer.sign(canonical_json(payload)).signature).decode("ascii")


def verify_signature(payload: Dict[str, Any], signature_b64: str, verifier: signing.VerifyKey) -> bool:
    try:
        verifier.verify(canonical_json(payload), base64.b64decode(signature_b64))
        return True
    except (nacl_exceptions.BadSignatureError, ValueError):
        return False


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def process_snapshot(max_processes: int = 512) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "ppid", "cmdline"]):
        if len(rows) >= max_processes:
            break
        info = proc.info
        rows.append({"pid": info.get("pid"), "ppid": info.get("ppid"), "cmdline": " ".join(info.get("cmdline") or [])})
    return rows


def tcp_connections(max_connections: int = 512) -> List[Dict[str, Any]]:
    conns: List[Dict[str, Any]] = []
    for conn in psutil.net_connections(kind="tcp"):
        if len(conns) >= max_connections:
            break
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
        conns.append({"pid": conn.pid, "status": conn.status, "local": local, "remote": remote})
    return conns


class Plugin:
    name = "base"

    def process(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        return telemetry


@dataclass
class AgentConfig:
    control_plane_url: str
    poll_interval_seconds: int = 15
    monitored_binaries: Sequence[Path] = ()
    host_id: str = socket.gethostname()
    tls_verify: bool = True
    request_timeout_seconds: int = 10
    dashboard_settings_url: Optional[str] = None
    autonomous_containment_enabled: bool = True
    kernel_telemetry_enabled: bool = True
    ebpf_program_path: Optional[Path] = None
    ebpf_signature_path: Optional[Path] = None
    transparency_url: Optional[str] = None
    capability_registry_path: Path = Path(".agent/capability_registry.json")


class HegemonAgent:
    def __init__(
        self,
        config: AgentConfig,
        signing_key: signing.SigningKey,
        control_plane_verify_keys: Sequence[signing.VerifyKey],
        human_hmac_key: Optional[str] = None,
        plugins: Optional[List[Plugin]] = None,
        ledger: Optional[SignedLedger] = None,
    ) -> None:
        self.config = config
        self.signing_key = signing_key
        self.control_plane_verify_keys = control_plane_verify_keys
        self.human_hmac_key = human_hmac_key or ""
        self.plugins = plugins or []
        self._stop = threading.Event()
        self.last_checkpoint = "genesis"
        self.ledger = ledger or SignedLedger(Path(".agent/ledger.log"), signing_key)
        self.attestation = SoftwareAttestationProvider(signing_key)
        self.wasm_loader = WasmModuleLoader(control_plane_verify_keys, ["process_inspect", "network_inspect", "containment_execute"], self.ledger)
        self.kernel_manager = KernelTelemetryManager(
            KernelTelemetryConfig(
                enabled=config.kernel_telemetry_enabled,
                ebpf_program_path=config.ebpf_program_path,
                ebpf_signature_path=config.ebpf_signature_path,
            ),
            control_plane_verify_keys,
        )
        self.phase6_verifier = Phase6OrderVerifier(control_plane_verify_keys, self.human_hmac_key, self.ledger, quorum_threshold=1)
        self.transparency_publisher = TransparencyPublisher(config.transparency_url) if config.transparency_url else None
        self.updater = SecureUpdater(control_plane_verify_keys, self.ledger)
        self.containment_policy = ContainmentPolicyEngine()
        self.capability_registry = CapabilityRegistry(config.capability_registry_path)
        self.capability_manager = Phase9CapabilityManager(
            loader=self.wasm_loader,
            registry=self.capability_registry,
            ledger=self.ledger,
            control_verify_keys=control_plane_verify_keys,
            human_hmac_key=self.human_hmac_key,
        )
        self.ledger.append("kernel_telemetry_init", self.kernel_manager.initialize())

    def refresh_dashboard_settings(self) -> None:
        if not self.config.dashboard_settings_url:
            return
        try:
            res = requests.get(self.config.dashboard_settings_url, timeout=5, verify=self.config.tls_verify)
            res.raise_for_status()
            settings = res.json()
            enabled = bool(settings.get("autonomous_containment_enabled", True))
            self.config.autonomous_containment_enabled = enabled
            self.ledger.append("dashboard_settings_refresh", {"autonomous_containment_enabled": enabled})
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("Failed to refresh dashboard settings: %s", exc)

    def collect_telemetry(self) -> Dict[str, Any]:
        att = self.attestation.attest(nonce=self.last_checkpoint)
        payload: Dict[str, Any] = {
            "schema_version": "0.6",
            "host_id": self.config.host_id,
            "timestamp": utc_now().isoformat(),
            "checkpoint": self.last_checkpoint,
            "processes": process_snapshot(),
            "tcp_connections": tcp_connections(),
            "binary_hashes": {str(binary): sha256_file(binary) for binary in self.config.monitored_binaries},
            "autonomous_containment_enabled": self.config.autonomous_containment_enabled,
            "attestation": {"mode": att.mode, "risk_flag": att.risk_flag, "quote": att.quote},
            "kernel_telemetry": self.kernel_manager.snapshot(),
            "capability_registry": {"modules": len(self.capability_registry.load().get("modules", {}))},
        }
        for plugin in self.plugins:
            payload = plugin.process(payload)
        return payload

    def signed_envelope(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "telemetry": telemetry,
            "signature": sign_payload(telemetry, self.signing_key),
            "pubkey": self.signing_key.verify_key.encode(encoder=encoding.Base64Encoder).decode("ascii"),
        }

    def post_telemetry(self, telemetry: Dict[str, Any]) -> requests.Response:
        return requests.post(
            self.config.control_plane_url,
            json=self.signed_envelope(telemetry),
            timeout=self.config.request_timeout_seconds,
            verify=self.config.tls_verify,
        )

    def run_forever(self) -> None:
        LOGGER.info("Hegemon Agent starting for host=%s autonomous=%s", self.config.host_id, self.config.autonomous_containment_enabled)
        while not self._stop.is_set():
            self.refresh_dashboard_settings()
            try:
                telemetry = self.collect_telemetry()
                response = self.post_telemetry(telemetry)
                response.raise_for_status()
                self.ledger.append("telemetry_posted", {"status_code": response.status_code})
            except Exception as exc:  # noqa: BLE001
                self.ledger.append("telemetry_failure", {"error": str(exc)})
                LOGGER.exception("Telemetry loop failure: %s", exc)
            self._stop.wait(self.config.poll_interval_seconds)
        LOGGER.info("Hegemon Agent stopped")

    def stop(self) -> None:
        self._stop.set()

    def _validate_required_order_fields(self, order: Dict[str, Any]) -> Dict[str, Any]:
        if "order" not in order:
            raise SecurityError("missing order body")
        core = order["order"]
        for required in ("actions", "target_hosts", "timestamp", "nonce", "policy_id", "checkpoint", "digest"):
            if required not in core:
                raise SecurityError(f"missing required order field: {required}")
        if not isinstance(core["actions"], list) or not core["actions"]:
            raise SecurityError("order has no actions")
        if self.config.host_id not in core["target_hosts"] and "*" not in core["target_hosts"]:
            raise SecurityError("order does not target this host")
        return core

    def _validate_order_digest(self, core_payload: Dict[str, Any]) -> None:
        provided = core_payload.get("digest")
        unsigned = dict(core_payload)
        unsigned.pop("digest", None)
        expected = build_order_digest(unsigned)
        if provided != expected:
            raise SecurityError("order digest mismatch")

    def _validate_chain(self, order: Dict[str, Any], core_payload: Dict[str, Any]) -> None:
        signatures = order.get("signatures", [])
        required = int(order.get("required_quorum", 1))
        if required <= 0:
            raise SecurityError("invalid required quorum")
        matched_signers = set()
        for signature_b64 in signatures:
            for idx, verifier in enumerate(self.control_plane_verify_keys):
                if idx in matched_signers:
                    continue
                if verify_signature(core_payload, signature_b64, verifier):
                    matched_signers.add(idx)
                    break
        if len(matched_signers) < required:
            raise SecurityError(f"quorum validation failed: {len(matched_signers)}/{required}")

    def _validate_human_confirmation(self, order: Dict[str, Any], core_payload: Dict[str, Any]) -> None:
        if not self.human_hmac_key:
            raise SecurityError("human approval key not configured")
        human = order.get("human_confirmation", {})
        expected_payload = {
            "operator_id": human.get("operator_id"),
            "nonce": human.get("nonce"),
            "order_digest": core_payload.get("digest"),
        }
        expected = hmac.new(self.human_hmac_key.encode("utf-8"), canonical_json(expected_payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(human.get("hmac", ""))):
            raise SecurityError("human confirmation HMAC is invalid")

    def _validate_freshness(self, core_payload: Dict[str, Any], skew_seconds: int = 120) -> None:
        issued = datetime.fromisoformat(core_payload["timestamp"])
        if abs((utc_now() - issued).total_seconds()) > skew_seconds:
            raise SecurityError("order timestamp outside clock skew bounds")

    def verify_containment_order(self, order: Dict[str, Any]) -> None:
        core_payload = self._validate_required_order_fields(order)
        self._validate_order_digest(core_payload)
        self._validate_chain(order, core_payload)
        self._validate_human_confirmation(order, core_payload)
        self._validate_freshness(core_payload)
        provided_quorum = int(order.get("required_quorum", 1))
        human_present = bool(order.get("human_confirmation", {}).get("hmac"))
        for action in core_payload.get("actions", []):
            action_type = action.get("type", "")
            try:
                self.containment_policy.validate_action_requirements(action_type, provided_quorum, human_present)
            except ContainmentPolicyError as exc:
                raise SecurityError(str(exc)) from exc
        # Phase 6 deeper checks (quorum causality + ledger continuity)
        self.phase6_verifier.quorum_threshold = int(order.get("required_quorum", 1))
        self.phase6_verifier.verify(order)
        self.ledger.append("containment_order_verified", {"digest": core_payload["digest"]})

    def _publish_transparency_decision(self, decision: Dict[str, Any]) -> None:
        if not self.transparency_publisher:
            return
        signed = {"decision": decision, "signature": sign_payload(decision, self.signing_key)}
        try:
            self.transparency_publisher.publish(signed)
            self.ledger.append("transparency_published", {"decision_digest": decision.get("order_digest")})
        except Exception as exc:  # noqa: BLE001
            self.ledger.append("transparency_publish_failed", {"error": str(exc)})

    def execute_containment_order(self, order: Dict[str, Any], human_approved: Optional[bool] = None) -> Dict[str, Any]:
        self.verify_containment_order(order)
        gate = self.config.autonomous_containment_enabled or bool(human_approved)
        if not gate:
            raise SecurityError("human approval gate not satisfied (autonomous mode disabled)")

        pre_snapshot = {"process_count": len(process_snapshot()), "tcp_connection_count": len(tcp_connections())}
        self.ledger.append("containment_pre_snapshot", pre_snapshot)

        results: List[Dict[str, Any]] = []
        for action in order["order"].get("actions", []):
            if action.get("type") == "kill_process":
                target_pid = int(action["pid"])
                try:
                    os.kill(target_pid, signal.SIGTERM)
                    results.append({"action": action, "status": "sent_sigterm"})
                except ProcessLookupError:
                    results.append({"action": action, "status": "pid_not_found"})
                except PermissionError as exc:
                    results.append({"action": action, "status": f"permission_denied:{exc}"})
            else:
                results.append({"action": action, "status": "unsupported"})

        post_snapshot = {"process_count": len(process_snapshot()), "tcp_connection_count": len(tcp_connections())}
        self.last_checkpoint = order["order"].get("digest", self.last_checkpoint)
        self.ledger.append("containment_post_snapshot", {"results": results, "post": post_snapshot, "checkpoint": self.last_checkpoint})

        decision = {
            "order_digest": order["order"].get("digest"),
            "host_id": self.config.host_id,
            "timestamp": utc_now().isoformat(),
            "results": results,
            "checkpoint": self.last_checkpoint,
        }
        self._publish_transparency_decision(decision)
        return {"result": results, "new_checkpoint": self.last_checkpoint}

    def install_capability_module(
        self,
        wasm_path: Path,
        manifest_path: Path,
        module_signature_path: Path,
        control_signature_b64: str,
        operator_id: str,
        nonce: str,
        human_hmac_hex: str,
    ) -> Dict[str, Any]:
        manifest = self.capability_manager.install_signed_module(
            wasm_path=wasm_path,
            manifest_path=manifest_path,
            module_signature_path=module_signature_path,
            control_signature_b64=control_signature_b64,
            operator_id=operator_id,
            nonce=nonce,
            human_hmac_hex=human_hmac_hex,
        )
        return {"module_id": manifest.module_id, "version": manifest.version, "capabilities": manifest.capabilities}

    def revoke_capability_module(self, module_id: str) -> Dict[str, Any]:
        self.capability_manager.revoke_module(module_id)
        broadcast = self.capability_manager.broadcast_revocation(module_id)
        return {"module_id": module_id, "revoked": True, "broadcast": broadcast}



def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def run_cli() -> int:
    parser = argparse.ArgumentParser(description="Hegemon Agent Phase 9 baseline (strengthened phases 1-7)")
    parser.add_argument("--control-plane-url", default="https://localhost:9443/telemetry")
    parser.add_argument("--dashboard-settings-url", default=None)
    parser.add_argument("--transparency-url", default=None)
    parser.add_argument("--agent-key", default=".keys/agent_private.key")
    parser.add_argument("--agent-pub", default=".keys/agent_public.key")
    parser.add_argument("--keystore-path", default=".keys/secure_store.json")
    parser.add_argument("--control-pub", action="append", default=[])
    parser.add_argument("--human-hmac-key", default="dev-human-secret")
    parser.add_argument("--interval", type=int, default=15)
    parser.add_argument("--monitor-bin", action="append", default=[sys.executable])
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--insecure-no-tls-verify", action="store_true", help="Dev only: disable TLS certificate verification")
    parser.add_argument("--disable-autonomous-containment", action="store_true", help="Disable autonomous containment unless explicit --approve is provided")
    parser.add_argument("--ledger-path", default=".agent/ledger.log")
    parser.add_argument("--disable-kernel-telemetry", action="store_true", help="Disable kernel-adjacent telemetry")
    parser.add_argument("--ebpf-program", default=None, help="Path to signed eBPF source file")
    parser.add_argument("--ebpf-signature", default=None, help="Path to base64 signature for eBPF program digest")
    parser.add_argument("--capability-registry-path", default=".agent/capability_registry.json")

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run")
    contain = sub.add_parser("contain")
    contain.add_argument("--order", required=True, help="Path to signed order JSON")
    contain.add_argument("--approve", action="store_true", help="Explicit human approval gate when autonomous mode is disabled")

    module_install = sub.add_parser("module-install")
    module_install.add_argument("--wasm", required=True)
    module_install.add_argument("--manifest", required=True)
    module_install.add_argument("--module-signature", required=True)
    module_install.add_argument("--control-signature", required=True)
    module_install.add_argument("--operator-id", required=True)
    module_install.add_argument("--nonce", required=True)
    module_install.add_argument("--human-hmac", required=True)

    module_revoke = sub.add_parser("module-revoke")
    module_revoke.add_argument("--module-id", required=True)

    args = parser.parse_args()
    setup_logging(args.log_level)

    if args.insecure_no_tls_verify:
        LOGGER.warning("TLS verification disabled; unsafe outside development")

    keystore = SecureKeyStore(Path(args.keystore_path))
    key_manager = KeyManager(Path(args.agent_key), Path(args.agent_pub), keystore)
    key_manager.private_key_path.parent.mkdir(parents=True, exist_ok=True)
    key_manager.generate_if_missing()

    control_keys = [signing.VerifyKey(Path(path).read_bytes(), encoder=encoding.Base64Encoder) for path in args.control_pub]
    agent_signing_key = key_manager.load_signing_key()
    ledger = SignedLedger(Path(args.ledger_path), agent_signing_key)

    agent = HegemonAgent(
        config=AgentConfig(
            control_plane_url=args.control_plane_url,
            poll_interval_seconds=args.interval,
            monitored_binaries=[Path(p) for p in args.monitor_bin],
            tls_verify=not args.insecure_no_tls_verify,
            dashboard_settings_url=args.dashboard_settings_url,
            autonomous_containment_enabled=not args.disable_autonomous_containment,
            kernel_telemetry_enabled=not args.disable_kernel_telemetry,
            ebpf_program_path=Path(args.ebpf_program) if args.ebpf_program else None,
            ebpf_signature_path=Path(args.ebpf_signature) if args.ebpf_signature else None,
            transparency_url=args.transparency_url,
            capability_registry_path=Path(args.capability_registry_path),
        ),
        signing_key=agent_signing_key,
        control_plane_verify_keys=control_keys,
        human_hmac_key=args.human_hmac_key,
        ledger=ledger,
    )

    if args.command == "contain":
        order = json.loads(Path(args.order).read_text())
        result = agent.execute_containment_order(order, human_approved=args.approve)
        print(json.dumps(result, indent=2))
        return 0

    if args.command == "module-install":
        try:
            out = agent.install_capability_module(
                wasm_path=Path(args.wasm),
                manifest_path=Path(args.manifest),
                module_signature_path=Path(args.module_signature),
                control_signature_b64=args.control_signature,
                operator_id=args.operator_id,
                nonce=args.nonce,
                human_hmac_hex=args.human_hmac,
            )
        except CapabilityLifecycleError as exc:
            raise SystemExit(str(exc))
        print(json.dumps(out, indent=2))
        return 0

    if args.command == "module-revoke":
        out = agent.revoke_capability_module(args.module_id)
        print(json.dumps(out, indent=2))
        return 0

    if args.command in (None, "run"):
        agent.run_forever()
        return 0

    parser.error("invalid command")
    return 2


if __name__ == "__main__":
    raise SystemExit(run_cli())
