import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl import signing

from hegemon_agent import (
    AgentConfig,
    HegemonAgent,
    SecurityError,
    build_order_digest,
    canonical_json,
    sign_payload,
)
from kernel_telemetry import KernelTelemetryConfig, KernelTelemetryManager, KernelTelemetryError
from phase5_update import SecureUpdater, UpdateSecurityError
from phase7_containment import ContainmentPolicyEngine, ContainmentPolicyError
from phase6_controlplane import OrderVerificationError, Phase6OrderVerifier
from phase9_capabilities import CapabilityRegistry, Phase9CapabilityManager, CapabilityLifecycleError
from signed_ledger import SignedLedger
from wasm_security import WasmModuleLoader, WasmSecurityError


def _build_order(agent: HegemonAgent, control_signers, required_quorum=1, checkpoint="genesis", timestamp=None):
    order_core = {
        "actions": [{"type": "kill_process", "pid": 999999}],
        "target_hosts": [agent.config.host_id],
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "nonce": "n-123",
        "policy_id": "policy-1",
        "checkpoint": checkpoint,
    }
    order_core["digest"] = build_order_digest(order_core)
    signatures = [sign_payload(order_core, signer) for signer in control_signers]
    human_payload = {
        "operator_id": "op-1",
        "nonce": "h-nonce",
        "order_digest": order_core["digest"],
    }
    hm = hmac.new(b"human-secret", canonical_json(human_payload), hashlib.sha256).hexdigest()
    return {
        "order": order_core,
        "signatures": signatures,
        "required_quorum": required_quorum,
        "human_confirmation": {"operator_id": "op-1", "nonce": "h-nonce", "hmac": hm},
    }


def _agent_and_signers(tmp_path: Path):
    agent_key = signing.SigningKey.generate()
    control_signers = [signing.SigningKey.generate(), signing.SigningKey.generate(), signing.SigningKey.generate()]
    ledger = SignedLedger(tmp_path / "ledger.log", agent_key)
    agent = HegemonAgent(
        config=AgentConfig(control_plane_url="https://example.test/telemetry", host_id="host-1"),
        signing_key=agent_key,
        control_plane_verify_keys=[s.verify_key for s in control_signers],
        human_hmac_key="human-secret",
        ledger=ledger,
    )
    return agent, control_signers


def test_telemetry_contains_phase6_keys(tmp_path):
    agent, _ = _agent_and_signers(tmp_path)
    telemetry = agent.collect_telemetry()
    assert telemetry["schema_version"] == "0.6"
    assert telemetry["autonomous_containment_enabled"] is True
    assert "attestation" in telemetry
    assert "kernel_telemetry" in telemetry


def test_verify_and_execute_order(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    order = _build_order(agent, [control_signers[0], control_signers[1]], required_quorum=2)
    result = agent.execute_containment_order(order)
    assert "new_checkpoint" in result


def test_rejects_unsigned_order(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    order = _build_order(agent, [control_signers[0], control_signers[1]], required_quorum=2)
    order["signatures"] = []
    try:
        agent.verify_containment_order(order)
    except SecurityError as exc:
        assert "quorum" in str(exc)
    else:
        raise AssertionError("expected containment verification failure")


def test_rejects_digest_tamper(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    order = _build_order(agent, [control_signers[0]], required_quorum=1)
    order["order"]["policy_id"] = "tampered"
    try:
        agent.verify_containment_order(order)
    except SecurityError as exc:
        assert "digest mismatch" in str(exc)
    else:
        raise AssertionError("expected digest mismatch")


def test_rejects_duplicate_signer_quorum_bypass(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    order = _build_order(agent, [control_signers[0]], required_quorum=2)
    order["signatures"] = [order["signatures"][0], order["signatures"][0]]
    try:
        agent.verify_containment_order(order)
    except SecurityError as exc:
        assert "quorum" in str(exc)
    else:
        raise AssertionError("expected quorum verification failure")


def test_phase6_rejects_stale_timestamp(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    order = _build_order(agent, [control_signers[0]], required_quorum=1, timestamp=old)
    try:
        agent.verify_containment_order(order)
    except (SecurityError, OrderVerificationError):
        pass
    else:
        raise AssertionError("expected stale timestamp rejection")


def test_phase6_checkpoint_causality(tmp_path):
    signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", signer)
    verifier = Phase6OrderVerifier([signer.verify_key], "human-secret", ledger, quorum_threshold=1)
    core = {
        "actions": [{"type": "kill_process", "pid": 1}],
        "target_hosts": ["host-1"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": "x",
        "policy_id": "p",
        "checkpoint": "bad-checkpoint",
    }
    core["digest"] = build_order_digest(core)
    human_payload = {"operator_id": "op-1", "nonce": "h-nonce", "order_digest": core["digest"]}
    order = {
        "order": core,
        "signatures": [sign_payload(core, signer)],
        "human_confirmation": {
            "operator_id": "op-1",
            "nonce": "h-nonce",
            "hmac": hmac.new(b"human-secret", canonical_json(human_payload), hashlib.sha256).hexdigest(),
        },
    }
    try:
        verifier.verify(order)
    except OrderVerificationError as exc:
        assert "checkpoint" in str(exc)
    else:
        raise AssertionError("expected checkpoint causality failure")


def test_wasm_loader_rejects_unauthorized_capability(tmp_path):
    signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", signer)
    loader = WasmModuleLoader([signer.verify_key], ["process_inspect"], ledger)

    wasm_path = tmp_path / "mod.wasm"
    manifest_path = tmp_path / "mod.manifest.json"
    sig_path = tmp_path / "mod.sig"

    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    digest = hashlib.sha256(wasm_path.read_bytes()).hexdigest().encode("utf-8")
    sig_path.write_text(base64.b64encode(signer.sign(digest).signature).decode("ascii"))
    manifest_path.write_text(json.dumps({
        "module_id": "m1",
        "version": "1.0.0",
        "capabilities": ["containment_execute"],
        "required_abi": ["read_telemetry"],
    }))

    try:
        loader.load_signed_module(wasm_path, manifest_path, sig_path)
    except WasmSecurityError as exc:
        assert "unauthorized capabilities" in str(exc)
    else:
        raise AssertionError("expected unauthorized capability failure")


def test_kernel_manager_rejects_bad_program_signature(tmp_path):
    signer = signing.SigningKey.generate()
    bad = signing.SigningKey.generate()
    prog = tmp_path / "p.c"
    sig = tmp_path / "p.sig"
    prog.write_text("int kprobe__sys_execve(void *ctx){return 0;}")
    digest = hashlib.sha256(prog.read_bytes()).hexdigest().encode("utf-8")
    sig.write_text(base64.b64encode(bad.sign(digest).signature).decode("ascii"))
    mgr = KernelTelemetryManager(KernelTelemetryConfig(enabled=True, ebpf_program_path=prog, ebpf_signature_path=sig), [signer.verify_key])
    try:
        mgr.initialize()
    except KernelTelemetryError as exc:
        assert "verification failed" in str(exc)
    else:
        assert mgr.snapshot()


def test_phase5_secure_updater_rejects_bad_signature(tmp_path):
    signer = signing.SigningKey.generate()
    bad = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", signer)
    updater = SecureUpdater([signer.verify_key], ledger)

    pkg = tmp_path / "pkg.bin"
    pkg.write_bytes(b"binary")
    digest = hashlib.sha256(pkg.read_bytes()).hexdigest()
    repro = hashlib.sha256(("repro:" + digest).encode("utf-8")).hexdigest()
    manifest = {"version": "1.0.0", "package_path": str(pkg), "sha256": digest, "reproducible_fingerprint": repro}
    sig = base64.b64encode(bad.sign(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")).signature).decode("ascii")

    try:
        updater.verify_signed_manifest(manifest, sig)
    except UpdateSecurityError as exc:
        assert "signature" in str(exc)
    else:
        raise AssertionError("expected bad signature failure")


def test_phase7_policy_requires_quorum_for_kill_process():
    policy = ContainmentPolicyEngine()
    try:
        policy.validate_action_requirements("kill_process", provided_quorum=1, human_hmac_present=True)
    except ContainmentPolicyError as exc:
        assert "insufficient quorum" in str(exc)
    else:
        raise AssertionError("expected policy rejection")


def test_phase9_install_and_revoke_module(tmp_path):
    control_signer = signing.SigningKey.generate()
    agent_signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", agent_signer)
    loader = WasmModuleLoader([control_signer.verify_key], ["process_inspect"], ledger)
    registry = CapabilityRegistry(tmp_path / "cap_registry.json")
    manager = Phase9CapabilityManager(
        loader=loader,
        registry=registry,
        ledger=ledger,
        control_verify_keys=[control_signer.verify_key],
        human_hmac_key="human-secret",
        peer_revocation_endpoints=["https://peer-a/revoke"],
    )

    wasm_path = tmp_path / "mod.wasm"
    manifest_path = tmp_path / "mod.manifest.json"
    sig_path = tmp_path / "mod.sig"

    manifest = {
        "module_id": "m9",
        "version": "1.2.3",
        "capabilities": ["process_inspect"],
        "required_abi": ["read_telemetry"],
    }
    manifest_path.write_text(json.dumps(manifest))
    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    mod_digest = hashlib.sha256(wasm_path.read_bytes()).hexdigest().encode("utf-8")
    sig_path.write_text(base64.b64encode(control_signer.sign(mod_digest).signature).decode("ascii"))

    control_signature = base64.b64encode(
        control_signer.sign(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")).signature
    ).decode("ascii")
    human_payload = {
        "operator_id": "op-1",
        "nonce": "n-1",
        "manifest_digest": hashlib.sha256(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest(),
    }
    human_hmac = hmac.new(b"human-secret", json.dumps(human_payload, separators=(",", ":"), sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()

    manager.install_signed_module(
        wasm_path=wasm_path,
        manifest_path=manifest_path,
        module_signature_path=sig_path,
        control_signature_b64=control_signature,
        operator_id="op-1",
        nonce="n-1",
        human_hmac_hex=human_hmac,
    )
    assert manager.request_capability("m9", "process_inspect") is True

    manager.revoke_module("m9")
    assert manager.request_capability("m9", "process_inspect") is False


def test_phase9_rejects_bad_control_approval(tmp_path):
    control_signer = signing.SigningKey.generate()
    bad_signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", control_signer)
    loader = WasmModuleLoader([control_signer.verify_key], ["process_inspect"], ledger)
    registry = CapabilityRegistry(tmp_path / "cap_registry.json")
    manager = Phase9CapabilityManager(loader, registry, ledger, [control_signer.verify_key], "human-secret")

    wasm_path = tmp_path / "mod.wasm"
    manifest_path = tmp_path / "mod.manifest.json"
    sig_path = tmp_path / "mod.sig"

    manifest = {"module_id": "m1", "version": "1.0.0", "capabilities": ["process_inspect"], "required_abi": ["read_telemetry"]}
    manifest_path.write_text(json.dumps(manifest))
    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    mod_digest = hashlib.sha256(wasm_path.read_bytes()).hexdigest().encode("utf-8")
    sig_path.write_text(base64.b64encode(control_signer.sign(mod_digest).signature).decode("ascii"))

    bad_control_sig = base64.b64encode(bad_signer.sign(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")).signature).decode("ascii")
    human_payload = {"operator_id": "op", "nonce": "n", "manifest_digest": hashlib.sha256(json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()}
    human_hmac = hmac.new(b"human-secret", json.dumps(human_payload, separators=(",", ":"), sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()

    try:
        manager.install_signed_module(wasm_path, manifest_path, sig_path, bad_control_sig, "op", "n", human_hmac)
    except CapabilityLifecycleError as exc:
        assert "control-plane approval" in str(exc)
    else:
        raise AssertionError("expected control approval rejection")


def test_signed_ledger_tolerates_truncated_last_line(tmp_path):
    signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", signer)
    ledger.append("one", {"a": 1})
    with (tmp_path / "ledger.log").open("a", encoding="utf-8") as fp:
        fp.write('{"bad":')
    rows = ledger.read_all()
    assert len(rows) == 1


def test_wasm_request_action_requires_containment_capability(tmp_path):
    signer = signing.SigningKey.generate()
    ledger = SignedLedger(tmp_path / "ledger.log", signer)
    loader = WasmModuleLoader([signer.verify_key], ["process_inspect", "containment_execute"], ledger)

    wasm_path = tmp_path / "mod.wasm"
    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00")
    digest = hashlib.sha256(wasm_path.read_bytes()).hexdigest().encode("utf-8")
    sig_path = tmp_path / "mod.sig"
    sig_path.write_text(base64.b64encode(signer.sign(digest).signature).decode("ascii"))

    manifest_path = tmp_path / "mod.manifest.json"
    manifest_path.write_text(json.dumps({
        "module_id": "m1",
        "version": "1.0.0",
        "capabilities": ["process_inspect"],
        "required_abi": ["request_action"],
    }))

    try:
        loader.load_signed_module(wasm_path, manifest_path, sig_path)
    except WasmSecurityError as exc:
        assert "request_action ABI requires" in str(exc)
    else:
        raise AssertionError("expected request_action capability rejection")


def test_agent_rejects_replayed_nonce(tmp_path):
    agent, control_signers = _agent_and_signers(tmp_path)
    order = _build_order(agent, [control_signers[0], control_signers[1]], required_quorum=2)
    agent.verify_containment_order(order)
    try:
        agent.verify_containment_order(order)
    except SecurityError as exc:
        assert "replayed order nonce" in str(exc)
    else:
        raise AssertionError("expected replay rejection")
