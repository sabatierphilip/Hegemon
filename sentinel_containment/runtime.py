from __future__ import annotations

import base64
import http.server
import json
import logging
import os
import secrets
import socketserver
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.containment.executors import ContainmentActionExecutor
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.honeypot import HoneypotDetector
from sentinel_containment.detection.mirror_clone import MirrorCloneDetector
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.main import run_cycle
from sentinel_containment.security import (
    CloudAttestationVerifier,
    FriendlyPeerRegistry,
    HardwareKeyVerifier,
    HumanConfirmationVerifier,
    MeshCheckpointLedger,
    PeerVerificationMesh,
    TPMQuoteVerifier,
)
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import (
    DynamicSystemTelemetrySource,
    IngestionService,
    discover_live_file_sources,
)


logger = logging.getLogger(__name__)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class FastLaneHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        server: "FastLaneServer" = self.server  # type: ignore[assignment]
        if self.path != server.path:
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid_json"}')
            return
        if not isinstance(payload, dict):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error":"event_must_be_object"}')
            return

        result = server.runtime.process_priority_event(payload)
        self.send_response(202)
        self.end_headers()
        self.wfile.write(json.dumps(result).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        return


class FastLaneServer(ThreadingHTTPServer):
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        runtime: "SentinelRuntime",
        server_cert: str,
        server_key: str,
        client_ca_cert: str,
    ):
        self.path = path
        self.runtime = runtime
        super().__init__((host, port), FastLaneHandler)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=server_cert, keyfile=server_key)
        context.load_verify_locations(cafile=client_ca_cert)
        self.socket = context.wrap_socket(self.socket, server_side=True)


class SentinelRuntime:
    """Single-process orchestrator for ingestion, detection, containment, dashboard state, and fast-lane interrupts."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.latest_state_path = Path(settings.get("latest_state_path", "data/latest_state.json"))

        ingest_cfg = settings.get("ingestion", {})
        telemetry_path = Path(
            settings.get("telemetry_index_path", ingest_cfg.get("index_path", "data/telemetry_index.jsonl"))
        )
        self.ingestor = TelemetryIngestor(telemetry_path)
        self.baseline = BehavioralBaseline(
            threshold=float(settings.get("anomaly_threshold", 2.0)),
            window=int(settings.get("baseline_window", 30)),
            min_history=int(settings.get("baseline_min_history", 5)),
        )
        self.rule_engine = RuleEngine(
            Path(settings.get("rules_path", "rules")),
            dedup_window_seconds=int(settings.get("alert_dedup_window_seconds", 300)),
        )
        self.correlator = AlertCorrelator()
        self.graph_detector = GraphAnomalyDetector(
            warmup_events=int(settings.get("graph_warmup_events", 5)),
            novelty_weight=float(settings.get("graph_novelty_weight", 1.6)),
            warmup_min_distinct_sources=int(settings.get("graph_warmup_min_distinct_sources", 2)),
            warmup_min_relations=int(settings.get("graph_warmup_min_relations", 1)),
        )
        self.sequence_model = AttackSequenceModel(
            chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30)),
            max_events_per_host=int(settings.get("attack_chain_max_events_per_host", 2048)),
            max_tracked_hosts=int(settings.get("attack_chain_max_tracked_hosts", 2048)),
        )
        self.honeypot_detector = HoneypotDetector(
            settings.get("honeypot_resources", []),
            settings.get("proto_agi_indicators", []),
            settings.get("honeypot_p2p_threat_patterns", []),
        )
        self.mirror_clone_detector = MirrorCloneDetector(
            warmup_events=int(settings.get("clone_warmup_events", 6)),
            min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
            rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
            max_tracked_shards=int(settings.get("clone_max_tracked_shards", 2048)),
            max_actions_per_shard=int(settings.get("clone_max_actions_per_shard", 20000)),
        )
        self.audit = ImmutableAuditLog(
            out_of_band_path=Path(settings.get("audit_out_of_band_path")) if settings.get("audit_out_of_band_path") else None
        )
        self.asset_mapper = AssetMapper(CloudProviderAdapter(simulated=bool(settings.get("simulated_mode", False))))
        self.containment = ContainmentEngine(
            self.audit,
            identity_store=settings.get("approval_identity_store", {}),
            required_approvals=int(settings.get("approval_quorum", 1)),
            hardware_key_verifier=HardwareKeyVerifier(
                settings.get("trusted_hardware_public_keys", {}),
                fail_closed=bool(settings.get("hardware_key_fail_closed", True)),
            ),
            human_confirmation_verifier=HumanConfirmationVerifier(
                shared_secret=str(settings.get("human_confirmation_shared_secret", "")),
                prompt_count=int(settings.get("human_confirmation_prompt_count", 2)),
                question_salt=str(settings.get("human_confirmation_question_salt", "human-presence-gate")),
                fail_closed=bool(settings.get("human_confirmation_fail_closed", True)),
            ),
            action_executor=ContainmentActionExecutor(active_mode=bool(settings.get("containment_live_mode", False))),
        )
        self.fast_lane_containment = ContainmentEngine(
            self.audit,
            identity_store=settings.get("approval_identity_store", {}),
            required_approvals=int(settings.get("approval_quorum", 1)),
            hardware_key_verifier=HardwareKeyVerifier(
                settings.get("trusted_hardware_public_keys", {}),
                fail_closed=bool(settings.get("hardware_key_fail_closed", True)),
            ),
            human_confirmation_verifier=HumanConfirmationVerifier(
                shared_secret=str(settings.get("human_confirmation_shared_secret", "")),
                prompt_count=int(settings.get("human_confirmation_prompt_count", 2)),
                question_salt=str(settings.get("human_confirmation_question_salt", "human-presence-gate")),
                fail_closed=bool(settings.get("human_confirmation_fail_closed", True)),
            ),
            action_executor=ContainmentActionExecutor(active_mode=bool(settings.get("containment_live_mode", False))),
        )

        extra_sources = {
            "host_kernel": Path(ingest_cfg.get("kernel_events_file", "data/kernel_events.jsonl")),
            "host_runtime": Path(ingest_cfg.get("runtime_events_file", "data/runtime_events.jsonl")),
            "host_osquery": Path(ingest_cfg.get("osquery_file", "data/osquery_events.jsonl")),
            "hypervisor": Path(ingest_cfg.get("hypervisor_events_file", "data/hypervisor_events.jsonl")),
            "counterclone": Path(ingest_cfg.get("counterclone_events_file", "data/counterclone_events.jsonl")),
        }
        extra_sources.update(discover_live_file_sources(extra_sources))
        self.ingestion_service = IngestionService(
            ingestor=self.ingestor,
            syslog_host=ingest_cfg.get("syslog_host", "0.0.0.0"),
            syslog_port=int(ingest_cfg.get("syslog_port", 5514)),
            cloudtrail_path=Path(ingest_cfg.get("cloudtrail_file", "data/cloudtrail.jsonl")),
            network_flow_path=Path(ingest_cfg.get("network_flow_file", "data/network_flows.jsonl")),
            model_api_path=Path(ingest_cfg.get("model_api_file", "data/model_api.jsonl")),
            extra_sources=extra_sources,
            kernel_webhook_host=ingest_cfg.get("kernel_webhook_host", "0.0.0.0"),
            kernel_webhook_port=int(ingest_cfg.get("kernel_webhook_port", 5515)),
            kernel_webhook_path=ingest_cfg.get("kernel_webhook_path", "/kernel-event"),
            on_kernel_event=self.process_priority_event,
            counterclone_integrity_key=ingest_cfg.get("counterclone_integrity_key"),
        )

        self._telemetry_setup_notice: dict[str, Any] = {"required": True, "granted": False, "completed": False, "details": []}
        self._human_required = bool(settings.get("human_required_default", False))
        self._hardware_key_setup_notice: dict[str, Any] = {
            "required": True,
            "configured": self.fast_lane_containment.hardware_key_verifier.configured,
            "completed": self.fast_lane_containment.hardware_key_verifier.configured,
            "details": [],
        }
        self._dynamic_threads: list[threading.Thread] = []
        self._containment_decision: dict[str, Any] = {
            "pending": False,
            "host": None,
            "severity": 0,
            "reason": "",
            "simulation": {},
            "recommended_actions": [],
            "hold_active": False,
        }
        self._containment_decision_lock = threading.Lock()
        self._holding_hosts: set[str] = set()
        self._auto_hardware_private_key: ed25519.Ed25519PrivateKey | None = None
        self._auto_hardware_key_id: str | None = None
        self._startup_warning_banner = ""

        self.fast_lane_server: FastLaneServer | None = None
        self.fast_lane_status: dict[str, Any] = {"enabled": bool(settings.get("fast_lane", {}).get("enabled", False)), "active": False, "missing_tls_files": []}
        p2p_cfg = settings.get("peer_verification", {})
        configured_peer_ids = p2p_cfg.get("peer_ids", [
            "ingestion_service",
            "detection_engine",
            "containment_engine",
            "web_dashboard",
            "fast_lane_gateway",
        ])
        process_keys: dict[str, str] = {}
        for peer_id in configured_peer_ids:
            normalized = str(peer_id).strip()
            if not normalized:
                continue
            env_key = f"HEGEMON_P2P_KEY_{normalized.upper()}"
            process_keys[normalized] = str(settings.env(env_key, secrets.token_hex(32)))

        configured_legacy_keys = {str(k): str(v) for k, v in p2p_cfg.get("process_keys", {}).items()}
        if configured_legacy_keys:
            self.audit.append(
                "peer_verification_warning",
                {
                    "reason": "deprecated_process_keys_in_config",
                    "message": "peer_verification.process_keys is deprecated; use HEGEMON_P2P_KEY_<PEER_ID> env vars",
                },
            )
            for pid, key in configured_legacy_keys.items():
                process_keys.setdefault(pid, key)

        external_verifiers = []
        tpm_cfg = p2p_cfg.get("external_tpm_attestation", {})
        if bool(tpm_cfg.get("enabled", False)):
            external_verifiers.append(
                TPMQuoteVerifier(
                    trusted_measurements={str(k): str(v) for k, v in tpm_cfg.get("trusted_measurements", {}).items()}
                )
            )

        cloud_cfg = p2p_cfg.get("external_cloud_attestation", {})
        if bool(cloud_cfg.get("enabled", False)):
            issuers = [str(i) for i in cloud_cfg.get("trusted_issuers", [])]
            external_verifiers.append(
                CloudAttestationVerifier(
                    trusted_issuers=issuers,
                    required_nonce_prefix=str(cloud_cfg.get("required_nonce_prefix", "hegemon")),
                )
            )

        self.peer_mesh = PeerVerificationMesh(
            process_keys=process_keys,
            max_clock_skew_seconds=int(p2p_cfg.get("max_clock_skew_seconds", 30)),
            external_verifiers=external_verifiers,
        )
        self._peer_verification_interval = float(p2p_cfg.get("interval_seconds", 5.0))
        self._next_peer_verification_due = 0.0
        self._p2p_signer_ids = [str(pid).strip() for pid in p2p_cfg.get("checkpoint_signers", configured_peer_ids) if str(pid).strip()]
        self._p2p_replication_targets = [str(x).strip() for x in p2p_cfg.get("replication_targets", configured_peer_ids) if str(x).strip()]
        self._p2p_attestation_cache: dict[str, dict[str, dict[str, Any]]] = {}
        self.checkpoint_ledger = MeshCheckpointLedger(
            self.peer_mesh,
            quorum_size=int(p2p_cfg.get("checkpoint_quorum", 2)),
            replication_targets=self._p2p_replication_targets,
            max_nonce_age_seconds=int(p2p_cfg.get("checkpoint_nonce_max_age_seconds", 900)),
            require_sequential=bool(p2p_cfg.get("checkpoint_require_sequential", True)),
        )

        friendly_cfg = settings.get("friendly_enrollment", {})
        self.friendly_registry = FriendlyPeerRegistry(
            enrollment_user=str(friendly_cfg.get("enrollment_user", "user")),
            trusted_user_public_keys={str(k): str(v) for k, v in friendly_cfg.get("trusted_user_public_keys", {}).items()},
        )

        fast_lane_cfg = settings.get("fast_lane", {})
        if fast_lane_cfg.get("enabled", False):
            server_cert = Path(str(fast_lane_cfg.get("server_cert_path", "certs/fastlane-server.crt")))
            server_key = Path(str(fast_lane_cfg.get("server_key_path", "certs/fastlane-server.key")))
            client_ca = Path(str(fast_lane_cfg.get("client_ca_cert_path", "certs/fastlane-client-ca.crt")))
            missing = [str(path) for path in (server_cert, server_key, client_ca) if not path.exists()]
            if missing:
                self.fast_lane_status = {"enabled": True, "active": False, "missing_tls_files": missing}
                self.audit.append(
                    "fast_lane_disabled",
                    {
                        "reason": "missing_tls_material",
                        "missing_files": missing,
                    },
                )
                logger.warning("Fast-lane TLS listener disabled; missing cert material: %s", ", ".join(missing))
            else:
                self.fast_lane_server = FastLaneServer(
                    host=str(fast_lane_cfg.get("host", "0.0.0.0")),
                    port=int(fast_lane_cfg.get("port", 9443)),
                    path=str(fast_lane_cfg.get("path", "/fast-lane/event")),
                    runtime=self,
                    server_cert=str(server_cert),
                    server_key=str(server_key),
                    client_ca_cert=str(client_ca),
                )
                self.fast_lane_status = {"enabled": True, "active": True, "missing_tls_files": []}

        if bool(self.settings.get("auto_grant_telemetry_permission", True)) and not self._human_required:
            self.apply_telemetry_permission(True)
        if bool(self.settings.get("auto_configure_hardware_keys_on_startup", True)):
            self.auto_configure_hardware_keys(True)
        self._emit_preflight_trust_anchor_warning_if_needed()

    def get_human_gate_status(self) -> dict[str, Any]:
        return {
            "human_required": self._human_required,
            "completed": not self._human_required,
            "details": ["operator_decision_required"] if self._human_required else ["fully_autonomous_mode"],
        }

    def set_human_gate(self, human_required: bool) -> dict[str, Any]:
        self._human_required = bool(human_required)
        self.settings.data["human_required_default"] = self._human_required
        if not self._human_required:
            self.apply_telemetry_permission(True)
            self.auto_configure_hardware_keys(True)
        payload = self.get_human_gate_status()
        self.audit.append("human_gate_updated", payload)
        return payload

    def get_containment_decision_status(self) -> dict[str, Any]:
        with self._containment_decision_lock:
            payload = dict(self._containment_decision)
            payload["holding_hosts"] = sorted(self._holding_hosts)
            return payload

    def _autonomous_containment_signature_bundle(
        self,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
    ) -> dict[str, Any] | None:
        private_key = self._auto_hardware_private_key
        key_id = str(self._auto_hardware_key_id or "").strip()
        if private_key is None or not key_id:
            return None

        digest = HardwareKeyVerifier.canonical_payload(
            host,
            severity,
            requested_actions,
            approvals,
            key_id,
            "yubikey",
            authorize_all_containment=False,
        )
        signature = base64.b64encode(private_key.sign(digest)).decode("utf-8")
        return {
            "key_id": key_id,
            "key_type": "yubikey",
            "signature": signature,
            "authorize_all_containment": False,
        }

    def apply_containment_decision(self, execute: bool) -> dict[str, Any]:
        with self._containment_decision_lock:
            if not self._containment_decision.get("pending", False):
                return {
                    "pending": False,
                    "executed": False,
                    "released": False,
                    "message": "No containment decision pending",
                    "holding_hosts": sorted(self._holding_hosts),
                }

            host = str(self._containment_decision.get("host") or "unknown")
            severity = int(self._containment_decision.get("severity", 0) or 0)
            recommended_actions = [str(a) for a in self._containment_decision.get("recommended_actions", [])]
            response: dict[str, Any] = {
                "pending": False,
                "host": host,
                "severity": severity,
            }

            if execute:
                approvals = list(self.settings.get("automated_approvers", ["user"]))
                signature_bundle = self.settings.get("containment_signature")
                if not signature_bundle:
                    signature_bundle = self._autonomous_containment_signature_bundle(
                        host=host,
                        severity=severity,
                        requested_actions=recommended_actions,
                        approvals=approvals,
                    )

                effective_signature = signature_bundle or self._autonomous_containment_signature_bundle(
                    host=host,
                    severity=severity,
                    requested_actions=recommended_actions,
                    approvals=approvals,
                )
                result = self.fast_lane_containment.execute(
                    host=host,
                    severity=severity,
                    requested_actions=recommended_actions,
                    approvals=approvals,
                    simulation_mode=False,
                    hard_quarantine_threshold=int(self.settings.get("hard_quarantine_threshold", 90)),
                    signature_bundle=effective_signature,
                    confirmation_bundle=self.settings.get("containment_confirmation"),
                )
                response.update(
                    {
                        "executed": result.approved,
                        "released": False,
                        "actions_executed": result.actions_executed,
                        "message": result.message,
                    }
                )
            else:
                self.fast_lane_containment.contained_hosts.discard(host)
                response.update(
                    {
                        "executed": False,
                        "released": True,
                        "actions_executed": ["release_containment_hold"],
                        "message": "Containment hold released by operator decision",
                    }
                )

            self._holding_hosts.discard(host)
            self._containment_decision = {
                "pending": False,
                "host": None,
                "severity": 0,
                "reason": "",
                "simulation": {},
                "recommended_actions": [],
                "hold_active": False,
            }
            response["holding_hosts"] = sorted(self._holding_hosts)
            self.audit.append("containment_manual_decision", response)
            return response

    def _update_containment_decision_from_state(self, state: dict[str, Any]) -> None:
        containment_state = state.get("containment") or {}
        should_prompt = bool(containment_state) and (
            bool(state.get("honeypot_alerts")) or bool(state.get("mirror_alerts")) or "simulate_quarantine_host" in containment_state.get("actions_executed", [])
        )
        if not should_prompt:
            return

        host = "unknown"
        alerts = state.get("alerts") or []
        honeypot_alerts = state.get("honeypot_alerts") or []
        if alerts:
            host = str((alerts[0] or {}).get("event", {}).get("host", "unknown"))
        elif honeypot_alerts:
            host = str((honeypot_alerts[0] or {}).get("event", {}).get("host", "unknown"))

        severity = int(state.get("candidate_severity", 0) or 0)
        recommended_actions = [
            "disable_outbound_traffic",
            "revoke_rotate_api_keys",
            "quarantine_host",
            "forensic_snapshot_metadata",
        ]
        if bool(honeypot_alerts) or bool(state.get("mirror_alerts")):
            recommended_actions = [
                "kill_active_model_sessions",
                "disable_iam_sessions",
                "disable_outbound_traffic",
                "revoke_rotate_api_keys",
                "pause_model_serving_container",
                "sinkhole_suspicious_destinations",
                "block_lateral_movement_paths",
                "quarantine_host",
                "forensic_snapshot_metadata",
            ]

        with self._containment_decision_lock:
            if self._containment_decision.get("pending", False):
                return
            if not self._human_required:
                approvals = list(self.settings.get("automated_approvers", ["user"]))
                configured_signature = self.settings.get("containment_signature")
                effective_signature = configured_signature if isinstance(configured_signature, dict) else self._autonomous_containment_signature_bundle(
                    host=host,
                    severity=severity,
                    requested_actions=recommended_actions,
                    approvals=approvals,
                )
                auto_result = self.fast_lane_containment.execute(
                    host=host,
                    severity=severity,
                    requested_actions=recommended_actions,
                    approvals=approvals,
                    simulation_mode=False,
                    hard_quarantine_threshold=int(self.settings.get("hard_quarantine_threshold", 90)),
                    signature_bundle=effective_signature,
                    confirmation_bundle=self.settings.get("containment_confirmation"),
                )
                self.audit.append(
                    "containment_auto_approved",
                    {
                        "host": host,
                        "severity": severity,
                        "approved": auto_result.approved,
                        "actions_executed": auto_result.actions_executed,
                        "message": auto_result.message,
                    },
                )
                return
            hold_approvals = list(self.settings.get("automated_approvers", ["user"]))
            configured_hold_signature = self.settings.get("containment_signature")
            effective_hold_signature = configured_hold_signature if isinstance(configured_hold_signature, dict) else self._autonomous_containment_signature_bundle(
                host=host,
                severity=max(70, min(89, severity)),
                requested_actions=["disable_outbound_traffic", "forensic_snapshot_metadata"],
                approvals=hold_approvals,
            )
            hold_result = self.fast_lane_containment.execute(
                host=host,
                severity=max(70, min(89, severity)),
                requested_actions=["disable_outbound_traffic", "forensic_snapshot_metadata"],
                approvals=hold_approvals,
                simulation_mode=False,
                hard_quarantine_threshold=int(self.settings.get("hard_quarantine_threshold", 90)),
                signature_bundle=effective_hold_signature,
                confirmation_bundle=self.settings.get("containment_confirmation"),
            )
            self._holding_hosts.add(host)
            self._containment_decision = {
                "pending": True,
                "host": host,
                "severity": severity,
                "reason": "malware_or_rogue_agent_detected",
                "simulation": containment_state,
                "recommended_actions": recommended_actions,
                "hold_active": True,
            }
            pending_payload = dict(self._containment_decision)
            pending_payload["holding_hosts"] = sorted(self._holding_hosts)
            self.audit.append("containment_decision_pending", pending_payload)
            self.audit.append("containment_hold_applied", {"host": host, "severity": severity, "approved": hold_result.approved, "actions_executed": hold_result.actions_executed, "message": hold_result.message})

    def get_hardware_key_setup_notice(self) -> dict[str, Any]:
        return dict(self._hardware_key_setup_notice)

    def _containment_policy_status(self) -> dict[str, Any]:
        engines = {
            "primary": self.containment,
            "fast_lane": self.fast_lane_containment,
        }
        blocked_reasons: list[str] = []
        approvals = list(self.settings.get("automated_approvers", ["user"]))
        host = "preflight-trust-anchor-check"
        severity = 95
        requested_actions = ["disable_outbound_traffic", "quarantine_host"]

        for name, engine in engines.items():
            signature_bundle = self.settings.get("containment_signature")
            if not isinstance(signature_bundle, dict):
                signature_bundle = self._autonomous_containment_signature_bundle(
                    host=host,
                    severity=severity,
                    requested_actions=requested_actions,
                    approvals=approvals,
                )
            confirmation_bundle = self.settings.get("containment_confirmation")
            if not isinstance(confirmation_bundle, dict):
                confirmation_bundle = None

            signature_verification = (
                engine.hardware_key_verifier.verify(
                    host=host,
                    severity=severity,
                    requested_actions=requested_actions,
                    approvals=approvals,
                    signature_bundle=signature_bundle,
                )
                if engine.hardware_key_verifier.enabled
                else None
            )
            confirmation_verification = (
                engine.human_confirmation_verifier.verify(
                    host=host,
                    severity=severity,
                    requested_actions=requested_actions,
                    approvals=approvals,
                    confirmation_bundle=confirmation_bundle,
                )
                if engine.human_confirmation_verifier.enabled
                else None
            )

            signature_ok = signature_verification is None or signature_verification.allowed
            confirmation_ok = confirmation_verification is None or confirmation_verification.allowed
            bypass_by_human = bool(
                confirmation_verification
                and confirmation_verification.allowed
                and engine.human_confirmation_verifier.configured
            )
            bypass_by_signature = bool(
                signature_verification
                and signature_verification.allowed
                and engine.hardware_key_verifier.configured
            )

            if not signature_ok and not bypass_by_human and signature_verification is not None:
                blocked_reasons.append(f"{name}: {signature_verification.message}")
            if not confirmation_ok and not bypass_by_signature and confirmation_verification is not None:
                blocked_reasons.append(f"{name}: {confirmation_verification.message}")

        return {
            "ready": not blocked_reasons,
            "blocked_reasons": blocked_reasons,
            "token_configured": True,
            "key_policy_ready": not blocked_reasons,
        }

    def _emit_preflight_trust_anchor_warning_if_needed(self) -> None:
        status = self._containment_policy_status()
        if status["ready"]:
            self._startup_warning_banner = ""
            return
        reason_blob = " | ".join(status["blocked_reasons"])
        self._startup_warning_banner = (
            "⚠️ HARD WARNING: containment authorization pre-flight failed. "
            f"Current key policy blocks kill-chain/containment execution: {reason_blob}"
        )
        self.audit.append("containment_preflight_blocked", status)
        logger.error(self._startup_warning_banner)

    def get_readiness_status(self) -> dict[str, Any]:
        policy = self._containment_policy_status()
        return {
            "token_ready": True,
            "key_policy_ready": bool(policy["key_policy_ready"]),
            "containment_ready": bool(policy["ready"]),
            "startup_warning": self._startup_warning_banner,
            "blocked_reasons": list(policy["blocked_reasons"]),
        }

    def _apply_hardware_key_to_all_engines(self, key_id: str, public_pem: str) -> None:
        self.containment.hardware_key_verifier.upsert_trusted_public_key(key_id, public_pem)
        self.fast_lane_containment.hardware_key_verifier.upsert_trusted_public_key(key_id, public_pem)
        self.settings.data.setdefault("trusted_hardware_public_keys", {})[key_id] = public_pem
        self.settings.data["hardware_key_fail_closed"] = True

    @staticmethod
    def _sha256_hex(payload: bytes) -> str:
        import hashlib

        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _secure_write_new_file(path: Path, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def _load_or_create_autohardware_key(self, private_key_path: Path, key_id: str) -> tuple[ed25519.Ed25519PrivateKey, str]:
        seal_path = private_key_path.with_suffix(f"{private_key_path.suffix}.seal")

        if private_key_path.exists() and seal_path.exists():
            private_bytes = private_key_path.read_bytes()
            seal_payload = json.loads(seal_path.read_text(encoding="utf-8"))
            expected_private_hash = str(seal_payload.get("private_key_sha256", "")).strip()
            if expected_private_hash != self._sha256_hex(private_bytes):
                raise RuntimeError("sealed hardware private key integrity check failed")
            private_key = serialization.load_pem_private_key(private_bytes, password=None)
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise RuntimeError("auto hardware private key is not Ed25519")
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            expected_public_hash = str(seal_payload.get("public_key_sha256", "")).strip()
            if expected_public_hash != self._sha256_hex(public_pem.encode("utf-8")):
                raise RuntimeError("sealed hardware public key integrity check failed")
            return private_key, public_pem

        if private_key_path.exists() or seal_path.exists():
            quarantine_suffix = f".quarantine.{int(time.time())}"
            if private_key_path.exists():
                private_key_path.replace(private_key_path.with_name(private_key_path.name + quarantine_suffix))
            if seal_path.exists():
                seal_path.replace(seal_path.with_name(seal_path.name + quarantine_suffix))

        private_key = ed25519.Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        seal_payload = {
            "version": 1,
            "key_id": key_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "private_key_sha256": self._sha256_hex(private_bytes),
            "public_key_sha256": self._sha256_hex(public_pem.encode("utf-8")),
        }
        seal_bytes = (json.dumps(seal_payload, sort_keys=True) + "\n").encode("utf-8")

        self._secure_write_new_file(private_key_path, private_bytes)
        self._secure_write_new_file(seal_path, seal_bytes)
        return private_key, public_pem

    def auto_configure_hardware_keys(self, configure: bool) -> dict[str, Any]:
        if not configure:
            self._hardware_key_setup_notice = {
                "required": True,
                "configured": self.fast_lane_containment.hardware_key_verifier.configured,
                "completed": False,
                "details": ["operator_declined_auto_config"],
            }
            self.audit.append("hardware_key_autoconfig_declined", self._hardware_key_setup_notice)
            return dict(self._hardware_key_setup_notice)

        existing_signature = self.settings.get("containment_signature")
        if self.fast_lane_containment.hardware_key_verifier.configured and isinstance(existing_signature, dict):
            key_id = str(existing_signature.get("key_id", "auto-ed25519-local")).strip() or "auto-ed25519-local"
            trusted_keys = self.settings.get("trusted_hardware_public_keys", {})
            key_material = str(trusted_keys.get(key_id, "")).strip() if isinstance(trusted_keys, dict) else ""
            if key_material:
                self._apply_hardware_key_to_all_engines(key_id, key_material)
            self._hardware_key_setup_notice = {
                "required": True,
                "configured": True,
                "completed": True,
                "details": ["hardware_key_profile_already_configured"],
                "key_id": key_id,
                "local_only": True,
            }
            return dict(self._hardware_key_setup_notice)

        key_id = str(self.settings.get("auto_hardware_key_id", "auto-ed25519-local")).strip() or "auto-ed25519-local"
        persist_private_key = bool(self.settings.get("auto_hardware_persist_private_key", False))

        if persist_private_key:
            private_key_path = Path(str(self.settings.get("auto_hardware_private_key_path", "data/auto_hardware_ed25519.pem")))
            private_key_path.parent.mkdir(parents=True, exist_ok=True)
            private_key, public_pem = self._load_or_create_autohardware_key(private_key_path, key_id)
            detail = f"public_key_loaded_from_sealed_store:{private_key_path.with_suffix(private_key_path.suffix + '.seal')}"
            audit_payload = {"key_id": key_id, "local_only": True, "persist_private_key": True}
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")
            detail = "ephemeral_private_key_not_persisted"
            audit_payload = {"key_id": key_id, "local_only": True, "persist_private_key": False}

        self._apply_hardware_key_to_all_engines(key_id, public_pem)
        self.settings.data.pop("containment_signature", None)
        self._auto_hardware_private_key = private_key
        self._auto_hardware_key_id = key_id

        self._hardware_key_setup_notice = {
            "required": True,
            "configured": True,
            "completed": True,
            "details": [
                "hardware_key_profile_hardened",
                "runtime_trust_anchor_updated",
                detail,
                "operator_signature_required",
                "autonomous_runtime_signature_enabled",
            ],
            "key_id": key_id,
            "local_only": True,
        }
        self.audit.append("hardware_key_autoconfig_completed", audit_payload)
        self._emit_preflight_trust_anchor_warning_if_needed()
        return dict(self._hardware_key_setup_notice)

    def run_incident_drill(self) -> dict[str, Any]:
        if not self._containment_policy_status()["ready"] and bool(self.settings.get("drill_auto_configure_hardware_keys", True)):
            self.auto_configure_hardware_keys(True)

        drill_event = {
            "source_type": "incident_drill",
            "host": "drill-host-001",
            "severity": int(self.settings.get("incident_drill_severity", 98)),
            "kill_chain": True,
            "honeypot_trigger": True,
            "requested_actions": [
                "kill_active_model_sessions",
                "disable_iam_sessions",
                "disable_outbound_traffic",
                "revoke_rotate_api_keys",
                "pause_model_serving_container",
                "sinkhole_suspicious_destinations",
                "block_lateral_movement_paths",
                "quarantine_host",
                "forensic_snapshot_metadata",
            ],
        }
        result = self.process_priority_event(drill_event)
        payload = {
            "mode": "deterministic_incident_drill",
            "approved": bool(result.get("approved", False)),
            "host": drill_event["host"],
            "severity": drill_event["severity"],
            "actions_executed": result.get("actions_executed", []),
            "message": result.get("message", ""),
        }
        self.audit.append("incident_drill_completed", payload)
        return payload

    def apply_telemetry_permission(self, granted: bool) -> dict[str, Any]:
        details: list[str] = []
        if granted:
            details = self._setup_dynamic_telemetry_sources()
        self._telemetry_setup_notice = {
            "required": True,
            "granted": bool(granted),
            "completed": bool(granted),
            "details": details,
        }
        self.audit.append("telemetry_permission", self._telemetry_setup_notice)
        return dict(self._telemetry_setup_notice)

    def get_telemetry_setup_notice(self) -> dict[str, Any]:
        return dict(self._telemetry_setup_notice)

    def _setup_dynamic_telemetry_sources(self) -> list[str]:
        ingest_cfg = self.settings.get("ingestion", {})
        details: list[str] = []

        autodiscovery = discover_live_file_sources({fs.source_type: fs.path for fs in self.ingestion_service.file_sources})
        for source_type, path in autodiscovery.items():
            if self.ingestion_service.add_file_source(
                source_type,
                path,
                counterclone_integrity_key=ingest_cfg.get("counterclone_integrity_key"),
            ):
                details.append(f"attached_file_source:{source_type}:{path}")

        dynamic_source = DynamicSystemTelemetrySource(
            self.ingestor,
            poll_interval_seconds=float(ingest_cfg.get("dynamic_system_poll_seconds", 10.0)),
        )
        t = threading.Thread(target=dynamic_source.run_forever, args=(lambda: self._stop.is_set(),), daemon=True)
        t.start()
        self._dynamic_threads.append(t)
        details.append("enabled_dynamic_system_runtime")
        return details

    def process_priority_event(self, event: dict[str, Any]) -> dict[str, Any]:
        source_type = str(event.get("source_type", "fast_lane"))
        self.ingestor.ingest(source_type, event)

        severity = int(event.get("severity", 95))
        host = str(event.get("host", "unknown"))
        requested_actions = event.get("requested_actions")
        if not isinstance(requested_actions, list):
            if bool(event.get("kill_chain", False)) or bool(event.get("honeypot_trigger", False)):
                requested_actions = [
                    "kill_active_model_sessions",
                    "disable_iam_sessions",
                    "disable_outbound_traffic",
                    "revoke_rotate_api_keys",
                    "pause_model_serving_container",
                    "sinkhole_suspicious_destinations",
                    "block_lateral_movement_paths",
                    "quarantine_host",
                    "forensic_snapshot_metadata",
                ]
            else:
                requested_actions = [
                    "disable_outbound_traffic",
                    "revoke_rotate_api_keys",
                    "quarantine_host",
                    "forensic_snapshot_metadata",
                ]

        normalized_actions = [str(a) for a in requested_actions]
        approvals = list(self.settings.get("automated_approvers", ["user"]))
        event_signature = event.get("containment_signature") if isinstance(event.get("containment_signature"), dict) else None
        configured_signature = self.settings.get("containment_signature") if isinstance(self.settings.get("containment_signature"), dict) else None
        effective_signature = event_signature or configured_signature or self._autonomous_containment_signature_bundle(
            host=host,
            severity=severity,
            requested_actions=normalized_actions,
            approvals=approvals,
        )

        result = self.fast_lane_containment.execute(
            host=host,
            severity=severity,
            requested_actions=normalized_actions,
            approvals=approvals,
            simulation_mode=False,
            hard_quarantine_threshold=int(self.settings.get("hard_quarantine_threshold", 90)),
            signature_bundle=effective_signature,
            confirmation_bundle=event.get("containment_confirmation")
            if isinstance(event.get("containment_confirmation"), dict)
            else self.settings.get("containment_confirmation"),
        )
        payload = {
            "host": host,
            "severity": severity,
            "approved": result.approved,
            "actions_executed": result.actions_executed,
            "message": result.message,
            "path": "fast_lane",
        }
        self.audit.append("fast_lane_containment", payload)
        return payload

    def _run_peer_verification(self) -> dict[str, Any]:
        self._p2p_attestation_cache = self._build_peer_attestation_evidence()
        result = self.peer_mesh.run_attestation_cycle(external_attestations=self._p2p_attestation_cache)
        payload = {
            "verified": result.ok,
            "verified_pairs": result.verified_pairs,
            "failures": result.failures,
            "mesh_size": len(self.peer_mesh.process_ids),
            "external_verification": result.external_verification,
        }
        self.ingestor.ingest(
            "host_runtime",
            {
                "host": self.settings.get("system_name", "hegemon"),
                "process": "peer-verification-mesh",
                "action": "p2p_attestation_cycle",
                "resource": "hegemon_processes",
                "collector_level": "runtime",
                "peer_verification": payload,
                "counterclone_participant": True,
                "counterclone_integrity_verified": result.ok,
            },
        )
        if not result.ok:
            self.audit.append("peer_verification_failed", payload)
        return payload


    def _build_peer_attestation_evidence(self) -> dict[str, dict[str, dict[str, Any]]]:
        p2p_cfg = self.settings.get("peer_verification", {})
        tpm_refs = p2p_cfg.get("external_tpm_attestation", {}).get("trusted_measurements", {})
        cloud_cfg = p2p_cfg.get("external_cloud_attestation", {})
        issuers = cloud_cfg.get("trusted_issuers", [])
        cloud_issuer = str(issuers[0]) if isinstance(issuers, list) and issuers else ""
        nonce_prefix = str(cloud_cfg.get("required_nonce_prefix", "hegemon"))

        evidence: dict[str, dict[str, dict[str, Any]]] = {}
        now = int(time.time())
        for peer in self.peer_mesh.process_ids:
            evidence[peer] = {
                "tpm_quote": {"measurement": str(tpm_refs.get(peer, ""))},
                "cloud_attestation": {
                    "issuer": cloud_issuer,
                    "nonce": f"{nonce_prefix}-{now}-{peer}",
                    "workload": peer,
                },
            }
        return evidence

    def _checkpoint_critical_state(self, state: dict[str, Any]) -> dict[str, Any]:
        directive_payload = {
            "autonomous_recon_directives": state.get("autonomous_recon_directives", []),
            "stage_two_counteroffensive_directives": state.get("stage_two_counteroffensive_directives", []),
            "level_three_hunting_directives": state.get("level_three_hunting_directives", []),
            "level_four_continuous_directives": state.get("level_four_continuous_directives", []),
            "level_five_hunter_directives": state.get("level_five_hunter_directives", []),
            "counter_clone_actions": state.get("counter_clone_actions", []),
            "candidate_severity": state.get("candidate_severity", 0),
            "risk_confidence": state.get("risk_confidence", 0.0),
        }
        checkpoint = self.checkpoint_ledger.create_checkpoint(
            entries=[directive_payload],
            signer_ids=self._p2p_signer_ids,
            attestation_bundle=self._p2p_attestation_cache,
            replication_targets=self._p2p_replication_targets,
        )
        validation = self.checkpoint_ledger.validate_checkpoint(
            checkpoint,
            attestation_bundle=self._p2p_attestation_cache,
            observe_state=True,
        )
        for target in checkpoint.replication_targets:
            self.checkpoint_ledger.gossip_observe(checkpoint, source_peer=target)

        payload = {
            "accepted": validation.accepted,
            "quorum_met": validation.quorum_met,
            "reasons": validation.reasons,
            "verified_signers": validation.verified_signers,
            "observed_notaries": validation.observed_notaries,
            "checkpoint": {
                "seq_no": checkpoint.seq_no,
                "epoch": checkpoint.epoch,
                "nonce": checkpoint.nonce,
                "created_at": checkpoint.created_at,
                "prev_checkpoint_hash": checkpoint.prev_checkpoint_hash,
                "merkle_root": checkpoint.merkle_root,
                "entry_count": checkpoint.entry_count,
                "signer_ids": checkpoint.signer_ids,
                "replication_targets": checkpoint.replication_targets,
                "checkpoint_hash": checkpoint.checkpoint_hash,
            },
        }

        critical_directives = bool(
            state.get("autonomous_recon_directives")
            or state.get("stage_two_counteroffensive_directives")
            or state.get("level_three_hunting_directives")
            or state.get("level_four_continuous_directives")
            or state.get("level_five_hunter_directives")
        )
        if critical_directives and not validation.accepted:
            payload["directive_quarantine"] = True
            state["autonomous_recon_directives"] = []
            state["stage_two_counteroffensive_directives"] = []
            state["level_three_hunting_directives"] = []
            state["level_four_continuous_directives"] = []
            state["level_five_hunter_directives"] = []
        return payload

    def enroll_friendly_software(
        self,
        *,
        requested_by: str,
        software_id: str,
        peer_key: str,
        endpoints: list[str],
        signature_bundle: dict[str, Any] | None,
    ) -> dict[str, Any]:
        enrollment = self.friendly_registry.enroll(
            requested_by=requested_by,
            software_id=software_id,
            peer_key=peer_key,
            endpoints=endpoints,
            signature_bundle=signature_bundle,
        )
        payload = {
            "requested_by": requested_by,
            "software_id": software_id,
            "accepted": enrollment.accepted,
            "message": enrollment.message,
        }
        if enrollment.accepted and enrollment.record:
            self.peer_mesh.add_or_update_peer(software_id, peer_key)
            patrol = {
                "host": self.settings.get("system_name", "hegemon"),
                "process": "friendly-patrol",
                "action": "guard_friendly_software",
                "resource": software_id,
                "collector_level": "counterclone",
                "counterclone_participant": True,
                "counterclone_integrity_verified": True,
                "patrol_targets": self.friendly_registry.patrol_targets(),
            }
            self.ingestor.ingest("counterclone", patrol)
            payload["patrol_targets"] = self.friendly_registry.patrol_targets()
        self.audit.append("friendly_enrollment", payload)
        return payload

    def run_once(self) -> dict:
        state = run_cycle(
            self.settings,
            baseline=self.baseline,
            rules=self.rule_engine,
            correlator=self.correlator,
            graph_detector=self.graph_detector,
            sequence_model=self.sequence_model,
            honeypot_detector=self.honeypot_detector,
            mirror_clone_detector=self.mirror_clone_detector,
            audit=self.audit,
            mapper=self.asset_mapper,
            ingestor=self.ingestor,
            containment=self.containment,
        )
        self._update_containment_decision_from_state(state)
        state["containment_decision"] = self.get_containment_decision_status()
        state["fast_lane_status"] = dict(self.fast_lane_status)
        state["readiness"] = self.get_readiness_status()
        state["p2p_checkpoint"] = self._checkpoint_critical_state(state)
        self.latest_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.latest_state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")
        return state

    def _cycle_loop(self) -> None:
        base_interval = float(self.settings.get("continuous_cycle_sleep_seconds", 0.25))
        burst_threshold = int(self.settings.get("burst_cycle_severity_threshold", 80))
        burst_interval_seconds = float(self.settings.get("burst_cycle_seconds", 0.1))
        while not self._stop.is_set():
            state = self.run_once()
            now = time.time()
            if now >= self._next_peer_verification_due:
                self._run_peer_verification()
                self._next_peer_verification_due = now + self._peer_verification_interval
            cycle_interval = burst_interval_seconds if state.get("candidate_severity", 0) >= burst_threshold else base_interval
            self._stop.wait(max(0.0, cycle_interval))

    def start(self) -> None:
        self.ingestion_service.start()
        if self.fast_lane_server is not None:
            fast_lane_thread = threading.Thread(target=self.fast_lane_server.serve_forever, daemon=True)
            fast_lane_thread.start()
            self._threads.append(fast_lane_thread)
        cycle_thread = threading.Thread(target=self._cycle_loop, daemon=True)
        cycle_thread.start()
        self._threads.append(cycle_thread)

    def stop(self) -> None:
        self._stop.set()
        self.ingestion_service.stop()
        if self.fast_lane_server is not None:
            self.fast_lane_server.shutdown()
            self.fast_lane_server.server_close()
        for t in self._threads:
            t.join(timeout=2)
