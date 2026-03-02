from __future__ import annotations

import http.server
import json
import secrets
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Any

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
    PeerVerificationMesh,
    TPMQuoteVerifier,
)
from sentinel_containment.telemetry.ingestor import TelemetryIngestor
from sentinel_containment.telemetry.sources import (
    DynamicSystemTelemetrySource,
    IngestionService,
    discover_live_file_sources,
)


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
            chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30))
        )
        self.honeypot_detector = HoneypotDetector(
            settings.get("honeypot_resources", []),
            settings.get("proto_agi_indicators", []),
        )
        self.mirror_clone_detector = MirrorCloneDetector(
            warmup_events=int(settings.get("clone_warmup_events", 6)),
            min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
            rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
        )
        self.audit = ImmutableAuditLog(
            out_of_band_path=Path(settings.get("audit_out_of_band_path")) if settings.get("audit_out_of_band_path") else None
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
        self._dynamic_threads: list[threading.Thread] = []

        self.fast_lane_server: FastLaneServer | None = None
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

        friendly_cfg = settings.get("friendly_enrollment", {})
        self.friendly_registry = FriendlyPeerRegistry(
            enrollment_user=str(friendly_cfg.get("enrollment_user", "user")),
            trusted_user_public_keys={str(k): str(v) for k, v in friendly_cfg.get("trusted_user_public_keys", {}).items()},
        )

        fast_lane_cfg = settings.get("fast_lane", {})
        if fast_lane_cfg.get("enabled", False):
            self.fast_lane_server = FastLaneServer(
                host=str(fast_lane_cfg.get("host", "0.0.0.0")),
                port=int(fast_lane_cfg.get("port", 9443)),
                path=str(fast_lane_cfg.get("path", "/fast-lane/event")),
                runtime=self,
                server_cert=str(fast_lane_cfg.get("server_cert_path", "certs/fastlane-server.crt")),
                server_key=str(fast_lane_cfg.get("server_key_path", "certs/fastlane-server.key")),
                client_ca_cert=str(fast_lane_cfg.get("client_ca_cert_path", "certs/fastlane-client-ca.crt")),
            )

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

        result = self.fast_lane_containment.execute(
            host=host,
            severity=severity,
            requested_actions=[str(a) for a in requested_actions],
            approvals=list(self.settings.get("automated_approvers", ["user"])),
            simulation_mode=False,
            hard_quarantine_threshold=int(self.settings.get("hard_quarantine_threshold", 90)),
            signature_bundle=event.get("containment_signature")
            if isinstance(event.get("containment_signature"), dict)
            else self.settings.get("containment_signature"),
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
        result = self.peer_mesh.run_attestation_cycle()
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
        )
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
