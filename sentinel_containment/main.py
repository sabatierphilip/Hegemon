from __future__ import annotations

import time
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.blast_radius import CredentialBlastRadiusAnalyzer
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.containment.executors import ContainmentActionExecutor
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.mirror_clone import (
    LevelThreeDirective,
    MirrorCloneDetector,
    ReconDirective,
    StageTwoDirective,
)
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.graph_anomaly import parse_event_time
from sentinel_containment.detection.honeypot import HoneypotDetector
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.security import HardwareKeyVerifier, HumanConfirmationVerifier
from sentinel_containment.soar.workflow import SoarEngine
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


CLONE_ALLOWED_SYNTHETIC_ACTIONS = {"read", "list", "model_invoke"}


def _build_hardware_key_verifier(settings: Settings) -> HardwareKeyVerifier:
    return HardwareKeyVerifier(
        settings.get("trusted_hardware_public_keys", {}),
        fail_closed=bool(settings.get("hardware_key_fail_closed", True)),
    )


def _build_human_confirmation_verifier(settings: Settings) -> HumanConfirmationVerifier:
    return HumanConfirmationVerifier(
        shared_secret=str(settings.get("human_confirmation_shared_secret", "")),
        prompt_count=int(settings.get("human_confirmation_prompt_count", 2)),
        question_salt=str(settings.get("human_confirmation_question_salt", "human-presence-gate")),
        fail_closed=bool(settings.get("human_confirmation_fail_closed", True)),
    )


def _containment_signature(settings: Settings) -> dict[str, Any] | None:
    payload = settings.get("containment_signature")
    return payload if isinstance(payload, dict) else None


def _containment_confirmation(settings: Settings) -> dict[str, Any] | None:
    payload = settings.get("containment_confirmation")
    return payload if isinstance(payload, dict) else None


def execute_counter_clone_actions(
    actions: list[dict[str, Any]],
    deployment: dict[str, Any],
    containment: ContainmentEngine,
    ingestor: TelemetryIngestor,
    audit: ImmutableAuditLog,
    signature_bundle: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute counter-clone actions with safety constraints and synthetic stream isolation.

    `activate_deception_hardening` is explicitly defined as emitting baseline-like synthetic
    read/list/model_invoke events that obscure detector timing without offensive behavior.
    """
    execution_log: list[dict[str, Any]] = []

    def _record(action: str, target: str, status: str, details: dict[str, Any] | None = None) -> None:
        payload = {"action": action, "target": target, "status": status, "details": details or {}}
        execution_log.append(payload)
        audit.append("counter_clone_executor", payload)

    simulated_host = deployment["shard"].split("|", 1)[0].replace("host:", "")
    for item in actions:
        action = str(item.get("action", "unknown"))
        target = str(item.get("target", "unknown"))

        if action == "prestage_containment":
            target_host = target.split("|", 1)[0].replace("host:", "") if "host:" in target else simulated_host
            result = containment.execute(
                host=target_host,
                severity=70,
                requested_actions=["disable_outbound_traffic", "forensic_snapshot_metadata"],
                approvals=["user"],
                simulation_mode=True,
                signature_bundle=signature_bundle,
            )
            _record(action, target, "executed", {"approved": result.approved, "actions": result.actions_executed})
            continue

        if action == "block_simulated_path":
            _record(action, target, "simulated", {"rule": "egress_sinkhole", "applied": True})
            continue

        if action == "emit_synthetic_probe":
            sequence = deployment.get("synthetic_probe_sequence", [])
            probe = next((p for p in sequence if str(p.get("resource", "")) == target), None)
            probe_action = str((probe or {}).get("action", "list")).strip().lower()
            if probe_action not in CLONE_ALLOWED_SYNTHETIC_ACTIONS:
                _record(action, target, "dropped", {"reason": "action_not_whitelisted", "candidate": probe_action})
                continue

            ingestor.ingest(
                "clone_synthetic",
                {
                    "host": (probe or {}).get("host", simulated_host),
                    "user": "clone-shadow",
                    "process": "counter-clone",
                    "action": probe_action,
                    "resource": target,
                    "synthetic": True,
                    "counterclone_participant": True,
                    "counterclone_integrity_verified": True,
                    "clone_deployment_id": deployment.get("deployment_id", "unknown"),
                },
            )
            _record(action, target, "executed", {"event_action": probe_action})
            continue

        if action == "launch_autonomous_recon":
            ingestor.ingest(
                "clone_synthetic",
                {
                    "host": simulated_host,
                    "user": "clone-hunter",
                    "process": "counter-clone",
                    "action": "list",
                    "resource": f"synthetic://hunter/{target}",
                    "synthetic": True,
                    "counterclone_participant": True,
                    "counterclone_integrity_verified": True,
                    "clone_deployment_id": deployment.get("deployment_id", "autonomous-recon"),
                },
            )
            _record(action, target, "executed", {"mode": "active_hunt"})
            continue

        if action == "backmodel_markov_kill_chain":
            _record(action, target, "executed", {"model": "markov", "status": "updated"})
            continue

        if action == "simulate_branch_intercepts":
            intercepts = [segment.strip() for segment in target.split("||") if segment.strip()]
            _record(
                action,
                target,
                "executed",
                {
                    "branch_count": len(intercepts),
                    "status": "intercepts_staged",
                },
            )
            continue

        if action == "seed_honeypot_route":
            ingestor.ingest(
                "clone_synthetic",
                {
                    "host": simulated_host,
                    "user": "clone-hunter",
                    "process": "counter-clone",
                    "action": "list",
                    "resource": f"synthetic://honeypot/{target}",
                    "synthetic": True,
                    "counterclone_participant": True,
                    "counterclone_integrity_verified": True,
                    "clone_deployment_id": deployment.get("deployment_id", "autonomous-recon"),
                },
            )
            _record(action, target, "executed", {"status": "deception_seeded"})
            continue

        if action == "run_phase":
            if target == "activate_deception_hardening":
                for baseline_action in ("list", "read", "model_invoke"):
                    ingestor.ingest(
                        "clone_synthetic",
                        {
                            "host": simulated_host,
                            "user": "clone-shadow",
                            "process": "counter-clone",
                            "action": baseline_action,
                            "resource": f"synthetic://baseline/{baseline_action}",
                            "synthetic": True,
                            "counterclone_participant": True,
                            "counterclone_integrity_verified": True,
                            "clone_deployment_id": deployment.get("deployment_id", "unknown"),
                        },
                    )
                _record(action, target, "executed", {"definition": "baseline_cover_traffic"})
            else:
                _record(action, target, "executed", {"phase": "acknowledged"})
            continue

        if action == "deploy_mirror_swarm":
            ingestor.ingest(
                "clone_synthetic",
                {
                    "host": simulated_host,
                    "user": "mirror-swarm",
                    "process": "counter-clone",
                    "action": "list",
                    "resource": f"synthetic://swarm/{target}",
                    "synthetic": True,
                    "counterclone_participant": True,
                    "counterclone_integrity_verified": True,
                    "clone_deployment_id": deployment.get("deployment_id", "stage2"),
                },
            )
            _record(action, target, "executed", {"mode": "stage2_swarm_deployed"})
            continue

        if action == "hunt_rogue_agent":
            _record(action, target, "executed", {"mode": "stage2_hunt_active"})
            continue

        if action == "isolate_proto_agi_mesh":
            _record(action, target, "simulated", {"mode": "proto_agi_mesh_isolation", "rule": "mesh_sinkhole"})
            continue

        _record(action, target, "ignored", {"reason": "unsupported_action"})

    return execution_log


def compute_risk_confidence(
    candidate_severity: int,
    rule_alerts: list,
    baseline_alerts: list,
    graph_anomalies: list,
    attack_chains: list,
    honeypot_alerts: list,
    mirror_alerts: list,
    blast_radius_score: int,
) -> float:
    """Blend severity, detector consensus, and blast radius into a normalized risk confidence."""
    signal_buckets = [
        bool(rule_alerts),
        bool(baseline_alerts),
        bool(graph_anomalies),
        bool(attack_chains),
        bool(honeypot_alerts),
        bool(mirror_alerts),
    ]
    detector_consensus = sum(1 for s in signal_buckets if s) / len(signal_buckets)
    severity_norm = max(0.0, min(float(candidate_severity) / 100.0, 1.0))
    blast_norm = max(0.0, min(float(blast_radius_score) / 100.0, 1.0))
    return round((severity_norm * 0.55) + (detector_consensus * 0.30) + (blast_norm * 0.15), 4)


def should_simulate_containment(settings: Settings, severity: int, blast_radius_score: int, immediate: bool) -> bool:
    simulation_default = bool(settings.get("containment_simulation_mode", False))
    if immediate or not simulation_default:
        return False

    force_hard_threshold = int(settings.get("force_hard_containment_threshold", 80))
    force_hard_blast_radius = int(settings.get("force_hard_containment_blast_radius", 70))
    if severity >= force_hard_threshold or blast_radius_score >= force_hard_blast_radius:
        return False

    return True


def distributed_attack_signal(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Estimate whether activity is intentionally sharded across identities."""
    shards: set[tuple[str, str, str]] = set()
    suspicious_actions = 0
    egress_events = 0
    for event in events:
        host = str(event.get("host", "unknown"))
        user = str(event.get("user", "unknown"))
        process = str(event.get("process", "unknown"))
        shards.add((host, user, process))

        action = str(event.get("action", "")).lower()
        resource = str(event.get("resource", "")).lower()
        payload = f"{action} {resource}"
        if any(token in payload for token in ("scan", "list", "read", "query", "network_send", "egress", "upload")):
            suspicious_actions += 1
        if float(event.get("egress_mb", 0) or 0) >= 80 or action in {"network_send", "upload", "egress"}:
            egress_events += 1

    shard_count = len(shards)
    suspicious_density = (suspicious_actions / max(1, len(events))) if events else 0.0
    concentrated_single_shard = shard_count == 1 and suspicious_density >= 0.85 and egress_events >= 1
    score = min(
        1.0,
        (shard_count / 4.0) * 0.45
        + suspicious_density * 0.30
        + min(1.0, egress_events / 2.0) * 0.15
        + (0.10 if concentrated_single_shard else 0.0),
    )
    return {
        "shard_count": shard_count,
        "suspicious_density": round(suspicious_density, 4),
        "egress_events": egress_events,
        "concentrated_single_shard": concentrated_single_shard,
        "score": round(score, 4),
        "is_distributed": (shard_count >= 3 and suspicious_density >= 0.45) or concentrated_single_shard,
    }


def run_cycle(
    settings: Settings,
    baseline: BehavioralBaseline | None = None,
    rules: RuleEngine | None = None,
    correlator: AlertCorrelator | None = None,
    graph_detector: GraphAnomalyDetector | None = None,
    sequence_model: AttackSequenceModel | None = None,
    honeypot_detector: HoneypotDetector | None = None,
    mirror_clone_detector: MirrorCloneDetector | None = None,
    audit: ImmutableAuditLog | None = None,
    mapper: AssetMapper | None = None,
    ingestor: TelemetryIngestor | None = None,
    containment: ContainmentEngine | None = None,
) -> dict:
    out_of_band = settings.get("audit_out_of_band_path")
    audit = audit or ImmutableAuditLog(out_of_band_path=Path(out_of_band) if out_of_band else None)
    mapper = mapper or AssetMapper(CloudProviderAdapter(simulated=bool(settings.get("simulated_mode", False))))
    topology = mapper.snapshot()

    ingestor = ingestor or TelemetryIngestor(Path(settings.get("telemetry_index_path", "data/telemetry_index.jsonl")))
    baseline = baseline or BehavioralBaseline(
        threshold=float(settings.get("anomaly_threshold", 2.0)),
        window=int(settings.get("baseline_window", 30)),
        min_history=int(settings.get("baseline_min_history", 5)),
    )
    rules = rules or RuleEngine(
        Path(settings.get("rules_path", "rules")),
        dedup_window_seconds=int(settings.get("alert_dedup_window_seconds", 300)),
    )
    correlator = correlator or AlertCorrelator()
    graph_detector = graph_detector or GraphAnomalyDetector(
        warmup_events=int(settings.get("graph_warmup_events", 5)),
        novelty_weight=float(settings.get("graph_novelty_weight", 1.6)),
        warmup_min_distinct_sources=int(settings.get("graph_warmup_min_distinct_sources", 2)),
        warmup_min_relations=int(settings.get("graph_warmup_min_relations", 1)),
    )
    sequence_model = sequence_model or AttackSequenceModel(
        chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30)),
        max_events_per_host=int(settings.get("attack_chain_max_events_per_host", 2048)),
        max_tracked_hosts=int(settings.get("attack_chain_max_tracked_hosts", 2048)),
    )
    honeypot_detector = honeypot_detector or HoneypotDetector(
        settings.get("honeypot_resources", []),
        settings.get("proto_agi_indicators", []),
    )
    mirror_clone_detector = mirror_clone_detector or MirrorCloneDetector(
        warmup_events=int(settings.get("clone_warmup_events", 6)),
        min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
        rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
        max_tracked_shards=int(settings.get("clone_max_tracked_shards", 2048)),
        max_actions_per_shard=int(settings.get("clone_max_actions_per_shard", 20000)),
    )
    containment = containment or ContainmentEngine(
        audit,
        identity_store=settings.get("approval_identity_store", {}),
        required_approvals=int(settings.get("approval_quorum", 1)),
        hardware_key_verifier=_build_hardware_key_verifier(settings),
        human_confirmation_verifier=_build_human_confirmation_verifier(settings),
        action_executor=ContainmentActionExecutor(active_mode=bool(settings.get("containment_live_mode", False))),
    )
    blast_radius_analyzer = CredentialBlastRadiusAnalyzer()
    soar = SoarEngine(Path(settings.get("playbook_path", "playbooks/default_playbook.yaml")), audit)

    recent_events = ingestor.read_recent(limit=int(settings.get("telemetry_batch_limit", 200)))
    horizon_minutes_cfg = settings.get("graph_horizons_minutes", [5, 30, 180])
    if not isinstance(horizon_minutes_cfg, list):
        horizon_minutes_cfg = [5, 30, 180]
    horizon_minutes = sorted({max(1, int(v)) for v in horizon_minutes_cfg})

    def _trusted_synthetic_event(event: dict[str, Any]) -> bool:
        return (
            bool(event.get("synthetic", False))
            and str(event.get("source_type", "")) == "clone_synthetic"
            and bool(event.get("counterclone_participant", False))
            and bool(event.get("counterclone_integrity_verified", False))
        )

    detector_events = [event for event in recent_events if not _trusted_synthetic_event(event)]
    rule_alerts = []
    baseline_alerts = []
    graph_anomalies = []
    honeypot_alerts = []
    mirror_alerts = []
    clone_deployments = []
    counter_clone_actions = []
    counter_clone_execution = []
    autonomous_recon_directives = []
    stage_two_counteroffensive_directives = []
    level_three_hunting_directives = []

    for event in detector_events:
        rule_alerts.extend(rules.evaluate(event))
        graph_anomalies.extend(graph_detector.evaluate(event))
        honeypot_alerts.extend(honeypot_detector.evaluate(event))
        mirror_alerts.extend(mirror_clone_detector.evaluate(event))
        host = event.get("host", "unknown")
        metrics = {
            "api_call_rate": float(event.get("api_call_count", 0) or 0),
            "network_egress": float(event.get("egress_mb", 0) or 0),
            "gpu_cpu": float(event.get("gpu_cpu", 0) or 0),
            "counterclone_activity": 1.0 if bool(event.get("counterclone_participant", False)) else 0.0,
        }
        if any(metrics.values()):
            baseline_alerts.extend(
                baseline.update_and_detect(
                    host,
                    metrics,
                    context={
                        "counterclone_participant": bool(event.get("counterclone_participant", False)),
                        "counterclone_integrity_verified": bool(event.get("counterclone_integrity_verified", False)),
                        "source_type": str(event.get("source_type", "unknown")),
                        "event_timestamp": str(event.get("@timestamp", "")),
                    },
                )
            )

    now_utc = datetime.now(timezone.utc)
    graph_horizon_summary: list[dict[str, Any]] = []
    active_horizons = 0
    for minutes in horizon_minutes:
        cutoff = now_utc - timedelta(minutes=minutes)
        horizon_events = [e for e in detector_events if parse_event_time(e) >= cutoff]
        horizon_anomalies = [a for a in graph_anomalies if parse_event_time(a.event) >= cutoff]
        anomaly_count = len(horizon_anomalies)
        peak_severity = max((a.severity for a in horizon_anomalies), default=0)
        if anomaly_count:
            active_horizons += 1
        graph_horizon_summary.append(
            {
                "minutes": minutes,
                "events": len(horizon_events),
                "graph_anomalies": anomaly_count,
                "peak_severity": peak_severity,
            }
        )

    correlated = correlator.correlate(rule_alerts, baseline_alerts)
    attack_chains = sequence_model.evaluate(detector_events)
    containment_result = None
    soar_actions = []
    blast_radius = blast_radius_analyzer.analyze(detector_events, topology)

    baseline_ready = all(len(values) >= baseline.min_history for values in baseline.series.values()) if baseline.series else False

    candidate_severity = 0
    if correlated:
        candidate_severity = correlated.severity
    if graph_anomalies:
        candidate_severity = max(candidate_severity, max(a.severity for a in graph_anomalies))
    if attack_chains:
        candidate_severity = max(candidate_severity, max(c.severity for c in attack_chains))
    if honeypot_alerts:
        candidate_severity = max(candidate_severity, max(a.severity for a in honeypot_alerts))
    if mirror_alerts:
        candidate_severity = max(candidate_severity, max(a.severity for a in mirror_alerts))
        deploy_threshold = int(settings.get("clone_deploy_severity_threshold", 75))
        for alert in mirror_alerts:
            if alert.severity >= deploy_threshold:
                deployment = mirror_clone_detector.deploy_counter_clone(alert)
                clone_deployments.append(deployment)
                planned_actions = mirror_clone_detector.execute_counter_clone(deployment)
                counter_clone_actions.extend(planned_actions)
                counter_clone_execution.extend(
                    execute_counter_clone_actions(
                        actions=[asdict(a) for a in planned_actions],
                        deployment=asdict(deployment),
                        containment=containment,
                        ingestor=ingestor,
                        audit=audit,
                        signature_bundle=_containment_signature(settings),
                    )
                )

    if active_horizons >= 2:
        candidate_severity = min(99, candidate_severity + 5)

    autonomous_recon_directives = [
        asdict(d)
        for d in mirror_clone_detector.generate_autonomous_recon_directives(
            max_directives=int(settings.get("autonomous_recon_max_directives", 4)),
            min_markov_score=float(settings.get("autonomous_recon_min_markov_score", 0.35)),
        )
    ]
    for directive in autonomous_recon_directives:
        planned_actions = mirror_clone_detector.execute_recon_directive(ReconDirective(**directive))
        counter_clone_actions.extend(planned_actions)
        counter_clone_execution.extend(
            execute_counter_clone_actions(
                actions=[asdict(a) for a in planned_actions],
                deployment={
                    "deployment_id": f"recon::{directive['shard']}",
                    "shard": directive["shard"],
                    "synthetic_probe_sequence": [
                        {
                            "host": directive["shard"].split("|", 1)[0].replace("host:", ""),
                            "action": "list",
                            "resource": "synthetic://hunter/recon",
                        }
                    ],
                },
                containment=containment,
                ingestor=ingestor,
                audit=audit,
                signature_bundle=_containment_signature(settings),
            )
        )

    stage_two_counteroffensive_directives = [
        asdict(d)
        for d in mirror_clone_detector.generate_stage_two_counteroffensive_directives(
            max_directives=int(settings.get("stage_two_max_directives", 2)),
            min_escalation_score=float(settings.get("stage_two_min_escalation_score", 0.45)),
        )
    ]
    for directive in stage_two_counteroffensive_directives:
        planned_actions = mirror_clone_detector.execute_stage_two_directive(StageTwoDirective(**directive))
        counter_clone_actions.extend(planned_actions)
        counter_clone_execution.extend(
            execute_counter_clone_actions(
                actions=[asdict(a) for a in planned_actions],
                deployment={
                    "deployment_id": f"stage2::{directive['shard']}",
                    "shard": directive["shard"],
                    "synthetic_probe_sequence": [],
                },
                containment=containment,
                ingestor=ingestor,
                audit=audit,
                signature_bundle=_containment_signature(settings),
            )
        )

    level_three_hunting_directives = [
        asdict(d)
        for d in mirror_clone_detector.generate_level_three_hunting_directives(
            max_directives=int(settings.get("level_three_max_directives", 2)),
            min_severity_score=float(settings.get("level_three_min_severity_score", 0.55)),
        )
    ]
    for directive in level_three_hunting_directives:
        planned_actions = mirror_clone_detector.execute_level_three_directive(LevelThreeDirective(**directive))
        counter_clone_actions.extend(planned_actions)
        counter_clone_execution.extend(
            execute_counter_clone_actions(
                actions=[asdict(a) for a in planned_actions],
                deployment={
                    "deployment_id": f"stage3::{directive['shard']}",
                    "shard": directive["shard"],
                    "synthetic_probe_sequence": [],
                },
                containment=containment,
                ingestor=ingestor,
                audit=audit,
                signature_bundle=_containment_signature(settings),
            )
        )

    immediate_honeypot_containment = any(alert.kill_chain_recommended for alert in honeypot_alerts)
    risk_confidence = compute_risk_confidence(
        candidate_severity,
        rule_alerts,
        baseline_alerts,
        graph_anomalies,
        attack_chains,
        honeypot_alerts,
        mirror_alerts,
        blast_radius.estimated_impact_score,
    )
    distributed_signal = distributed_attack_signal(detector_events)
    if distributed_signal["is_distributed"]:
        severity_boost = int(8 + distributed_signal["score"] * 12)
        candidate_severity = min(100, candidate_severity + severity_boost)
        risk_confidence = min(1.0, round(risk_confidence + 0.12 + distributed_signal["score"] * 0.10, 4))

    should_contain = False
    if immediate_honeypot_containment:
        should_contain = True
    elif candidate_severity and baseline_ready and candidate_severity >= int(settings.get("containment_severity_threshold", 70)):
        should_contain = True
    elif candidate_severity >= int(settings.get("fast_track_containment_threshold", 85)) and risk_confidence >= float(settings.get("fast_track_risk_confidence", 0.65)):
        should_contain = True
    elif (
        distributed_signal["is_distributed"]
        and candidate_severity >= int(settings.get("distributed_attack_containment_threshold", 78))
        and risk_confidence >= float(settings.get("distributed_attack_risk_confidence", 0.68))
    ):
        should_contain = True

    if should_contain:
        soar_actions = soar.run({"anomaly_detected": True, "data_exfil_flag": True})
        target_host = "unknown"
        if rule_alerts:
            target_host = rule_alerts[0].event.get("host", "unknown")
        elif honeypot_alerts:
            target_host = honeypot_alerts[0].event.get("host", "unknown")
        elif clone_deployments:
            target_host = clone_deployments[0].shard.split("|", 1)[0].replace("host:", "")

        requested_actions = [
            "disable_outbound_traffic",
            "revoke_rotate_api_keys",
            "quarantine_host",
            "forensic_snapshot_metadata",
        ]
        if immediate_honeypot_containment:
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
        elif candidate_severity >= int(settings.get("hard_response_action_threshold", 85)):
            requested_actions.extend([
                "sinkhole_suspicious_destinations",
                "block_lateral_movement_paths",
            ])

        simulation_mode = should_simulate_containment(
            settings,
            severity=candidate_severity,
            blast_radius_score=blast_radius.estimated_impact_score,
            immediate=immediate_honeypot_containment,
        )

        containment_result = containment.execute(
            host=target_host,
            severity=candidate_severity,
            requested_actions=requested_actions,
            approvals=list(settings.get("automated_approvers", ["user"])),
            simulation_mode=simulation_mode,
            hard_quarantine_threshold=int(settings.get("hard_quarantine_threshold", 90)),
            simulation_context={"blast_radius": asdict(blast_radius)},
            signature_bundle=_containment_signature(settings),
            confirmation_bundle=_containment_confirmation(settings),
        )

    state = {
        "topology": topology,
        "events_processed": len(recent_events),
        "alerts": [asdict(a) for a in rule_alerts],
        "baseline_anomalies": [asdict(a) for a in baseline_alerts],
        "graph_anomalies": [asdict(a) for a in graph_anomalies],
        "graph_horizon_summary": graph_horizon_summary,
        "persistent_horizon_activity": active_horizons >= 2,
        "attack_chains": [asdict(c) for c in attack_chains],
        "honeypot_alerts": [asdict(a) for a in honeypot_alerts],
        "mirror_alerts": [asdict(a) for a in mirror_alerts],
        "clone_deployments": [asdict(d) for d in clone_deployments],
        "counter_clone_actions": [asdict(a) for a in counter_clone_actions],
        "counter_clone_execution": counter_clone_execution,
        "autonomous_recon_directives": autonomous_recon_directives,
        "stage_two_counteroffensive_directives": stage_two_counteroffensive_directives,
        "level_three_hunting_directives": level_three_hunting_directives,
        "correlated": asdict(correlated) if correlated else None,
        "candidate_severity": candidate_severity,
        "risk_confidence": risk_confidence,
        "distributed_attack_signal": distributed_signal,
        "credential_blast_radius": asdict(blast_radius),
        "containment": asdict(containment_result) if containment_result else None,
        "baseline_ready": baseline_ready,
        "soar_actions": soar_actions,
        "contained_hosts": sorted(list(containment.contained_hosts)),
        "immediate_honeypot_containment": immediate_honeypot_containment,
    }
    audit.append("cycle_complete", state)
    return state


def run_forever(config_path: str = "config/config.yaml") -> None:
    settings = Settings.load(config_path)
    base_interval = float(settings.get("continuous_cycle_sleep_seconds", 0.25))
    baseline = BehavioralBaseline(
        threshold=float(settings.get("anomaly_threshold", 2.0)),
        window=int(settings.get("baseline_window", 30)),
        min_history=int(settings.get("baseline_min_history", 5)),
    )
    rules = RuleEngine(
        Path(settings.get("rules_path", "rules")),
        dedup_window_seconds=int(settings.get("alert_dedup_window_seconds", 300)),
    )
    correlator = AlertCorrelator()
    graph_detector = GraphAnomalyDetector(
        warmup_events=int(settings.get("graph_warmup_events", 5)),
        novelty_weight=float(settings.get("graph_novelty_weight", 1.6)),
        warmup_min_distinct_sources=int(settings.get("graph_warmup_min_distinct_sources", 2)),
        warmup_min_relations=int(settings.get("graph_warmup_min_relations", 1)),
    )
    sequence_model = AttackSequenceModel(
        chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30)),
        max_events_per_host=int(settings.get("attack_chain_max_events_per_host", 2048)),
        max_tracked_hosts=int(settings.get("attack_chain_max_tracked_hosts", 2048)),
    )
    honeypot_detector = HoneypotDetector(
        settings.get("honeypot_resources", []),
        settings.get("proto_agi_indicators", []),
    )
    mirror_clone_detector = MirrorCloneDetector(
        warmup_events=int(settings.get("clone_warmup_events", 6)),
        min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
        rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
        max_tracked_shards=int(settings.get("clone_max_tracked_shards", 2048)),
        max_actions_per_shard=int(settings.get("clone_max_actions_per_shard", 20000)),
    )
    out_of_band = settings.get("audit_out_of_band_path")
    audit = ImmutableAuditLog(out_of_band_path=Path(out_of_band) if out_of_band else None)
    mapper = AssetMapper(CloudProviderAdapter(simulated=bool(settings.get("simulated_mode", False))))
    ingestor = TelemetryIngestor(Path(settings.get("telemetry_index_path", "data/telemetry_index.jsonl")))
    containment = ContainmentEngine(
        audit,
        identity_store=settings.get("approval_identity_store", {}),
        required_approvals=int(settings.get("approval_quorum", 1)),
        hardware_key_verifier=_build_hardware_key_verifier(settings),
        human_confirmation_verifier=_build_human_confirmation_verifier(settings),
        action_executor=ContainmentActionExecutor(active_mode=bool(settings.get("containment_live_mode", False))),
    )
    while True:
        state = run_cycle(
            settings,
            baseline=baseline,
            rules=rules,
            correlator=correlator,
            graph_detector=graph_detector,
            sequence_model=sequence_model,
            honeypot_detector=honeypot_detector,
            mirror_clone_detector=mirror_clone_detector,
            audit=audit,
            mapper=mapper,
            ingestor=ingestor,
            containment=containment,
        )
        burst_threshold = int(settings.get("burst_cycle_severity_threshold", 80))
        burst_interval_seconds = float(settings.get("burst_cycle_seconds", 0.1))
        cycle_interval = burst_interval_seconds if state.get("candidate_severity", 0) >= burst_threshold else base_interval
        time.sleep(max(0.0, cycle_interval))


if __name__ == "__main__":
    run_forever()
