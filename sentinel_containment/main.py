from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.blast_radius import CredentialBlastRadiusAnalyzer
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.mirror_clone import MirrorCloneDetector
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.honeypot import HoneypotDetector
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.soar.workflow import SoarEngine
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


CLONE_ALLOWED_SYNTHETIC_ACTIONS = {"read", "list", "model_invoke"}


def execute_counter_clone_actions(
    actions: list[dict[str, Any]],
    deployment: dict[str, Any],
    containment: ContainmentEngine,
    ingestor: TelemetryIngestor,
    audit: ImmutableAuditLog,
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
            )
            _record(action, target, "executed", {"approved": result.approved, "actions": result.actions_executed})
            continue

        if action == "block_simulated_path":
            _record(action, target, "simulated", {"rule": "egress_sinkhole", "applied": True})
            continue

        if action == "emit_synthetic_probe":
            sequence = deployment.get("synthetic_probe_sequence", [])
            probe = next((p for p in sequence if str(p.get("resource", "")) == target), None)
            probe_action = str((probe or {}).get("action", "unknown")).strip().lower()
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
                    "clone_deployment_id": deployment.get("deployment_id", "unknown"),
                },
            )
            _record(action, target, "executed", {"event_action": probe_action})
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
                            "clone_deployment_id": deployment.get("deployment_id", "unknown"),
                        },
                    )
                _record(action, target, "executed", {"definition": "baseline_cover_traffic"})
            else:
                _record(action, target, "executed", {"phase": "acknowledged"})
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


def run_cycle(
    settings: Settings,
    baseline: BehavioralBaseline | None = None,
    rules: RuleEngine | None = None,
    correlator: AlertCorrelator | None = None,
    graph_detector: GraphAnomalyDetector | None = None,
    sequence_model: AttackSequenceModel | None = None,
    honeypot_detector: HoneypotDetector | None = None,
    mirror_clone_detector: MirrorCloneDetector | None = None,
) -> dict:
    out_of_band = settings.get("audit_out_of_band_path")
    audit = ImmutableAuditLog(out_of_band_path=Path(out_of_band) if out_of_band else None)
    mapper = AssetMapper(CloudProviderAdapter(simulated=bool(settings.get("simulated_mode", False))))
    topology = mapper.snapshot()

    ingestor = TelemetryIngestor(Path(settings.get("telemetry_index_path", "data/telemetry_index.jsonl")))
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
    )
    sequence_model = sequence_model or AttackSequenceModel(
        chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30))
    )
    honeypot_detector = honeypot_detector or HoneypotDetector(
        settings.get("honeypot_resources", []),
        settings.get("proto_agi_indicators", []),
    )
    mirror_clone_detector = mirror_clone_detector or MirrorCloneDetector(
        warmup_events=int(settings.get("clone_warmup_events", 6)),
        min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
        rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
    )
    containment = ContainmentEngine(
        audit,
        identity_store=settings.get("approval_identity_store", {}),
        required_approvals=int(settings.get("approval_quorum", 1)),
    )
    blast_radius_analyzer = CredentialBlastRadiusAnalyzer()
    soar = SoarEngine(Path(settings.get("playbook_path", "playbooks/default_playbook.yaml")), audit)

    recent_events = ingestor.read_recent(limit=int(settings.get("telemetry_batch_limit", 200)))
    detector_events = [event for event in recent_events if not bool(event.get("synthetic", False))]
    rule_alerts = []
    baseline_alerts = []
    graph_anomalies = []
    honeypot_alerts = []
    mirror_alerts = []
    clone_deployments = []
    counter_clone_actions = []
    counter_clone_execution = []

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
                        "source_type": str(event.get("source_type", "unknown")),
                    },
                )
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
    should_contain = False
    if immediate_honeypot_containment:
        should_contain = True
    elif candidate_severity and baseline_ready and candidate_severity >= int(settings.get("containment_severity_threshold", 70)):
        should_contain = True
    elif candidate_severity >= int(settings.get("fast_track_containment_threshold", 85)) and risk_confidence >= float(settings.get("fast_track_risk_confidence", 0.65)):
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
        )

    state = {
        "topology": topology,
        "events_processed": len(recent_events),
        "alerts": [asdict(a) for a in rule_alerts],
        "baseline_anomalies": [asdict(a) for a in baseline_alerts],
        "graph_anomalies": [asdict(a) for a in graph_anomalies],
        "attack_chains": [asdict(c) for c in attack_chains],
        "honeypot_alerts": [asdict(a) for a in honeypot_alerts],
        "mirror_alerts": [asdict(a) for a in mirror_alerts],
        "clone_deployments": [asdict(d) for d in clone_deployments],
        "counter_clone_actions": [asdict(a) for a in counter_clone_actions],
        "counter_clone_execution": counter_clone_execution,
        "correlated": asdict(correlated) if correlated else None,
        "candidate_severity": candidate_severity,
        "risk_confidence": risk_confidence,
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
    )
    sequence_model = AttackSequenceModel(chain_window_minutes=int(settings.get("attack_chain_window_minutes", 30)))
    honeypot_detector = HoneypotDetector(
        settings.get("honeypot_resources", []),
        settings.get("proto_agi_indicators", []),
    )
    mirror_clone_detector = MirrorCloneDetector(
        warmup_events=int(settings.get("clone_warmup_events", 6)),
        min_prediction_confidence=float(settings.get("clone_min_prediction_confidence", 0.65)),
        rapid_clone_minutes=int(settings.get("clone_rapid_deploy_minutes", 3)),
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
        )
        burst_threshold = int(settings.get("burst_cycle_severity_threshold", 80))
        burst_interval_seconds = float(settings.get("burst_cycle_seconds", 0.1))
        cycle_interval = burst_interval_seconds if state.get("candidate_severity", 0) >= burst_threshold else base_interval
        time.sleep(max(0.0, cycle_interval))


if __name__ == "__main__":
    run_forever()
