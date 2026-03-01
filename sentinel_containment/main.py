from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.blast_radius import CredentialBlastRadiusAnalyzer
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.attack_sequence import AttackSequenceModel
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.graph_anomaly import GraphAnomalyDetector
from sentinel_containment.detection.honeypot import HoneypotDetector
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.soar.workflow import SoarEngine
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


def run_cycle(
    settings: Settings,
    baseline: BehavioralBaseline | None = None,
    rules: RuleEngine | None = None,
    correlator: AlertCorrelator | None = None,
    graph_detector: GraphAnomalyDetector | None = None,
    sequence_model: AttackSequenceModel | None = None,
    honeypot_detector: HoneypotDetector | None = None,
) -> dict:
    out_of_band = settings.get("audit_out_of_band_path")
    audit = ImmutableAuditLog(out_of_band_path=Path(out_of_band) if out_of_band else None)
    mapper = AssetMapper(CloudProviderAdapter(simulated=settings.get("simulated_mode", False)))
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
    containment = ContainmentEngine(audit, identity_store=settings.get("approval_identity_store", {}))
    blast_radius_analyzer = CredentialBlastRadiusAnalyzer()
    soar = SoarEngine(Path(settings.get("playbook_path", "playbooks/default_playbook.yaml")), audit)

    recent_events = ingestor.read_recent(limit=int(settings.get("telemetry_batch_limit", 200)))
    rule_alerts = []
    baseline_alerts = []
    graph_anomalies = []
    honeypot_alerts = []

    for event in recent_events:
        rule_alerts.extend(rules.evaluate(event))
        graph_anomalies.extend(graph_detector.evaluate(event))
        honeypot_alerts.extend(honeypot_detector.evaluate(event))
        host = event.get("host", "unknown")
        metrics = {
            "api_call_rate": float(event.get("api_call_count", 0) or 0),
            "network_egress": float(event.get("egress_mb", 0) or 0),
            "gpu_cpu": float(event.get("gpu_cpu", 0) or 0),
        }
        if any(metrics.values()):
            baseline_alerts.extend(baseline.update_and_detect(host, metrics))

    correlated = correlator.correlate(rule_alerts, baseline_alerts)
    attack_chains = sequence_model.evaluate(recent_events)
    containment_result = None
    soar_actions = []
    blast_radius = blast_radius_analyzer.analyze(recent_events, topology)

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

    immediate_honeypot_containment = any(alert.kill_chain_recommended for alert in honeypot_alerts)
    should_contain = False
    if immediate_honeypot_containment:
        should_contain = True
    elif candidate_severity and baseline_ready and candidate_severity >= int(settings.get("containment_severity_threshold", 70)):
        should_contain = True

    if should_contain:
        soar_actions = soar.run({"anomaly_detected": True, "data_exfil_flag": True})
        target_host = "unknown"
        if rule_alerts:
            target_host = rule_alerts[0].event.get("host", "unknown")
        elif honeypot_alerts:
            target_host = honeypot_alerts[0].event.get("host", "unknown")

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
                "quarantine_host",
                "forensic_snapshot_metadata",
            ]

        containment_result = containment.execute(
            host=target_host,
            severity=candidate_severity,
            requested_actions=requested_actions,
            approvals=["alice", "bob"],
            simulation_mode=bool(settings.get("containment_simulation_mode", True)) and not immediate_honeypot_containment,
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
        "correlated": asdict(correlated) if correlated else None,
        "candidate_severity": candidate_severity,
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
    interval = int(settings.get("refresh_minutes", 5)) * 60
    while True:
        run_cycle(settings)
        time.sleep(interval)


if __name__ == "__main__":
    run_forever()
