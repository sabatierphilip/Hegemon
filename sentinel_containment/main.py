from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path

from sentinel_containment.asset_mapper.discovery import AssetMapper
from sentinel_containment.cloud.provider import CloudProviderAdapter
from sentinel_containment.config import Settings
from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.detection.baseline import BehavioralBaseline
from sentinel_containment.detection.correlator import AlertCorrelator
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.soar.workflow import SoarEngine
from sentinel_containment.telemetry.ingestor import TelemetryIngestor


def run_cycle(
    settings: Settings,
    baseline: BehavioralBaseline | None = None,
    rules: RuleEngine | None = None,
    correlator: AlertCorrelator | None = None,
) -> dict:
    audit = ImmutableAuditLog()
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
    containment = ContainmentEngine(audit)
    soar = SoarEngine(Path(settings.get("playbook_path", "playbooks/default_playbook.yaml")), audit)

    recent_events = ingestor.read_recent(limit=int(settings.get("telemetry_batch_limit", 200)))
    rule_alerts = []
    baseline_alerts = []

    for event in recent_events:
        rule_alerts.extend(rules.evaluate(event))
        host = event.get("host", "unknown")
        metrics = {
            "api_call_rate": float(event.get("api_call_count", 0) or 0),
            "network_egress": float(event.get("egress_mb", 0) or 0),
            "gpu_cpu": float(event.get("gpu_cpu", 0) or 0),
        }
        if any(metrics.values()):
            baseline_alerts.extend(baseline.update_and_detect(host, metrics))

    correlated = correlator.correlate(rule_alerts, baseline_alerts)
    containment_result = None
    soar_actions = []

    baseline_ready = all(len(values) >= baseline.min_history for values in baseline.series.values()) if baseline.series else False

    if correlated and baseline_ready and correlated.severity >= int(settings.get("containment_severity_threshold", 70)):
        soar_actions = soar.run({"anomaly_detected": True, "data_exfil_flag": True})
        target_host = "unknown"
        if rule_alerts:
            target_host = rule_alerts[0].event.get("host", "unknown")
        containment_result = containment.execute(
            host=target_host,
            severity=correlated.severity,
            requested_actions=[
                "disable_outbound_traffic",
                "revoke_rotate_api_keys",
                "quarantine_host",
                "forensic_snapshot_metadata",
            ],
            approvals=["alice", "bob"],
        )

    state = {
        "topology": topology,
        "events_processed": len(recent_events),
        "alerts": [asdict(a) for a in rule_alerts],
        "baseline_anomalies": [asdict(a) for a in baseline_alerts],
        "correlated": asdict(correlated) if correlated else None,
        "containment": asdict(containment_result) if containment_result else None,
        "baseline_ready": baseline_ready,
        "soar_actions": soar_actions,
        "contained_hosts": sorted(list(containment.contained_hosts)),
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
