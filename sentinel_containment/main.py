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


def run_cycle(settings: Settings) -> dict:
    audit = ImmutableAuditLog()
    mapper = AssetMapper(CloudProviderAdapter(simulated=settings.get("simulated_mode", True)))
    topology = mapper.snapshot()

    ingestor = TelemetryIngestor()
    baseline = BehavioralBaseline(threshold=float(settings.get("anomaly_threshold", 2.0)))
    rules = RuleEngine(Path(settings.get("rules_path", "rules")))
    correlator = AlertCorrelator()
    containment = ContainmentEngine(audit)
    soar = SoarEngine(Path(settings.get("playbook_path", "playbooks/default_playbook.yaml")), audit)

    sample_event = ingestor.ingest("model_api", {
        "host": "sim-model-1",
        "user": "service-account",
        "process": "model-gateway",
        "action": "model_invoke",
        "resource": "llm-safe-v1",
        "api_call_count": 800,
        "egress_mb": 900,
    })

    rule_alerts = rules.evaluate(sample_event)
    baseline_alerts = baseline.update_and_detect("sim-model-1", {
        "api_call_rate": sample_event.get("api_call_count", 0),
        "network_egress": sample_event.get("egress_mb", 0),
        "gpu_cpu": 95,
    })

    correlated = correlator.correlate(rule_alerts, baseline_alerts)
    containment_result = None
    soar_actions = []
    if correlated and correlated.severity >= int(settings.get("containment_severity_threshold", 70)):
        soar_actions = soar.run({"anomaly_detected": True, "data_exfil_flag": True})
        containment_result = containment.execute(
            host="sim-model-1",
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
        "alerts": [asdict(a) for a in rule_alerts],
        "baseline_anomalies": [asdict(a) for a in baseline_alerts],
        "correlated": asdict(correlated) if correlated else None,
        "containment": asdict(containment_result) if containment_result else None,
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
