from pathlib import Path

import yaml

from sentinel_containment.containment.engine import ContainmentEngine
from sentinel_containment.containment.executors import ContainmentActionExecutor
from sentinel_containment.detection.rule_engine import RuleEngine
from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog
from sentinel_containment.security import HardwareKeyVerifier, HumanConfirmationVerifier


def test_sigma_like_rule_matching(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "sigma.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Sigma Test",
                "severity": 80,
                "detection": {
                    "sigma": {
                        "all_of": [
                            {"action": {"in": ["command_execute"]}},
                            {"command_line": {"regex": r"(?i)psexec"}},
                        ],
                        "any_of": [{"user": {"contains": "admin"}}],
                        "not": [{"command_line": {"contains": "known-good-maintenance"}}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    alerts = RuleEngine(rules_path=rules_path).evaluate(
        {"action": "command_execute", "command_line": "PsExec \\\\host", "user": "domain-admin"}
    )
    assert alerts
    assert alerts[0].rule == "Sigma Test"


def test_yara_like_min_hits(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "yara.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Yara Test",
                "severity": 90,
                "detection": {
                    "yara_like": {
                        "fields": ["command_line", "metadata"],
                        "strings": ["mimikatz", "sekurlsa", "lsass"],
                        "min_hits": 2,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    alerts = RuleEngine(rules_path=rules_path).evaluate(
        {"command_line": "mimikatz sekurlsa::logonpasswords", "metadata": "lsass access"}
    )
    assert alerts


def test_containment_executor_records_live_action_results(tmp_path):
    audit_path = tmp_path / "audit.log"
    log = ImmutableAuditLog(audit_path)
    engine = ContainmentEngine(
        log,
        hardware_key_verifier=HardwareKeyVerifier({}, fail_closed=False),
        human_confirmation_verifier=HumanConfirmationVerifier(shared_secret="", fail_closed=False),
        action_executor=ContainmentActionExecutor(active_mode=False),
    )
    res = engine.execute(
        host="host-a",
        severity=95,
        requested_actions=["disable_iam_sessions"],
        approvals=["user"],
        high_impact_threshold=100,
        action_context={"aws_role_name": "app-role"},
    )

    assert res.approved
    entries = [line for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert entries
    assert "action_results" in entries[-1]


def test_long_window_accumulation_detects_low_and_slow_exfil(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "slow.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Low-slow test",
                "severity": 87,
                "detection": {
                    "equals": {"action": "network_send"},
                    "long_window_accumulation": {
                        "metric": "egress_mb",
                        "identity_fields": ["host", "user", "process"],
                        "window_seconds": 7200,
                        "max_per_event": 80,
                        "min_events": 4,
                        "min_total": 140,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path)
    alerts = []
    for _ in range(5):
        alerts = engine.evaluate(
            {
                "action": "network_send",
                "host": "node-a",
                "user": "svc-worker",
                "process": "agent",
                "egress_mb": 40,
            }
        )

    assert alerts
    assert alerts[0].rule == "Low-slow test"


def test_long_window_accumulation_triggers_on_total_without_min_event_count(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "slow_or.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Low-slow total-only trigger",
                "severity": 90,
                "detection": {
                    "equals": {"action": "network_send"},
                    "long_window_accumulation": {
                        "metric": "egress_mb",
                        "identity_fields": ["host", "user", "process"],
                        "window_seconds": 7200,
                        "max_per_event": 80,
                        "min_events": 8,
                        "min_total": 140,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path)
    alerts = []
    for _ in range(3):
        alerts = engine.evaluate(
            {
                "action": "network_send",
                "host": "node-a",
                "user": "svc-worker",
                "process": "agent",
                "egress_mb": 70,
            }
        )

    assert alerts
    assert alerts[0].rule == "Low-slow total-only trigger"


def test_field_entropy_flags_dns_tunneling_payload(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "entropy.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Entropy DNS",
                "severity": 89,
                "detection": {
                    "equals": {"action": "dns_query"},
                    "field_entropy": {
                        "fields": ["resource"],
                        "min_length": 40,
                        "min_entropy": 3.8,
                        "min_fields": 1,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    alerts = RuleEngine(rules_path=rules_path).evaluate(
        {
            "action": "dns_query",
            "resource": "x9a2f8q1m7p3k0z5v4t1w8y6u2r9n3c7b5d8f0g2h4j6l.example.com",
        }
    )
    assert alerts
    assert alerts[0].rule == "Entropy DNS"



def test_windowed_count_detects_dns_tunneling_pattern(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "dns.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "DNS tunnel test",
                "severity": 86,
                "detection": {
                    "equals": {"action": "dns_query"},
                    "windowed_count": {
                        "field": "metadata.dns_query_name",
                        "identity_field": "host",
                        "window_seconds": 3600,
                        "count_threshold": 3,
                    },
                    "additional_checks": [
                        {"field": "metadata.dns_query_length", "greater_than": 30},
                        {"field": "metadata.dns_record_type", "equals": "TXT"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path)
    alerts = []
    seen = []
    for i in range(3):
        alerts = engine.evaluate(
            {
                "action": "dns_query",
                "host": "node-a",
                "metadata": {
                    "dns_query_name": f"x{i}.exfil.example",
                    "dns_query_length": 70,
                    "dns_record_type": "TXT",
                },
            }
        )
        seen.extend(alerts)

    assert seen
    assert seen[0].rule == "DNS tunnel test"

def test_long_window_accumulation_catches_patient_high_volume_exfil(tmp_path):
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "slow.yaml").write_text(
        yaml.safe_dump(
            {
                "title": "Low-slow patient exfil",
                "severity": 87,
                "detection": {
                    "equals": {"action": "network_send"},
                    "long_window_accumulation": {
                        "metric": "egress_mb",
                        "identity_fields": ["host", "user", "process"],
                        "window_seconds": 21600,
                        "max_per_event": 80,
                        "min_events": 8,
                        "min_total": 300,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    engine = RuleEngine(rules_path=rules_path)
    alerts = []
    for _ in range(12):
        alerts.extend(engine.evaluate(
            {
                "action": "network_send",
                "host": "node-a",
                "user": "svc-worker",
                "process": "agent",
                "egress_mb": 79,
            }
        ))

    assert alerts
    assert alerts[0].rule == "Low-slow patient exfil"
