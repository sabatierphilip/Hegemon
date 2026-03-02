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
