from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog


@dataclass
class ContainmentResult:
    approved: bool
    actions_executed: list[str]
    message: str


class ContainmentEngine:
    def __init__(self, audit_log: ImmutableAuditLog):
        self.audit_log = audit_log
        self.contained_hosts: set[str] = set()

    def execute(
        self,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        high_impact_threshold: int = 80,
    ) -> ContainmentResult:
        if severity >= high_impact_threshold and len(set(approvals)) < 2:
            self.audit_log.append("containment_denied", {
                "host": host,
                "severity": severity,
                "requested_actions": requested_actions,
                "reason": "two_person_approval_required",
            })
            return ContainmentResult(False, [], "Containment denied: two-person approval required")

        safe_actions = {
            "disable_outbound_traffic",
            "revoke_rotate_api_keys",
            "disable_iam_sessions",
            "quarantine_host",
            "pause_model_serving_container",
            "forensic_snapshot_metadata",
        }

        executed = [a for a in requested_actions if a in safe_actions]
        if "quarantine_host" in executed:
            self.contained_hosts.add(host)

        self.audit_log.append("containment_executed", {
            "host": host,
            "severity": severity,
            "actions": executed,
            "approvals": approvals,
            "reversible": True,
            "offensive_actions": False,
        })
        return ContainmentResult(True, executed, "Containment actions executed")
