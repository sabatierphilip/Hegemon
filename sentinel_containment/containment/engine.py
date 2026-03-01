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
    def __init__(self, audit_log: ImmutableAuditLog, identity_store: dict[str, list[str]] | None = None):
        self.audit_log = audit_log
        self.contained_hosts: set[str] = set()
        self.identity_store = identity_store or {}
        self._alias_lookup = self._build_alias_lookup(self.identity_store)

    def execute(
        self,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        high_impact_threshold: int = 80,
        simulation_mode: bool = True,
        hard_quarantine_threshold: int = 90,
        simulation_context: dict[str, Any] | None = None,
    ) -> ContainmentResult:
        unique_approvers = self._normalize_approvals(approvals)
        if severity >= high_impact_threshold and len(unique_approvers) < 2:
            self.audit_log.append("containment_denied", {
                "host": host,
                "severity": severity,
                "requested_actions": requested_actions,
                "reason": "two_person_approval_required",
                "normalized_approvals": sorted(unique_approvers),
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
        quarantine_requested = "quarantine_host" in executed

        if quarantine_requested and simulation_mode:
            simulation = self._simulate_quarantine(host, severity, simulation_context or {})
            self.audit_log.append("containment_simulated", simulation)

            if severity < hard_quarantine_threshold:
                executed.remove("quarantine_host")
                executed.append("simulate_quarantine_host")

        if "quarantine_host" in executed:
            self.contained_hosts.add(host)

        self.audit_log.append("containment_executed", {
            "host": host,
            "severity": severity,
            "actions": executed,
            "approvals": approvals,
            "normalized_approvals": sorted(unique_approvers),
            "reversible": True,
            "offensive_actions": False,
            "simulation_mode": simulation_mode,
        })
        return ContainmentResult(True, executed, "Containment actions executed")

    def _simulate_quarantine(self, host: str, severity: int, context: dict[str, Any]) -> dict[str, Any]:
        blast_radius = context.get("blast_radius", {})
        impacted_hosts = blast_radius.get("impacted_hosts", [])
        impacted_assets = blast_radius.get("impacted_resources", [])
        return {
            "host": host,
            "severity": severity,
            "estimated_service_impact": "medium" if severity < 90 else "high",
            "lateral_hosts_at_risk": impacted_hosts,
            "dependent_assets_at_risk": impacted_assets,
            "recommendation": "Proceed with hard quarantine" if severity >= 90 else "Continue monitored containment",
        }

    @staticmethod
    def _normalize_identity(identity: str) -> str:
        return "".join(ch for ch in identity.strip().lower() if ch.isalnum() or ch in {"@", "."})

    def _build_alias_lookup(self, identity_store: dict[str, list[str]]) -> dict[str, str]:
        lookup: dict[str, str] = {}
        for canonical, aliases in identity_store.items():
            canonical_norm = self._normalize_identity(canonical)
            lookup[canonical_norm] = canonical_norm
            for alias in aliases:
                lookup[self._normalize_identity(alias)] = canonical_norm
        return lookup

    def _normalize_approvals(self, approvals: list[str]) -> set[str]:
        normalized = set()
        for identity in approvals:
            key = self._normalize_identity(identity)
            normalized.add(self._alias_lookup.get(key, key))
        return {n for n in normalized if n}
