"""Phase 7 controlled containment capability matrix."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class CapabilityRule:
    min_quorum: int
    require_human_hmac: bool


DEFAULT_CAPABILITY_MATRIX: Dict[str, CapabilityRule] = {
    "kill_process": CapabilityRule(min_quorum=2, require_human_hmac=True),
    "network_block": CapabilityRule(min_quorum=1, require_human_hmac=True),
}


class ContainmentPolicyError(RuntimeError):
    pass


class ContainmentPolicyEngine:
    def __init__(self, matrix: Dict[str, CapabilityRule] | None = None) -> None:
        self.matrix = matrix or DEFAULT_CAPABILITY_MATRIX

    def validate_action_requirements(self, action_type: str, provided_quorum: int, human_hmac_present: bool) -> None:
        rule = self.matrix.get(action_type)
        if not rule:
            raise ContainmentPolicyError(f"action not in capability matrix: {action_type}")
        if provided_quorum < rule.min_quorum:
            raise ContainmentPolicyError(
                f"insufficient quorum for action {action_type}: {provided_quorum} < {rule.min_quorum}"
            )
        if rule.require_human_hmac and not human_hmac_present:
            raise ContainmentPolicyError(f"human hmac required for action {action_type}")
