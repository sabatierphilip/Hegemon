from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from sentinel_containment.logging_layer.immutable_log import ImmutableAuditLog


class SoarEngine:
    def __init__(self, playbook_path: Path, audit_log: ImmutableAuditLog):
        self.playbook_path = playbook_path
        self.audit_log = audit_log
        with playbook_path.open("r", encoding="utf-8") as f:
            self.playbook = yaml.safe_load(f) or {}

    def run(self, context: dict[str, Any]) -> list[str]:
        actions_taken: list[str] = []
        for rule in self.playbook.get("playbooks", []):
            when = rule.get("when", {})
            if all(context.get(k) == v for k, v in when.items()):
                for step in rule.get("then", []):
                    action = step.get("action")
                    actions_taken.append(action)
                    self.audit_log.append("soar_action", {"action": action, "context": context})
        return actions_taken
