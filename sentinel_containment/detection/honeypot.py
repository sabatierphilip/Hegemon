from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HoneypotAlert:
    resource: str
    severity: int
    reason: str
    event: dict[str, Any]


class HoneypotDetector:
    """Flags interactions with decoy assets that should never be touched."""

    def __init__(self, decoy_resources: list[str] | None = None):
        self.decoy_resources = {resource.strip().lower() for resource in (decoy_resources or []) if resource.strip()}

    def evaluate(self, event: dict[str, Any]) -> list[HoneypotAlert]:
        if not self.decoy_resources:
            return []

        resource = str(event.get("resource", "")).strip().lower()
        metadata = event.get("metadata", {})
        metadata_blob = str(metadata).lower()

        for decoy in self.decoy_resources:
            if decoy and (decoy in resource or decoy in metadata_blob):
                return [
                    HoneypotAlert(
                        resource=resource or "unknown",
                        severity=99,
                        reason=f"Honeypot resource touched: {decoy}",
                        event=event,
                    )
                ]
        return []
