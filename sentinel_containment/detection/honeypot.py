from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class HoneypotAlert:
    resource: str
    severity: int
    reason: str
    classification: str
    kill_chain_recommended: bool
    matched_indicators: list[str]
    event: dict[str, Any]


class HoneypotDetector:
    """Flags interactions with decoy assets that should never be touched."""

    def __init__(self, decoy_resources: list[str] | None = None, proto_agi_indicators: list[str] | None = None):
        self.decoy_resources = {resource.strip().lower() for resource in (decoy_resources or []) if resource.strip()}
        default_indicators = [
            "recursive self-improvement",
            "autonomous replication",
            "policy evasion",
            "self-preservation directive",
            "sandbox escape",
            "compute hoarding",
        ]
        indicators = proto_agi_indicators or default_indicators
        self.proto_agi_indicators = {indicator.strip().lower() for indicator in indicators if indicator.strip()}

    def _metadata_blob(self, event: dict[str, Any]) -> str:
        metadata = event.get("metadata", {})
        fields = [
            str(event.get("action", "")),
            str(event.get("process", "")),
            str(event.get("user_agent", "")),
            str(event.get("message", "")),
            str(metadata),
        ]
        return " ".join(fields).lower()

    def evaluate(self, event: dict[str, Any]) -> list[HoneypotAlert]:
        if not self.decoy_resources:
            return []

        resource = str(event.get("resource", "")).strip().lower()
        metadata_blob = self._metadata_blob(event)
        matched_indicators = sorted(indicator for indicator in self.proto_agi_indicators if indicator in metadata_blob)

        for decoy in self.decoy_resources:
            if decoy and (decoy in resource or decoy in metadata_blob):
                classification = "proto_agi_honeypot_tripwire" if matched_indicators else "honeypot_tripwire"
                kill_chain_recommended = bool(matched_indicators)
                return [
                    HoneypotAlert(
                        resource=resource or "unknown",
                        severity=100 if kill_chain_recommended else 99,
                        reason=f"Honeypot resource touched: {decoy}",
                        classification=classification,
                        kill_chain_recommended=kill_chain_recommended,
                        matched_indicators=matched_indicators,
                        event=event,
                    )
                ]
        return []
