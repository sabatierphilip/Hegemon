from __future__ import annotations

import base64
import re
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
    """Flags interactions with decoy assets and scores adversarial tradecraft sophistication."""

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
        self._advanced_tactics = {
            "credential_dump": ["credential dump", "lsass", "token theft", "vault export"],
            "stealth_channel": ["dns tunnel", "covert channel", "domain fronting", "steganography"],
            "defense_evasion": ["disable edr", "tamper", "hook bypass", "unhook"],
            "lateral_movement": ["wmic", "pass-the-hash", "remote service create", "lateral"],
            "command_staging": ["powershell -enc", "base64", "living off the land", "lolbin"],
        }

    def _metadata_blob(self, event: dict[str, Any], *, lowercase: bool = True) -> str:
        metadata = event.get("metadata", {})
        fields = [
            str(event.get("action", "")),
            str(event.get("process", "")),
            str(event.get("user_agent", "")),
            str(event.get("message", "")),
            str(event.get("command_line", "")),
            str(metadata),
        ]
        blob = " ".join(fields)
        return blob.lower() if lowercase else blob

    def _normalize_blob(self, blob: str) -> str:
        """Normalize obfuscated text so basic separator/leet tricks cannot evade matching."""
        normalized = blob.lower()
        normalized = re.sub(r"[\s\-_.:/\\]+", "", normalized)
        translation = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
        return normalized.translate(translation)

    def _decode_embedded_base64(self, blob: str) -> str:
        chunks: list[str] = []
        for token in re.findall(r"[A-Za-z0-9+/=]{16,}", blob):
            candidate = token + "=" * ((4 - (len(token) % 4)) % 4)
            try:
                decoded = base64.b64decode(candidate, validate=True)
            except Exception:
                continue
            if not decoded:
                continue
            text = decoded.decode("utf-8", errors="ignore")
            if text and any(ch.isalpha() for ch in text):
                chunks.append(text)
        return " ".join(chunks).lower()

    def _match_advanced_tactics(self, blob: str) -> list[str]:
        matches = []
        for tactic, indicators in self._advanced_tactics.items():
            if any(marker in blob for marker in indicators):
                matches.append(tactic)
        return sorted(matches)

    def evaluate(self, event: dict[str, Any]) -> list[HoneypotAlert]:
        if not self.decoy_resources:
            return []

        resource = str(event.get("resource", "")).strip().lower()
        metadata_blob_raw = self._metadata_blob(event, lowercase=False)
        metadata_blob = metadata_blob_raw.lower()
        normalized_blob = self._normalize_blob(metadata_blob)
        decoded_blob = self._decode_embedded_base64(metadata_blob_raw)
        normalized_decoded_blob = self._normalize_blob(decoded_blob)

        matched_indicators = sorted(
            indicator
            for indicator in self.proto_agi_indicators
            if (
                indicator in metadata_blob
                or self._normalize_blob(indicator) in normalized_blob
                or indicator in decoded_blob
                or self._normalize_blob(indicator) in normalized_decoded_blob
            )
        )
        matched_tactics = self._match_advanced_tactics(metadata_blob)

        for decoy in self.decoy_resources:
            if decoy and (decoy in resource or decoy in metadata_blob):
                if matched_indicators:
                    classification = "proto_agi_honeypot_tripwire"
                    kill_chain_recommended = True
                    severity = 100
                    reason = f"Honeypot decoy triggered with proto-AGI indicators: {decoy}"
                elif len(matched_tactics) >= 2:
                    classification = "advanced_honeypot_intrusion"
                    kill_chain_recommended = True
                    severity = min(100, 96 + len(matched_tactics))
                    reason = f"Sophisticated decoy intrusion detected ({','.join(matched_tactics)}): {decoy}"
                else:
                    classification = "honeypot_tripwire"
                    kill_chain_recommended = False
                    severity = 99
                    reason = f"Honeypot resource touched: {decoy}"

                return [
                    HoneypotAlert(
                        resource=resource or "unknown",
                        severity=severity,
                        reason=reason,
                        classification=classification,
                        kill_chain_recommended=kill_chain_recommended,
                        matched_indicators=sorted(set(matched_indicators + matched_tactics)),
                        event=event,
                    )
                ]
        return []
