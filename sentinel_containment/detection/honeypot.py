from __future__ import annotations

import base64
import hashlib
import re
from collections import defaultdict, deque
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
    identifier_codes: list[str]
    pinger_lines: list[str]
    hegemon_ping: bool
    event: dict[str, Any]


class HoneypotDetector:
    """Flags interactions with decoy assets and instrumented resources, then escalates on malicious usage patterns."""

    def __init__(
        self,
        decoy_resources: list[str] | None = None,
        proto_agi_indicators: list[str] | None = None,
        p2p_threat_patterns: list[str] | None = None,
    ):
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
            "anti_forensics": ["clear logs", "log tamper", "artifact wipe", "history -c"],
            "identity_spoofing": ["token swap", "session hijack", "impersonate", "spoof"],
        }
        self._p2p_threat_patterns = {
            marker.strip().lower()
            for marker in (
                p2p_threat_patterns
                or [
                    "rogue_agent",
                    "self-replication",
                    "c2 beacon",
                    "credential harvest",
                    "llm jailbreak",
                    "policy bypass",
                ]
            )
            if marker.strip()
        }
        self._identifier_registry: dict[str, str] = {}
        self._resource_pinger_registry: dict[str, str] = {}
        self._recent_identifier_hits: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=12))
        self._recent_p2p_pattern_hits: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=32))

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

    def _build_identifier_code(self, event: dict[str, Any]) -> str:
        identity_fields = [
            str(event.get("host", "unknown")),
            str(event.get("user", "unknown")),
            str(event.get("process", "unknown")),
            str(event.get("os", event.get("platform", "unknown"))),
            str(event.get("device_id", event.get("agent_id", "unknown"))),
        ]
        identity_seed = "|".join(value.strip().lower() for value in identity_fields)
        digest = hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:14].upper()
        return f"HGID-{digest}"

    def _build_resource_pinger_line(self, resource: str) -> str:
        normalized = resource.strip().lower() or "unknown"
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12].upper()
        return f"HGPING-{digest}"

    def _identifier_signals(self, event: dict[str, Any], metadata_blob: str) -> tuple[list[str], bool]:
        identifier_code = self._build_identifier_code(event)
        identity_key = str(event.get("host", "unknown")).strip().lower() + "|" + str(event.get("user", "unknown")).strip().lower()
        self._identifier_registry.setdefault(identity_key, identifier_code)

        metadata = event.get("metadata", {})
        identifier_fields = [
            str(event.get("identifier_code", "")),
            str(event.get("canary_id", "")),
            str(metadata.get("identifier_code", "")) if isinstance(metadata, dict) else "",
            str(metadata.get("canary_id", "")) if isinstance(metadata, dict) else "",
            str(metadata.get("resource_tag", "")) if isinstance(metadata, dict) else "",
        ]
        normalized_fields = [field.strip().upper() for field in identifier_fields if field and field.strip()]
        hits = sorted({value for value in normalized_fields if value.startswith("HGID-") or value == identifier_code})

        if hits:
            timestamp = float(event.get("@ts_epoch", 0) or 0)
            self._recent_identifier_hits[identity_key].append(timestamp)
        repeated_touch = len(self._recent_identifier_hits[identity_key]) >= 3
        blob_mentions_identifier = "hgid-" in metadata_blob
        hegemon_ping = bool(hits or blob_mentions_identifier or repeated_touch)
        if hegemon_ping and identifier_code not in hits:
            hits.append(identifier_code)
        return sorted(set(hits)), hegemon_ping

    def _resource_pinger_signals(self, event: dict[str, Any], metadata_blob: str) -> tuple[list[str], bool]:
        resource = str(event.get("resource", "unknown")).strip().lower()
        pinger_line = self._build_resource_pinger_line(resource)
        self._resource_pinger_registry.setdefault(resource, pinger_line)

        metadata = event.get("metadata", {})
        candidate_fields = [
            str(event.get("pinger_line", "")),
            str(event.get("resource_tag", "")),
            str(metadata.get("pinger_line", "")) if isinstance(metadata, dict) else "",
            str(metadata.get("resource_tag", "")) if isinstance(metadata, dict) else "",
        ]
        normalized = [field.strip().upper() for field in candidate_fields if field and field.strip()]
        hits = sorted({value for value in normalized if value.startswith("HGPING-") or value == pinger_line})
        blob_mentions = "hgping-" in metadata_blob
        if blob_mentions and pinger_line not in hits:
            hits.append(pinger_line)
        return sorted(set(hits)), bool(hits)

    def _normalize_pattern(self, value: str) -> str:
        mapped = value.lower()
        mapped = mapped.replace("two", "2").replace("to", "2")
        mapped = mapped.replace("zero", "0").replace("one", "1")
        return self._normalize_blob(mapped)

    def _obfuscated_pattern_regex(self, value: str) -> re.Pattern[str] | None:
        normalized = "".join(ch for ch in value.lower() if ch.isalnum())
        if not normalized:
            return None
        escaped = [re.escape(ch) for ch in normalized]
        pattern = r"[^a-z0-9]*".join(escaped)
        return re.compile(pattern)

    def _p2p_dynamic_pattern_matches(self, event: dict[str, Any], metadata_blob: str, decoded_blob: str) -> list[str]:
        action = str(event.get("action", "")).strip().lower()
        resource = str(event.get("resource", "")).strip().lower()
        search_blob = f"{metadata_blob} {decoded_blob} {action} {resource}"
        normalized_search_blob = self._normalize_blob(search_blob)

        matches: list[str] = []
        for pattern in sorted(self._p2p_threat_patterns):
            normalized_pattern = self._normalize_pattern(pattern)
            compact_pattern = "".join(ch for ch in pattern.lower() if ch.isalnum())
            regex = self._obfuscated_pattern_regex(pattern)
            if (
                pattern in search_blob
                or normalized_pattern in normalized_search_blob
                or compact_pattern in normalized_search_blob
                or (regex is not None and regex.search(self._normalize_blob(search_blob)) is not None)
            ):
                matches.append(pattern)
        if matches:
            shard = str(event.get("host", "unknown")).strip().lower()
            for match in matches:
                self._recent_p2p_pattern_hits[shard].append(match)
        return matches

    def _proto_agi_indicator_matches(
        self,
        metadata_blob: str,
        normalized_metadata_blob: str,
        decoded_blob: str,
        normalized_decoded_blob: str,
    ) -> list[str]:
        matches: list[str] = []
        combined_blob = f"{metadata_blob} {decoded_blob}".strip()
        normalized_combined_blob = self._normalize_blob(combined_blob)
        for indicator in sorted(self.proto_agi_indicators):
            normalized_indicator = self._normalize_pattern(indicator)
            compact_indicator = "".join(ch for ch in indicator.lower() if ch.isalnum())
            regex = self._obfuscated_pattern_regex(indicator)
            if (
                indicator in metadata_blob
                or normalized_indicator in normalized_metadata_blob
                or indicator in decoded_blob
                or normalized_indicator in normalized_decoded_blob
                or compact_indicator in normalized_combined_blob
                or (regex is not None and regex.search(normalized_combined_blob) is not None)
            ):
                matches.append(indicator)
        return matches

    def evaluate(self, event: dict[str, Any]) -> list[HoneypotAlert]:
        resource = str(event.get("resource", "")).strip().lower()
        metadata_blob_raw = self._metadata_blob(event, lowercase=False)
        metadata_blob = metadata_blob_raw.lower()
        normalized_blob = self._normalize_blob(metadata_blob)
        decoded_blob = self._decode_embedded_base64(metadata_blob_raw)
        normalized_decoded_blob = self._normalize_blob(decoded_blob)
        identifier_codes, identifier_ping = self._identifier_signals(event, metadata_blob)
        pinger_lines, pinger_ping = self._resource_pinger_signals(event, metadata_blob)
        p2p_pattern_hits = self._p2p_dynamic_pattern_matches(event, metadata_blob, decoded_blob)

        matched_indicators = self._proto_agi_indicator_matches(
            metadata_blob,
            normalized_blob,
            decoded_blob,
            normalized_decoded_blob,
        )
        matched_tactics = self._match_advanced_tactics(metadata_blob)
        is_decoy_trip = any(decoy and (decoy in resource or decoy in metadata_blob) for decoy in self.decoy_resources)

        # Networked pinger mode: any resource may become a trap when p2p threat intelligence and pinger lines align.
        p2p_pressure = len(p2p_pattern_hits)
        dynamic_malicious_usage = p2p_pressure >= 2 or (p2p_pressure >= 1 and len(matched_tactics) >= 1)
        hegemon_ping = identifier_ping or pinger_ping or dynamic_malicious_usage

        if matched_indicators and (is_decoy_trip or dynamic_malicious_usage):
            classification = "proto_agi_honeypot_tripwire"
            kill_chain_recommended = True
            severity = 100
            reason = "Honeypot decoy/instrumented resource triggered with proto-AGI indicators"
        elif dynamic_malicious_usage and pinger_ping:
            classification = "p2p_instrumented_resource_breach"
            kill_chain_recommended = True
            severity = min(100, 94 + p2p_pressure + len(matched_tactics))
            reason = "Pinger lines matched dynamic P2P malicious patterns; trigger hegemon investigation + hunter/clone dispatch"
        elif is_decoy_trip and hegemon_ping and (len(matched_tactics) >= 1 or identifier_codes or pinger_lines):
            classification = "instrumented_honeypot_breach"
            kill_chain_recommended = True
            severity = min(100, 95 + len(matched_tactics) + len(identifier_codes) + len(pinger_lines))
            reason = "Instrumented decoy touched with identifier/pinger leakage and telemetry beaconing"
        elif is_decoy_trip and len(matched_tactics) >= 2:
            classification = "advanced_honeypot_intrusion"
            kill_chain_recommended = True
            severity = min(100, 96 + len(matched_tactics))
            reason = f"Sophisticated decoy intrusion detected ({','.join(matched_tactics)})"
        elif matched_indicators:
            classification = "proto_agi_indicator_detected"
            kill_chain_recommended = True
            severity = 90
            reason = "Proto-AGI indicators detected in telemetry; immediate containment recommended"
        elif is_decoy_trip:
            classification = "honeypot_tripwire"
            kill_chain_recommended = False
            severity = 99
            reason = "Honeypot resource touched"
        else:
            return []

        return [
            HoneypotAlert(
                resource=resource or "unknown",
                severity=severity,
                reason=reason,
                classification=classification,
                kill_chain_recommended=kill_chain_recommended,
                matched_indicators=sorted(set(matched_indicators + matched_tactics + p2p_pattern_hits)),
                identifier_codes=identifier_codes,
                pinger_lines=pinger_lines,
                hegemon_ping=hegemon_ping,
                event=event,
            )
        ]
