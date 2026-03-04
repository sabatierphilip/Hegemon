from __future__ import annotations

import json
import os
import hmac
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel_containment.security.distributor import SecurityDistributorEngine
from sentinel_containment.telemetry.schema import NormalizedEvent


class TelemetryIngestor:
    _COLLECTOR_LEVEL_ORDER = {
        "workload": 1,
        "os": 2,
        "runtime": 3,
        "hypervisor": 4,
        "counterclone": 5,
    }
    _MIN_COLLECTOR_LEVEL_BY_SOURCE = {
        "cloud_audit": "workload",
        "network_flow": "workload",
        "model_api": "workload",
        "syslog": "os",
        "host_osquery": "os",
        "host_kernel": "runtime",
        "host_runtime": "runtime",
        "hypervisor": "hypervisor",
        "counterclone": "counterclone",
        "fast_lane": "runtime",
    }

    def __init__(
        self,
        output_path: Path = Path("data/telemetry_index.jsonl"),
        signing_key: str | None = None,
        key_rotation_seconds: int = 300,
        distributor_engine: SecurityDistributorEngine | None = None,
    ):
        self.output_path = output_path
        self.signing_key = (signing_key or os.getenv("TELEMETRY_SIGNING_KEY") or "hegemon-default-telemetry-key").encode("utf-8")
        self.key_rotation_seconds = max(60, int(key_rotation_seconds))
        protected_paths = os.getenv("TELEMETRY_PROTECTED_PATH_PATTERNS", r"^/(etc|boot|root|var/lib/kubelet|var/lib/docker|sys|proc)")
        self._protected_path_pattern = re.compile(protected_paths)
        self.distributor_engine = distributor_engine

    def _epoch(self, event_ts: str) -> int:
        dt = datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
        return int(dt.timestamp()) // self.key_rotation_seconds

    def _derive_epoch_key(self, epoch: int) -> bytes:
        return hmac.new(self.signing_key, str(epoch).encode("utf-8"), hashlib.sha256).digest()

    def _last_chain_hash(self) -> str:
        if not self.output_path.exists() or self.output_path.stat().st_size == 0:
            return "GENESIS"
        with self.output_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        if not lines:
            return "GENESIS"
        try:
            payload = json.loads(lines[-1])
        except json.JSONDecodeError:
            return "GENESIS"
        return str(payload.get("telemetry_chain_hash", "GENESIS"))

    def _sign(self, doc: dict[str, Any], epoch: int) -> str:
        key = self._derive_epoch_key(epoch)
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()

    def _collector_level_verified(self, source_type: str, collector_level: str) -> bool:
        source_min = self._MIN_COLLECTOR_LEVEL_BY_SOURCE.get(source_type, "workload")
        min_rank = self._COLLECTOR_LEVEL_ORDER.get(source_min, 1)
        provided_rank = self._COLLECTOR_LEVEL_ORDER.get(collector_level, 0)
        return provided_rank >= min_rank

    def _core_and_file_access_verification(self, source_type: str, doc: dict[str, Any], raw_event: dict[str, Any]) -> dict[str, Any]:
        resource = str(doc.get("resource", ""))
        action = str(doc.get("action", ""))
        process = str(doc.get("process", ""))
        evidence = {
            "hypervisor_visible": bool(raw_event.get("hypervisor_visible", source_type == "hypervisor")),
            "counterclone_participant": bool(raw_event.get("counterclone_participant", source_type == "counterclone")),
            "counterclone_integrity_verified": bool(raw_event.get("counterclone_integrity_verified", False)),
        }
        protected_path_touched = bool(self._protected_path_pattern.search(resource))
        file_access_action = action in {"file_read", "file_write", "file_exec", "open", "chmod", "chown"}
        suspicious_process = any(marker in process.lower() for marker in ("agent", "autonomous", "proto", "unknown"))
        rogue_file_access_suspected = protected_path_touched and file_access_action and suspicious_process
        core_telemetry_verified = evidence["hypervisor_visible"] or (
            evidence["counterclone_participant"] and evidence["counterclone_integrity_verified"]
        )
        return {
            "core_telemetry_verified": core_telemetry_verified,
            "rogue_file_access_suspected": rogue_file_access_suspected,
            "protected_path_touched": protected_path_touched,
            "file_access_action": file_access_action,
            "collector_file_guard_verified": bool(raw_event.get("collector_file_guard_verified", False)),
        }

    def ingest(self, source_type: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        event = NormalizedEvent.from_raw(source_type, raw_event)
        doc = event.to_opensearch_doc()
        event_ts = str(doc.get("@timestamp", datetime.now(timezone.utc).isoformat()))
        prev_chain_hash = self._last_chain_hash()
        epoch = self._epoch(event_ts)
        collector_level = str(raw_event.get("collector_level", "workload"))
        verification = self._core_and_file_access_verification(source_type, doc, raw_event)
        distributor_envelope = self.distributor_engine.enrich_event(source_type, doc) if self.distributor_engine else {}
        integrity_payload = {
            **doc,
            "collector_level": collector_level,
            "telemetry_scope": raw_event.get("telemetry_scope", source_type),
            "source_type": source_type,
            "counterclone_participant": bool(raw_event.get("counterclone_participant", source_type == "counterclone")),
            "counterclone_integrity_verified": bool(raw_event.get("counterclone_integrity_verified", False)),
            "hypervisor_visible": bool(raw_event.get("hypervisor_visible", source_type == "hypervisor")),
            "collector_level_verified": self._collector_level_verified(source_type, collector_level),
            "verification": verification,
            "distributor": distributor_envelope,
            "integrity": {
                "prev_chain_hash": prev_chain_hash,
                "signature_epoch": epoch,
            },
        }
        integrity_payload["integrity"]["signature"] = self._sign(integrity_payload, epoch)
        integrity_payload["telemetry_chain_hash"] = hashlib.sha256(
            json.dumps(
                {
                    "prev": prev_chain_hash,
                    "event_hash": hashlib.sha256(
                        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest(),
                    "signature": integrity_payload["integrity"]["signature"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(integrity_payload) + "\n")
        return integrity_payload

    def ingest_batch(self, source_type: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.ingest(source_type, e) for e in events]

    def read_recent(self, limit: int = 200) -> list[dict[str, Any]]:
        if not self.output_path.exists():
            return []
        with self.output_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        events: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    events.append(payload)
            except json.JSONDecodeError:
                continue
        return events

    def verify_recent(self, limit: int = 200) -> bool:
        events = self.read_recent(limit=limit)
        last_chain = "GENESIS"
        for payload in events:
            integrity = payload.get("integrity", {})
            if integrity.get("prev_chain_hash") != last_chain:
                return False

            epoch = int(integrity.get("signature_epoch", 0))
            expected_sig = integrity.get("signature")
            candidate = dict(payload)
            candidate.pop("telemetry_chain_hash", None)
            candidate_integrity = dict(candidate.get("integrity", {}))
            candidate_integrity.pop("signature", None)
            candidate["integrity"] = candidate_integrity
            if expected_sig != self._sign(candidate, epoch):
                return False
            last_chain = str(payload.get("telemetry_chain_hash", ""))
        return True
