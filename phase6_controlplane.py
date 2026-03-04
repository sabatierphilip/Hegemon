"""Phase 6 order verification + transparency publication."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Sequence

import requests
from nacl import exceptions as nacl_exceptions, signing

from signed_ledger import SignedLedger


class OrderVerificationError(RuntimeError):
    pass


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Phase6OrderVerifier:
    def __init__(
        self,
        control_verify_keys: Sequence[signing.VerifyKey],
        human_hmac_key: str,
        ledger: SignedLedger,
        quorum_threshold: int,
        clock_skew_seconds: int = 120,
    ) -> None:
        self.control_verify_keys = control_verify_keys
        self.human_hmac_key = human_hmac_key
        self.ledger = ledger
        self.quorum_threshold = quorum_threshold
        self.clock_skew_seconds = clock_skew_seconds

    def _verify_quorum(self, order: Dict[str, Any]) -> None:
        signatures = order.get("signatures", [])
        core = order["order"]
        matched = set()
        for sig_b64 in signatures:
            sig = base64.b64decode(sig_b64)
            for idx, vk in enumerate(self.control_verify_keys):
                if idx in matched:
                    continue
                try:
                    vk.verify(_canonical(core), sig)
                    matched.add(idx)
                    break
                except nacl_exceptions.BadSignatureError:
                    continue
        if len(matched) < self.quorum_threshold:
            raise OrderVerificationError(f"quorum not met: {len(matched)}/{self.quorum_threshold}")

    def _verify_human(self, order: Dict[str, Any]) -> None:
        human = order.get("human_confirmation", {})
        expected_payload = {
            "operator_id": human.get("operator_id"),
            "nonce": human.get("nonce"),
            "order_digest": order["order"].get("digest"),
        }
        expected = hmac.new(self.human_hmac_key.encode("utf-8"), _canonical(expected_payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(human.get("hmac", ""))):
            raise OrderVerificationError("human confirmation invalid")

    def _verify_freshness(self, order: Dict[str, Any]) -> None:
        ts = datetime.fromisoformat(order["order"]["timestamp"])
        if abs((datetime.now(timezone.utc) - ts).total_seconds()) > self.clock_skew_seconds:
            raise OrderVerificationError("order timestamp stale")

    def _verify_checkpoint_causality(self, order: Dict[str, Any]) -> None:
        last_hash = self.ledger.last_hash()
        expected = order["order"].get("checkpoint")
        if expected not in ("genesis", last_hash):
            raise OrderVerificationError("checkpoint causality mismatch")

    def verify(self, order: Dict[str, Any]) -> None:
        self._verify_quorum(order)
        self._verify_human(order)
        self._verify_freshness(order)
        self._verify_checkpoint_causality(order)
        self.ledger.append("phase6_order_verified", {"digest": order["order"].get("digest")})


class TransparencyPublisher:
    def __init__(self, endpoint: str, timeout: int = 5) -> None:
        self.endpoint = endpoint
        self.timeout = timeout

    def publish(self, signed_decision: Dict[str, Any]) -> requests.Response:
        return requests.post(self.endpoint, json=signed_decision, timeout=self.timeout)
