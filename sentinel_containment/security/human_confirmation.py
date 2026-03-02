from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ConfirmationVerificationResult:
    allowed: bool
    message: str


class HumanConfirmationVerifier:
    """Verifies simple yes/no containment confirmations with anti-tamper binding."""

    def __init__(
        self,
        shared_secret: str | None = None,
        prompt_count: int = 2,
        question_salt: str = "human-presence-gate",
        fail_closed: bool = True,
    ):
        self.shared_secret = (shared_secret or "").strip()
        self.prompt_count = max(1, int(prompt_count))
        self.question_salt = str(question_salt)
        self._fail_closed = bool(fail_closed)

    @property
    def configured(self) -> bool:
        return bool(self.shared_secret)

    @property
    def enabled(self) -> bool:
        return self._fail_closed or self.configured

    def verify(
        self,
        *,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        confirmation_bundle: dict[str, Any] | None,
    ) -> ConfirmationVerificationResult:
        if not self.shared_secret:
            if self._fail_closed:
                return ConfirmationVerificationResult(False, "human confirmation blocked: shared secret not configured")
            return ConfirmationVerificationResult(True, "human confirmation disabled")

        if not confirmation_bundle:
            return ConfirmationVerificationResult(False, "interactive human confirmation required")

        nonce = str(confirmation_bundle.get("nonce", "")).strip()
        answers = confirmation_bundle.get("answers", [])
        proof = str(confirmation_bundle.get("proof", "")).strip()
        if not nonce or not isinstance(answers, list) or not proof:
            return ConfirmationVerificationResult(False, "missing human confirmation bundle fields")

        expected_questions = self.challenge_questions(
            host=host,
            severity=severity,
            requested_actions=requested_actions,
            approvals=approvals,
            nonce=nonce,
        )
        if len(answers) != len(expected_questions):
            return ConfirmationVerificationResult(False, "human confirmation answer count mismatch")
        if any(str(v).strip().lower() != "yes" for v in answers):
            return ConfirmationVerificationResult(False, "human confirmation requires explicit yes answers")

        canonical = self._canonical_confirmation_payload(
            host=host,
            severity=severity,
            requested_actions=requested_actions,
            approvals=approvals,
            nonce=nonce,
            answers=["yes" for _ in expected_questions],
        )
        expected_proof = hmac.new(self.shared_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_proof, proof):
            return ConfirmationVerificationResult(False, "human confirmation proof invalid")

        return ConfirmationVerificationResult(True, "human confirmation verified")

    def challenge_questions(
        self,
        *,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        nonce: str,
    ) -> list[str]:
        base = self._context_seed(host, severity, requested_actions, approvals, nonce)
        questions: list[str] = []
        for idx in range(self.prompt_count):
            digest = hashlib.sha256(f"{base}|q{idx}|{self.question_salt}".encode("utf-8")).hexdigest()
            short = digest[:10]
            questions.append(
                f"Human confirmation {idx + 1}/{self.prompt_count} for host {host}, token {short}: "
                "do you approve this containment plan? (yes/no)"
            )
        return questions

    @classmethod
    def build_confirmation_bundle(
        cls,
        *,
        shared_secret: str,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        nonce: str,
        answer: str = "yes",
        prompt_count: int = 2,
    ) -> dict[str, Any]:
        verifier = cls(shared_secret=shared_secret, prompt_count=prompt_count)
        answers = [str(answer).strip().lower() for _ in range(verifier.prompt_count)]
        canonical = verifier._canonical_confirmation_payload(
            host=host,
            severity=severity,
            requested_actions=requested_actions,
            approvals=approvals,
            nonce=nonce,
            answers=answers,
        )
        proof = hmac.new(shared_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return {"nonce": nonce, "answers": answers, "proof": proof}

    def _context_seed(
        self,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        nonce: str,
    ) -> str:
        payload = {
            "approvals": sorted(str(a).strip().lower() for a in approvals),
            "host": str(host),
            "nonce": str(nonce),
            "requested_actions": sorted(str(a) for a in requested_actions),
            "severity": int(severity),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    def _canonical_confirmation_payload(
        self,
        *,
        host: str,
        severity: int,
        requested_actions: list[str],
        approvals: list[str],
        nonce: str,
        answers: list[str],
    ) -> bytes:
        payload = {
            "approvals": sorted(str(a).strip().lower() for a in approvals),
            "answers": [str(v).strip().lower() for v in answers],
            "host": str(host),
            "nonce": str(nonce),
            "requested_actions": sorted(str(a) for a in requested_actions),
            "severity": int(severity),
            "scope": "containment_execute_human_confirmation",
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
