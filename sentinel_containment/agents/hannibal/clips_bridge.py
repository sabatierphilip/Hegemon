from __future__ import annotations

from pathlib import Path
import threading
from typing import Any

import clips

from .campaign_state import CampaignState

DOCTRINE_PATH = Path(__file__).parent / "doctrine.clp"


class ClipsBridge:
    """Manages a CLIPS environment instance. One per agent."""

    def __init__(self) -> None:
        self._env = clips.Environment()
        self._env.load(str(DOCTRINE_PATH))
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._env.reset()

    def evaluate(self, state: CampaignState) -> list[dict[str, Any]]:
        """Assert campaign state facts, run inference, collect decisions."""
        with self._lock:
            self._env.reset()
            for fact_str in state.to_clips_facts():
                self._env.assert_string(fact_str)
            self._env.run()

            decisions: list[dict[str, Any]] = []
            for fact in self._env.facts():
                if fact.template.name == "hannibal-decision":
                    decisions.append(
                        {
                            "action": str(fact["action"]),
                            "confidence": float(fact["confidence"]),
                            "rationale": str(fact["rationale"]),
                        }
                    )
            return decisions

    def assert_extra_fact(self, fact_str: str) -> None:
        with self._lock:
            self._env.assert_string(fact_str)
            self._env.run()
