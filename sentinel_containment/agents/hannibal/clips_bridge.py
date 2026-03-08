from __future__ import annotations

from pathlib import Path
import importlib
import importlib.util
import threading
from typing import Any

_CLIPS_AVAILABLE = importlib.util.find_spec("clips") is not None
clips = importlib.import_module("clips") if _CLIPS_AVAILABLE else None

from .campaign_state import CampaignState

DOCTRINE_PATH = Path(__file__).parent / "doctrine.clp"


class ClipsBridge:
    """Manages a CLIPS environment instance. One per agent."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._env = None
        if _CLIPS_AVAILABLE and clips is not None:
            self._env = clips.Environment()
            self._env.load(str(DOCTRINE_PATH))

    def reset(self) -> None:
        if self._env is None:
            return
        with self._lock:
            self._env.reset()

    def evaluate(self, state: CampaignState) -> list[dict[str, Any]]:
        """Assert campaign state facts, run inference, collect decisions."""
        if self._env is None:
            return [{"action": "DEPLOY_SCOUT", "confidence": 0.6, "rationale": "CLIPS unavailable; conservative scout fallback."}]
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
        if self._env is None:
            return
        with self._lock:
            self._env.assert_string(fact_str)
            self._env.run()
