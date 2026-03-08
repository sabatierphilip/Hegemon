from __future__ import annotations

import json
import random
from pathlib import Path

from .campaign_state import CampaignState

StateKey = tuple[int, int, int, int, int]


class HannibalQLearner:
    ALPHA = 0.15
    GAMMA = 0.85
    EPSILON_START = 0.25
    EPSILON_MIN = 0.05
    EPSILON_DECAY = 0.995

    def __init__(self, qtable_path: Path, actions: list[str]) -> None:
        self._path = qtable_path
        self._actions = actions
        self._n_actions = len(actions)
        self._epsilon = self.EPSILON_START
        self._episode = 0
        self._q: dict[str, list[float]] = {}
        if qtable_path.exists():
            self._load()

    def _key(self, state: StateKey) -> str:
        return "|".join(map(str, state))

    def _q_row(self, state: StateKey) -> list[float]:
        key = self._key(state)
        if key not in self._q:
            self._q[key] = [0.0] * self._n_actions
        return self._q[key]

    def select_action(self, state: StateKey, clips_preferred: list[str]) -> str:
        if random.random() < self._epsilon and clips_preferred:
            return random.choice(clips_preferred)
        row = self._q_row(state)
        best_idx = max(range(self._n_actions), key=lambda i: row[i])
        return self._actions[best_idx]

    def update(self, state: StateKey, action: str, reward: float, next_state: StateKey) -> None:
        if action not in self._actions:
            return
        action_idx = self._actions.index(action)
        row = self._q_row(state)
        next_row = self._q_row(next_state)
        td_target = reward + self.GAMMA * max(next_row)
        td_error = td_target - row[action_idx]
        row[action_idx] += self.ALPHA * td_error
        self._q[self._key(state)] = row
        self._epsilon = max(self.EPSILON_MIN, self._epsilon * self.EPSILON_DECAY)
        self._episode += 1
        if self._episode % 50 == 0:
            self._save()

    def reward_for_outcome(self, action: str, outcome: str, state: CampaignState) -> float:
        base = {
            "DEPLOY_SCOUT": 0.3,
            "DEPLOY_MAPPER": 0.4,
            "DEPLOY_FLANKER": 0.5,
            "DEPLOY_HARVESTER": 0.7,
            "DEPLOY_ENCIRCLER": 0.6,
            "DEPLOY_STRIKER": 0.8,
            "DEPLOY_WATCHDOG": 0.2,
            "SPAWN_CHILD_SWARM": 0.65,
            "RECALL_ALL_DRONES": -0.1,
            "TERMINATE_HIGHEST_RISK_DRONE": -0.15,
        }.get(action, 0.1)

        if outcome == "completed_with_findings":
            return base + 0.4
        if outcome == "completed_no_findings":
            return base - 0.1
        if outcome == "error":
            return base - 0.5 - (state.exposure_score * 0.3)
        if outcome == "terminated_by_agent":
            return 0.05
        return base

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"epsilon": self._epsilon, "episode": self._episode, "q": self._q}),
            encoding="utf-8",
        )

    def _load(self) -> None:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._epsilon = float(data.get("epsilon", self.EPSILON_START))
            self._episode = int(data.get("episode", 0))
            self._q = data.get("q", {})
        except Exception:
            self._q = {}
