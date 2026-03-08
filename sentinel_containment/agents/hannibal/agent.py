from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sentinel_containment.agents.base_agent import BaseAgent

from .campaign_state import CampaignState
from .clips_bridge import ClipsBridge
from .doctrine_defaults import ACTION_INDEX, DRONE_TYPE_CONFIGS
from .drone_factory import BUILDERS
from .nlp_parser import HannibalNLPParser
from .q_learner import HannibalQLearner

if TYPE_CHECKING:
    from sentinel_containment.controlplane import HegemonControlPlane

DATA_DIR = Path("data") / "agents" / "hannibal"

PHASE_ADVANCE_ACTIONS = {
    "ADVANCE_PHASE_RECONNAISSANCE": "reconnaissance",
    "ADVANCE_PHASE_MAPPING": "mapping",
    "ADVANCE_PHASE_FLANKING": "flanking",
    "ADVANCE_PHASE_ENCIRCLEMENT": "encirclement",
    "ADVANCE_PHASE_EXPLOITATION": "exploitation",
    "ADVANCE_PHASE_WITHDRAWAL": "withdrawal",
}


class HannibalAgent(BaseAgent):
    AGENT_ID = "hannibal"
    LOOP_INTERVAL = 30

    def __init__(self, control_plane: "HegemonControlPlane") -> None:
        self._cp = control_plane
        self._clips = ClipsBridge()
        self._q = HannibalQLearner(DATA_DIR / "qtable.json", list(ACTION_INDEX.keys()))
        self._nlp = HannibalNLPParser()
        self._campaign: CampaignState | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._log: list[dict[str, Any]] = []
        self._paused = False
        self._drone_actions: dict[str, str] = {}
        DATA_DIR.mkdir(parents=True, exist_ok=True)

    def receive_instruction(self, text: str) -> dict[str, Any]:
        directive = self._nlp.parse(text)
        explanation = self._nlp.explain(directive)
        result: dict[str, Any] = {"directive": directive.__dict__, "explanation": explanation, "acted": False}

        if directive.intent == "deploy_agent":
            target = directive.target_host or directive.target_network or "10.0.0.1"
            campaign_id = f"campaign-{secrets.token_hex(4)}"
            objective = directive.objective or text
            self.start_campaign(campaign_id=campaign_id, target=target, objective=objective, autonomy_override=directive.autonomy_override)
            result["acted"] = True
            result["campaign_id"] = campaign_id
        elif directive.intent == "pause_campaign":
            self._paused = True
            result["acted"] = True
        elif directive.intent == "resume_campaign":
            self._paused = False
            result["acted"] = True
        elif directive.intent == "abort_campaign":
            self.abort_campaign()
            result["acted"] = True
        elif directive.intent == "query_status":
            result["status"] = self.status()
            result["acted"] = True
        elif directive.intent == "set_target" and self._campaign:
            with self._lock:
                if directive.target_host:
                    setattr(self._campaign, "target_host", directive.target_host)
                if directive.target_network:
                    setattr(self._campaign, "target_network", directive.target_network)
            result["acted"] = True
        elif directive.intent == "set_objective" and self._campaign and directive.objective:
            with self._lock:
                self._campaign.mission_objective = directive.objective
            result["acted"] = True
        elif directive.intent == "adjust_autonomy" and directive.autonomy_override and self._campaign:
            with self._lock:
                setattr(self._campaign, "autonomy_override", directive.autonomy_override)
            result["acted"] = True

        return result

    def start_campaign(self, campaign_id: str, target: str, objective: str, autonomy_override: str | None = None) -> CampaignState:
        with self._lock:
            self._campaign = CampaignState(campaign_id=campaign_id, agent_id=self.AGENT_ID, mission_objective=objective)
            setattr(self._campaign, "target_host", target)
            setattr(self._campaign, "target_network", target if "/" in target else f"{target}/24")
            setattr(self._campaign, "autonomy_override", autonomy_override)
        self._stop_event.clear()
        self._paused = False
        self._thread = threading.Thread(target=self._deliberation_loop, daemon=True)
        self._thread.start()
        self._record_log("campaign_started", {"campaign_id": campaign_id, "target": target, "objective": objective})
        return self._campaign

    def abort_campaign(self) -> None:
        self._stop_event.set()
        with self._lock:
            if self._campaign:
                for drone_id in list(self._campaign.active_drone_ids):
                    try:
                        self._cp.terminate_drone(drone_id, actor="hannibal")
                    except Exception:
                        continue
                self._campaign.phase = "withdrawal"
        self._record_log("campaign_aborted", {})

    def status(self) -> dict[str, Any]:
        with self._lock:
            if not self._campaign:
                return {"state": "dormant", "q_episode": self._q._episode}
            return {
                "state": "running" if not self._paused else "paused",
                "campaign_id": self._campaign.campaign_id,
                "phase": self._campaign.phase,
                "alive_hosts": len(self._campaign.alive_hosts),
                "active_drones": len(self._campaign.active_drone_ids),
                "credentials_harvested": self._campaign.credentials_harvested,
                "exposure_score": round(self._campaign.exposure_score, 3),
                "objectives_completed": self._campaign.objectives_completed,
                "log_tail": self._log[-20:],
                "q_episode": self._q._episode,
            }

    def _deliberation_loop(self) -> None:
        while not self._stop_event.is_set():
            if not self._paused:
                try:
                    self._deliberate()
                except Exception as exc:
                    self._record_log("deliberation_error", {"error": str(exc)[:200]})
            self._stop_event.wait(timeout=self.LOOP_INTERVAL)

    def _deliberate(self) -> None:
        with self._lock:
            if not self._campaign:
                return
            state = self._campaign

        completed: list[tuple[str, str]] = []
        for drone_id in list(state.active_drone_ids):
            try:
                drone = self._cp.drones.get(drone_id)
                if not drone:
                    completed.append((drone_id, "error"))
                    continue
                state.update_from_drone_telemetry(drone_id, drone.telemetry, drone.findings)
                if drone.status in ("terminated", "error"):
                    outcome = "completed_with_findings" if drone.findings else "completed_no_findings"
                    if drone.status == "error":
                        outcome = "error"
                    completed.append((drone_id, outcome))
            except Exception:
                completed.append((drone_id, "error"))

        prev_q_vec = state.to_q_vector()
        for drone_id, outcome in completed:
            if drone_id in state.active_drone_ids:
                state.active_drone_ids.remove(drone_id)
            if drone_id not in state.terminated_drone_ids:
                state.terminated_drone_ids.append(drone_id)
            last_action = self._get_drone_action(drone_id)
            reward = self._q.reward_for_outcome(last_action, outcome, state)
            new_q_vec = state.to_q_vector()
            self._q.update(prev_q_vec, last_action, reward, new_q_vec)
            self._record_log("drone_completed", {"drone_id": drone_id, "outcome": outcome, "reward": reward})

        clips_decisions = self._clips.evaluate(state)
        clips_actions = [d["action"] for d in clips_decisions]

        selected_action = self._q.select_action(state.to_q_vector(), clips_actions)
        rationale = next((d["rationale"] for d in clips_decisions if d["action"] == selected_action), "Q-learner selected action not in CLIPS suggestions.")
        self._execute_action(selected_action, state, rationale)

    def _execute_action(self, action: str, state: CampaignState, rationale: str) -> None:
        target = getattr(state, "target_host", "127.0.0.1") or "127.0.0.1"
        network = getattr(state, "target_network", None) or f"{target}/24"
        autonomy = getattr(state, "autonomy_override", None)
        self._record_log("action_selected", {"action": action, "rationale": rationale})

        if action in PHASE_ADVANCE_ACTIONS:
            state.advance_phase(PHASE_ADVANCE_ACTIONS[action])
            return

        if action == "RECALL_ALL_DRONES":
            for drone_id in list(state.active_drone_ids):
                try:
                    self._cp.recall_drone(drone_id, actor="hannibal")
                except Exception:
                    continue
            return

        if action == "TERMINATE_HIGHEST_RISK_DRONE":
            worst, worst_score = None, -1.0
            for drone_id in state.active_drone_ids:
                drone = self._cp.drones.get(drone_id)
                if not drone:
                    continue
                age = self._drone_age_seconds(getattr(drone, "launched_at", None))
                score = len(drone.findings) + age / 60.0
                if score > worst_score:
                    worst_score = score
                    worst = drone_id
            if worst:
                try:
                    self._cp.terminate_drone(worst, actor="hannibal")
                except Exception:
                    pass
            return

        if action not in BUILDERS and action != "SPAWN_CHILD_SWARM":
            return
        if len(state.active_drone_ids) >= 8:
            self._record_log("fleet_cap_reached", {"active": len(state.active_drone_ids)})
            return

        config = DRONE_TYPE_CONFIGS.get(action, DRONE_TYPE_CONFIGS["DEPLOY_SCOUT"])
        drone_autonomy = autonomy or config["autonomy"]
        drone_tier = config["tier"]
        ttl = int(config["ttl"])

        if action == "SPAWN_CHILD_SWARM":
            for sub_action in ["DEPLOY_FLANKER", "DEPLOY_HARVESTER"]:
                self._deploy_drone(sub_action, target, network, drone_autonomy, drone_tier, ttl, state)
            return

        self._deploy_drone(action, target, network, drone_autonomy, drone_tier, ttl, state)

    @staticmethod
    def _drone_age_seconds(launched_at: str | None) -> float:
        if not launched_at:
            return 0.0
        try:
            ts = datetime.fromisoformat(launched_at.replace("Z", "+00:00"))
            return max(0.0, (datetime.now(timezone.utc) - ts).total_seconds())
        except Exception:
            return 0.0

    def _deploy_drone(self, action: str, target: str, network: str, autonomy: str, tier: str, ttl: int, state: CampaignState) -> None:
        builder = BUILDERS.get(action)
        if not builder:
            return
        try:
            if action == "DEPLOY_SCOUT":
                behaviour = builder(target, network)
            elif action == "DEPLOY_FLANKER":
                method = "ssh_hop" if state.alive_hosts else "tcp_probe"
                behaviour = builder(target, method)
            else:
                behaviour = builder(target)

            drone_name = f"hannibal-{action.lower().replace('deploy_', '')}-{secrets.token_hex(3)}"
            drone = self._cp.assemble_drone(
                name=drone_name,
                tier=tier,
                mission=state.mission_objective[:80],
                behaviour=behaviour,
                target_host=target,
                target_network=network,
                autonomy_level=autonomy,
                ttl_seconds=ttl,
                checkin_interval_seconds=45,
                actor="hannibal",
            )
            self._cp.launch_drone(drone.drone_id, actor="hannibal")
            state.active_drone_ids.append(drone.drone_id)
            state.drone_orders.append({"action": action, "drone_id": drone.drone_id, "drone_name": drone_name, "target": target, "ts": time.time(), "phase": state.phase})
            self._record_drone_action(drone.drone_id, action)
            self._record_log("drone_deployed", {"action": action, "drone_id": drone.drone_id, "drone_name": drone_name, "target": target})
        except Exception as exc:
            self._record_log("deploy_failed", {"action": action, "error": str(exc)[:200]})

    def _record_log(self, event: str, data: dict[str, Any]) -> None:
        self._log.append({"ts": time.time(), "event": event, **data})
        if len(self._log) > 1000:
            self._log = self._log[-800:]

    def _record_drone_action(self, drone_id: str, action: str) -> None:
        self._drone_actions[drone_id] = action

    def _get_drone_action(self, drone_id: str) -> str:
        return self._drone_actions.get(drone_id, "DEPLOY_SCOUT")
