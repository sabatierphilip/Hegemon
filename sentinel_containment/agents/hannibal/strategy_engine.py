from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .campaign_state import CampaignState


@dataclass
class RecommendedAction:
    action: str
    priority: str
    reason: str


class HannibalStrategyEngine:
    """Builds operator-facing analysis and what-if simulations for Mission Control."""

    def build_briefing(self, campaign: CampaignState | None, drones: dict[str, Any]) -> dict[str, Any]:
        if campaign is None:
            return {
                "readiness": "standby",
                "risk_score": 0.0,
                "risk_band": "low",
                "phase_velocity": "unknown",
                "top_risks": ["No active campaign"],
                "recommended_actions": [],
                "fleet_snapshot": {"total": 0, "active": 0, "terminated": 0, "error": 0},
                "generated_at": time.time(),
            }

        active = [drones[did] for did in campaign.active_drone_ids if did in drones]
        terminated = [d for d in drones.values() if getattr(d, "status", "") == "terminated"]
        errored = [d for d in drones.values() if getattr(d, "status", "") == "error"]

        risk_score = self._calculate_risk(campaign, active, errored)
        risk_band = self._risk_band(risk_score)
        top_risks = self._top_risks(campaign, active, errored)
        recs = [r.__dict__ for r in self._recommend(campaign, risk_score, active)]

        return {
            "readiness": "engaged" if campaign.phase != "withdrawal" else "withdrawn",
            "risk_score": round(risk_score, 4),
            "risk_band": risk_band,
            "phase_velocity": self._phase_velocity(campaign),
            "top_risks": top_risks,
            "recommended_actions": recs,
            "fleet_snapshot": {
                "total": len(drones),
                "active": len(active),
                "terminated": len(terminated),
                "error": len(errored),
            },
            "generated_at": time.time(),
        }

    def run_simulation(self, campaign: CampaignState | None, directive: str) -> dict[str, Any]:
        normalized = directive.strip().lower()
        if not campaign:
            return {
                "directive": directive,
                "predicted_outcome": "no_campaign",
                "exposure_delta": 0.0,
                "host_gain": 0,
                "credential_gain": 0,
                "notes": ["No campaign exists. Start a campaign to simulate directives."],
            }

        if "aggressive" in normalized or "enforce" in normalized:
            return {
                "directive": directive,
                "predicted_outcome": "high_gain_high_risk",
                "exposure_delta": 0.24,
                "host_gain": 3,
                "credential_gain": 2,
                "notes": [
                    "Fast expansion likely to reveal additional hosts.",
                    "Counter-detection risk materially increases under aggressive mode.",
                ],
            }

        if "pause" in normalized or "hold" in normalized:
            return {
                "directive": directive,
                "predicted_outcome": "containment_hold",
                "exposure_delta": -0.08,
                "host_gain": 0,
                "credential_gain": 0,
                "notes": ["Exposure cools down while fleet remains idle."],
            }

        return {
            "directive": directive,
            "predicted_outcome": "balanced_progress",
            "exposure_delta": 0.06,
            "host_gain": 1,
            "credential_gain": 1,
            "notes": [
                "Incremental recon likely to continue.",
                "Suitable when preserving stealth is a priority.",
            ],
        }

    def _calculate_risk(self, campaign: CampaignState, active_drones: list[Any], errored: list[Any]) -> float:
        drone_pressure = min(0.28, len(active_drones) * 0.04)
        detection_pressure = min(0.32, campaign.detection_events * 0.06)
        error_pressure = min(0.22, len(errored) * 0.08)
        objective_pressure = 0.18 if not campaign.objectives_completed else 0.0
        base = campaign.exposure_score
        return max(0.0, min(1.0, base + drone_pressure + detection_pressure + error_pressure + objective_pressure))

    def _phase_velocity(self, campaign: CampaignState) -> str:
        seconds_in_phase = max(0.0, time.time() - campaign.phase_entered_at)
        if seconds_in_phase < 120:
            return "rapid"
        if seconds_in_phase < 500:
            return "steady"
        return "stalled"

    @staticmethod
    def _risk_band(risk_score: float) -> str:
        if risk_score >= 0.75:
            return "critical"
        if risk_score >= 0.45:
            return "elevated"
        return "low"

    def _top_risks(self, campaign: CampaignState, active_drones: list[Any], errored: list[Any]) -> list[str]:
        risks: list[str] = []
        if campaign.exposure_score >= 0.7:
            risks.append("Operational exposure is above doctrine safety threshold")
        if len(active_drones) >= 6:
            risks.append("Fleet saturation may increase telemetry footprint")
        if campaign.detection_events >= 2:
            risks.append("Detection events indicate active blue-team awareness")
        if errored:
            risks.append("Drone failures can expose infrastructure and intent")
        if not risks:
            risks.append("No immediate strategic risks detected")
        return risks[:4]

    def _recommend(self, campaign: CampaignState, risk_score: float, active_drones: list[Any]) -> list[RecommendedAction]:
        recs: list[RecommendedAction] = []

        if risk_score >= 0.75:
            recs.append(
                RecommendedAction(
                    action="RECALL_ALL_DRONES",
                    priority="urgent",
                    reason="Exposure is critical; immediate withdrawal reduces attribution risk.",
                )
            )

        if campaign.phase in {"dormant", "reconnaissance"} and len(campaign.alive_hosts) < 2:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_SCOUT",
                    priority="high",
                    reason="Insufficient target visibility; launch recon assets to improve map coverage.",
                )
            )

        if campaign.phase in {"mapping", "flanking"} and not campaign.pivot_chains:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_MAPPER",
                    priority="high",
                    reason="No validated pivot chain exists; mapper needed before encirclement.",
                )
            )

        if campaign.high_value_targets and campaign.credentials_harvested == 0:
            recs.append(
                RecommendedAction(
                    action="DEPLOY_HARVESTER",
                    priority="high",
                    reason="High-value hosts are present; harvest credentials for deterministic control.",
                )
            )

        if len(active_drones) == 0 and campaign.phase != "withdrawal":
            recs.append(
                RecommendedAction(
                    action="SPAWN_CHILD_SWARM",
                    priority="normal",
                    reason="No active fleet detected; deploy a compact swarm to restore momentum.",
                )
            )

        if not recs:
            recs.append(
                RecommendedAction(
                    action="MAINTAIN_POSTURE",
                    priority="normal",
                    reason="Current campaign trajectory is stable; continue monitoring and adapt on new telemetry.",
                )
            )
        return recs[:5]
