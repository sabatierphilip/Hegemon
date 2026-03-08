from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .campaign_state import CampaignState

CATALOG_PATH = Path("config") / "hannibal_mission_catalog.json"


@dataclass
class MissionTask:
    task_id: str
    title: str
    owner: str
    status: str
    priority: str
    created_at: float
    updated_at: float
    notes: list[str] = field(default_factory=list)
    linked_action: str | None = None
    linked_host: str | None = None


@dataclass
class MissionOrder:
    order_id: str
    action: str
    rationale: str
    issued_at: float
    operator: str
    state: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class FleetDirective:
    directive_id: str
    title: str
    objective: str
    mode: str
    ttl_seconds: int
    issued_at: float
    actor: str
    expected_outcome: str


class MissionControlBoard:
    """Stateful mission-control board for Hannibal operations."""

    def __init__(self) -> None:
        self._tasks: dict[str, MissionTask] = {}
        self._orders: list[MissionOrder] = []
        self._directives: list[FleetDirective] = []
        self._playbooks: list[dict[str, Any]] = []
        self._decision_log: list[dict[str, Any]] = []
        self._last_refresh = 0.0
        self._load_playbooks()

    def _load_playbooks(self) -> None:
        if CATALOG_PATH.exists():
            try:
                self._playbooks = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            except Exception:
                self._playbooks = []

    def summarize(self, campaign: CampaignState | None, drones: dict[str, Any], strategy_briefing: dict[str, Any]) -> dict[str, Any]:
        active_drones = [drones[d] for d in (campaign.active_drone_ids if campaign else []) if d in drones]
        terminated = [d for d in drones.values() if getattr(d, "status", "") == "terminated"]
        errors = [d for d in drones.values() if getattr(d, "status", "") == "error"]
        total_findings = 0
        for drone in active_drones:
            total_findings += len(getattr(drone, "findings", []) or [])

        return {
            "campaign": {
                "id": campaign.campaign_id if campaign else None,
                "phase": campaign.phase if campaign else "dormant",
                "objective": campaign.mission_objective if campaign else "No campaign",
                "target_host": getattr(campaign, "target_host", None) if campaign else None,
                "target_network": getattr(campaign, "target_network", None) if campaign else None,
                "exposure_score": round(campaign.exposure_score, 4) if campaign else 0.0,
                "alive_hosts": len(campaign.alive_hosts) if campaign else 0,
                "hvt_count": len(campaign.high_value_targets) if campaign else 0,
                "credential_count": campaign.credentials_harvested if campaign else 0,
            },
            "fleet": {
                "active": len(active_drones),
                "terminated": len(terminated),
                "errors": len(errors),
                "active_findings": total_findings,
            },
            "strategy": strategy_briefing,
            "tasking": {
                "open": sum(1 for t in self._tasks.values() if t.status in {"open", "in_progress"}),
                "closed": sum(1 for t in self._tasks.values() if t.status in {"closed", "complete"}),
                "high_priority": sum(1 for t in self._tasks.values() if t.priority in {"high", "urgent"}),
            },
            "orders": [asdict(order) for order in self._orders[-50:]],
            "directives": [asdict(d) for d in self._directives[-30:]],
            "tasks": [asdict(task) for task in sorted(self._tasks.values(), key=lambda t: t.updated_at, reverse=True)[:200]],
            "playbooks": self._playbooks[:150],
            "generated_at": time.time(),
        }

    def create_task(self, payload: dict[str, Any], actor: str = "operator") -> dict[str, Any]:
        title = str(payload.get("title", "")).strip()
        if not title:
            raise ValueError("title required")

        now = time.time()
        task = MissionTask(
            task_id=f"task-{secrets.token_hex(5)}",
            title=title,
            owner=str(payload.get("owner", "mission-control")),
            status=str(payload.get("status", "open")),
            priority=str(payload.get("priority", "normal")),
            created_at=now,
            updated_at=now,
            notes=[str(n) for n in payload.get("notes", []) if str(n).strip()],
            linked_action=(str(payload.get("linked_action")) if payload.get("linked_action") else None),
            linked_host=(str(payload.get("linked_host")) if payload.get("linked_host") else None),
        )
        self._tasks[task.task_id] = task
        self._decision_log.append({"ts": now, "event": "task_created", "task_id": task.task_id, "actor": actor, "title": title})
        return asdict(task)

    def update_task(self, task_id: str, payload: dict[str, Any], actor: str = "operator") -> dict[str, Any]:
        task = self._tasks.get(task_id)
        if not task:
            raise KeyError("task not found")

        changed_fields: list[str] = []
        for field_name in ("title", "owner", "status", "priority", "linked_action", "linked_host"):
            if field_name in payload:
                value = payload.get(field_name)
                setattr(task, field_name, str(value) if value is not None else None)
                changed_fields.append(field_name)

        if "append_note" in payload:
            note = str(payload.get("append_note", "")).strip()
            if note:
                task.notes.append(note)
                changed_fields.append("notes")

        task.updated_at = time.time()
        self._decision_log.append(
            {
                "ts": task.updated_at,
                "event": "task_updated",
                "task_id": task.task_id,
                "actor": actor,
                "changed_fields": changed_fields,
            }
        )
        return asdict(task)

    def issue_order(self, action: str, rationale: str, operator: str = "operator", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        now = time.time()
        order = MissionOrder(
            order_id=f"order-{secrets.token_hex(5)}",
            action=action,
            rationale=rationale,
            issued_at=now,
            operator=operator,
            state="issued",
            payload=payload or {},
        )
        self._orders.append(order)
        if len(self._orders) > 1000:
            self._orders = self._orders[-700:]
        self._decision_log.append({"ts": now, "event": "order_issued", "order_id": order.order_id, "action": action, "operator": operator})
        return asdict(order)

    def close_order(self, order_id: str, outcome: str, operator: str = "operator") -> dict[str, Any]:
        for order in reversed(self._orders):
            if order.order_id == order_id:
                order.state = "closed"
                order.payload["outcome"] = outcome
                order.payload["closed_by"] = operator
                order.payload["closed_at"] = time.time()
                self._decision_log.append(
                    {"ts": time.time(), "event": "order_closed", "order_id": order_id, "operator": operator, "outcome": outcome}
                )
                return asdict(order)
        raise KeyError("order not found")

    def register_directive(self, payload: dict[str, Any], actor: str = "operator") -> dict[str, Any]:
        title = str(payload.get("title", "")).strip()
        objective = str(payload.get("objective", "")).strip()
        if not title or not objective:
            raise ValueError("title and objective required")

        directive = FleetDirective(
            directive_id=f"directive-{secrets.token_hex(4)}",
            title=title,
            objective=objective,
            mode=str(payload.get("mode", "balanced")),
            ttl_seconds=int(payload.get("ttl_seconds", 900)),
            issued_at=time.time(),
            actor=actor,
            expected_outcome=str(payload.get("expected_outcome", "incremental progress")),
        )
        self._directives.append(directive)
        if len(self._directives) > 400:
            self._directives = self._directives[-300:]

        self._decision_log.append(
            {
                "ts": directive.issued_at,
                "event": "directive_registered",
                "directive_id": directive.directive_id,
                "actor": actor,
                "mode": directive.mode,
            }
        )
        return asdict(directive)

    def decision_log(self) -> list[dict[str, Any]]:
        return self._decision_log[-400:]

    def list_playbooks(self, *, query: str | None = None, phase: str | None = None) -> list[dict[str, Any]]:
        out = self._playbooks
        if query:
            q = query.lower().strip()
            out = [p for p in out if q in str(p.get("name", "")).lower() or q in str(p.get("description", "")).lower()]
        if phase:
            phase_l = phase.lower().strip()
            out = [p for p in out if str(p.get("phase", "")).lower() == phase_l]
        return out[:250]

    def refresh_catalog(self) -> dict[str, Any]:
        before = len(self._playbooks)
        self._load_playbooks()
        after = len(self._playbooks)
        self._last_refresh = time.time()
        return {"before": before, "after": after, "refreshed_at": self._last_refresh}
