from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sentinel_containment.agents.hannibal.agent import HannibalAgent
from sentinel_containment.agents.hannibal.campaign_state import CampaignState
from sentinel_containment.agents.hannibal.clips_bridge import ClipsBridge
from sentinel_containment.agents.hannibal.doctrine_defaults import ACTION_INDEX
from sentinel_containment.agents.hannibal.drone_factory import (
    build_encircler,
    build_flanker,
    build_harvester,
    build_mapper,
    build_scout,
    build_striker,
    build_watchdog,
    build_custom_drone,
)
from sentinel_containment.agents.hannibal.nlp_parser import HannibalNLPParser
from sentinel_containment.agents.hannibal.q_learner import HannibalQLearner
from sentinel_containment.web.app import app as web_app


class _FakeDrone:
    def __init__(self, drone_id: str, *, status: str = "ready", findings: list[str] | None = None, telemetry: list[dict[str, Any]] | None = None):
        self.drone_id = drone_id
        self.status = status
        self.findings = findings or []
        self.telemetry = telemetry or []
        self.launched_at = None


class _FakeControlPlane:
    def __init__(self) -> None:
        self.drones: dict[str, _FakeDrone] = {}
        self._counter = 0

    def assemble_drone(
        self,
        *,
        name: str,
        tier: str,
        mission: str,
        behaviour: Any,
        target_host: str,
        target_network: str,
        autonomy_level: str,
        ttl_seconds: int,
        checkin_interval_seconds: int,
        actor: str,
    ) -> _FakeDrone:
        self._counter += 1
        drone_id = f"d-{self._counter}"
        drone = _FakeDrone(drone_id)
        self.drones[drone_id] = drone
        return drone

    def launch_drone(self, drone_id: str, actor: str) -> _FakeDrone:
        drone = self.drones[drone_id]
        drone.status = "launched"
        drone.launched_at = time.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return drone

    def terminate_drone(self, drone_id: str, actor: str) -> _FakeDrone:
        drone = self.drones[drone_id]
        drone.status = "terminated"
        return drone

    def recall_drone(self, drone_id: str, actor: str) -> _FakeDrone:
        drone = self.drones[drone_id]
        drone.status = "terminated"
        return drone


def test_nlp_deploy_intent():
    parser = HannibalNLPParser()
    directive = parser.parse("Deploy Hannibal against 10.0.1.5 — full recon")
    assert directive.intent == "deploy_agent"
    assert directive.target_host == "10.0.1.5"
    assert directive.confidence >= 0.80


def test_nlp_abort_intent():
    parser = HannibalNLPParser()
    directive = parser.parse("Abort the campaign and withdraw all drones")
    assert directive.intent == "abort_campaign"
    assert directive.confidence >= 0.85


def test_nlp_autonomy_override():
    parser = HannibalNLPParser()
    directive = parser.parse("Target 192.168.0.0/24, enforce mode, map network")
    assert directive.autonomy_override == "enforce"
    assert directive.target_network == "192.168.0.0/24"


def test_nlp_status_query():
    parser = HannibalNLPParser()
    directive = parser.parse("What is the current status?")
    assert directive.intent == "query_status"


def test_nlp_semantic_curriculum_enrichment():
    parser = HannibalNLPParser()
    directive = parser.parse(
        "Initiate Hannibal strategically to improve english comprehension and generate mission scripts "
        "on segment 22.99.0.0/24 with analyst drones"
    )
    assert directive.intent in {"deploy_agent", "set_objective", "adjust_autonomy"}
    assert directive.target_network == "22.99.0.0/24"
    assert directive.codegen_focus is not None
    assert directive.intel_focus is not None
    assert directive.mission_style is not None
    assert directive.recommended_drone_role is not None




def test_nlp_capability_enhancement_plan_includes_all_axes():
    parser = HannibalNLPParser()
    directive = parser.parse(
        "Upgrade Hannibal english understanding, drone building, code generation, mission intelligence, and mission conduct"
    )
    assert directive.enhancement_plan
    assert any(step.startswith("english:") for step in directive.enhancement_plan)
    assert any(step.startswith("drone_build:") for step in directive.enhancement_plan)
    assert any(step.startswith("codegen:") for step in directive.enhancement_plan)
    assert any(step.startswith("intelligence:") for step in directive.enhancement_plan)
    assert any(step.startswith("mission:") for step in directive.enhancement_plan)
    assert any(step.startswith("safety:") for step in directive.enhancement_plan)


def test_nlp_explain_renders_enhancement_plan():
    parser = HannibalNLPParser()
    directive = parser.parse("Improve Hannibal english understanding and code generation")
    explanation = parser.explain(directive)
    assert "Enhancement plan:" in explanation

def test_nlp_cidr_extraction():
    parser = HannibalNLPParser()
    directive = parser.parse("Scan 10.0.0.0/24 and find credentials")
    assert directive.target_network == "10.0.0.0/24"


def test_campaign_state_to_q_vector():
    state = CampaignState(campaign_id="c1", agent_id="hannibal", mission_objective="test")
    vector = state.to_q_vector()
    assert len(vector) == 5
    assert all(0 <= v <= 4 for v in vector)


def test_campaign_state_advance_phase():
    state = CampaignState(campaign_id="c1", agent_id="hannibal", mission_objective="test")
    state.advance_phase("reconnaissance")
    assert state.phase == "reconnaissance"


def test_campaign_state_clips_facts():
    state = CampaignState(campaign_id="c1", agent_id="hannibal", mission_objective="test")
    state.advance_phase("mapping")
    facts = state.to_clips_facts()
    assert any("campaign-state" in f for f in facts)
    assert any("mapping" in f for f in facts)


def test_campaign_state_telemetry_extraction():
    state = CampaignState(campaign_id="c1", agent_id="hannibal", mission_objective="test")
    telemetry = [
        {
            "kind": "lateral_move",
            "host": "10.0.0.2",
            "source_host": "10.0.0.1",
            "target_host": "10.0.0.2",
            "method": "ssh_hop",
        },
        {
            "kind": "pivot_plan",
            "source": "10.0.0.1",
            "target": "10.0.0.3",
            "confidence": 0.8,
            "method": "smb",
        },
        {"kind": "host_profile", "host": "10.0.0.2", "role": "dc", "services": ["ldap"]},
        {
            "kind": "credential_probe",
            "host": "10.0.0.2",
            "key": "db_password",
            "value": "redacted",
        },
    ]
    findings = ["credential_probe found KEY=ABC", "SIEM detection event seen"]
    state.update_from_drone_telemetry("d1", telemetry, findings)

    assert "10.0.0.2" in state.alive_hosts
    assert state.credential_findings
    assert state.pivot_chains
    assert "10.0.0.2" in state.high_value_targets
    assert state.detection_events >= 1


def test_campaign_state_roundtrip_serialization():
    state = CampaignState(campaign_id="c2", agent_id="hannibal", mission_objective="roundtrip")
    state.target_host = "10.10.10.10"
    state.alive_hosts.append("10.10.10.11")
    encoded = state.serialize()
    restored = CampaignState.deserialize(encoded)
    assert restored.campaign_id == state.campaign_id
    assert restored.target_host == "10.10.10.10"
    assert restored.alive_hosts == ["10.10.10.11"]


def test_clips_bridge_loads_and_evaluates():
    bridge = ClipsBridge()
    state = CampaignState(campaign_id="c3", agent_id="hannibal", mission_objective="initial recon")
    decisions = bridge.evaluate(state)
    assert isinstance(decisions, list)
    assert any(d["action"] == "DEPLOY_SCOUT" for d in decisions)


def test_q_learner_update(tmp_path: Path):
    learner = HannibalQLearner(tmp_path / "qtable.json", list(ACTION_INDEX.keys()))
    state = (0, 0, 0, 0, 0)
    next_state = (1, 1, 0, 0, 1)
    learner.update(state, "DEPLOY_SCOUT", 0.5, next_state)
    row = learner._q_row(state)
    assert row[ACTION_INDEX["DEPLOY_SCOUT"]] > 0.0


def test_q_learner_select_action(tmp_path: Path):
    learner = HannibalQLearner(tmp_path / "qtable.json", list(ACTION_INDEX.keys()))
    action = learner.select_action((0, 0, 0, 0, 0), ["DEPLOY_SCOUT"])
    assert action in ACTION_INDEX


def test_q_learner_persists(tmp_path: Path):
    path = tmp_path / "qtable.json"
    q1 = HannibalQLearner(path, list(ACTION_INDEX.keys()))
    q1.update((0, 0, 0, 0, 0), "DEPLOY_SCOUT", 1.0, (1, 0, 0, 0, 0))
    q1._save()

    q2 = HannibalQLearner(path, list(ACTION_INDEX.keys()))
    assert q2._episode == q1._episode


def test_drone_factory_all_types():
    _ = build_flanker("10.0.0.1", "ssh_hop")
    for builder in [build_scout, build_mapper, build_harvester, build_encircler, build_striker, build_watchdog]:
        behaviour = builder("10.0.0.1")
        assert behaviour.nodes
        assert any(n.kind == "on_launch" for n in behaviour.nodes)


def test_drone_factory_scout_has_subnet_scan():
    behaviour = build_scout("10.0.0.1", "10.0.0.0/24")
    assert any(n.kind == "subnet_scan" for n in behaviour.nodes)


def test_drone_factory_striker_has_self_destruct():
    behaviour = build_striker("10.0.0.1")
    assert any(n.kind in ("self_destruct", "self_terminate") for n in behaviour.nodes)


def test_drone_factory_harvester_ends_with_destruct():
    behaviour = build_harvester("10.0.0.1")
    assert behaviour.nodes[-1].kind in ("self_destruct", "self_terminate")




def test_drone_factory_custom_drone_runtime_builder():
    behaviour = build_custom_drone(
        "10.0.0.1",
        "10.0.0.0/24",
        objective="map network and harvest credentials",
        codegen_focus="typed_python_scaffolding",
        intel_focus="signal_correlation",
        mission_style="aggressive",
        english_focus="intent_disambiguation",
    )
    kinds = [n.kind for n in behaviour.nodes]
    assert "subnet_scan" in kinds
    assert "credential_probe" in kinds
    assert kinds.count("send_report") >= 2


def test_hannibal_agent_supports_custom_drone_instruction():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    reply = agent.receive_instruction(
        "Deploy Hannibal against 10.12.0.5 and create custom drone on the fly for code generation and intelligence"
    )
    assert reply["acted"] is True
    campaign = agent._campaign
    assert campaign is not None
    assert campaign.active_drone_ids
    order_actions = [order["action"] for order in campaign.drone_orders]
    assert "DEPLOY_CUSTOM_DRONE" in order_actions


def test_hannibal_agent_fleet_cap_is_15():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    state = CampaignState(campaign_id="cap-15", agent_id="hannibal", mission_objective="recon")
    state.target_host = "10.1.1.1"
    state.target_network = "10.1.1.0/24"
    agent._campaign = state

    for _ in range(16):
        agent._execute_action("DEPLOY_SCOUT", state, "test")

    assert len(state.active_drone_ids) == 15

def test_hannibal_agent_start_and_status():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    campaign = agent.start_campaign("camp-1", "10.0.0.1", "map network")
    assert campaign.campaign_id == "camp-1"
    status = agent.status()
    assert status["state"] in {"running", "paused"}
    assert status["campaign_id"] == "camp-1"
    agent.abort_campaign()


def test_hannibal_agent_instruction_flow():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)

    deploy = agent.receive_instruction("Deploy Hannibal against 10.5.5.5 and map network")
    assert deploy["acted"] is True
    assert "campaign_id" in deploy

    pause = agent.receive_instruction("pause the campaign")
    assert pause["acted"] is True

    resume = agent.receive_instruction("resume operations")
    assert resume["acted"] is True

    query = agent.receive_instruction("what is status")
    assert query["acted"] is True
    assert "status" in query

    abort = agent.receive_instruction("abort campaign")
    assert abort["acted"] is True


def test_hannibal_agent_deliberation_deploys_drone():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    state = CampaignState(campaign_id="camp-2", agent_id="hannibal", mission_objective="recon")
    state.target_host = "10.9.9.9"
    state.target_network = "10.9.9.0/24"
    agent._campaign = state
    agent._deliberate()
    assert len(state.active_drone_ids) >= 1


def test_hannibal_api_endpoints(monkeypatch):
    # bypass auth for endpoint contract validation
    monkeypatch.setattr("sentinel_containment.web.app._is_authenticated", lambda: True)
    monkeypatch.setattr("sentinel_containment.web.app._hannibal", None)

    client = web_app.test_client()
    base_headers = {"Origin": "http://localhost", "Content-Type": "application/json"}

    resp_instruct = client.post(
        "/api/agents/hannibal/instruct",
        json={"text": "Deploy Hannibal against 10.0.0.8"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert resp_instruct.status_code == 200

    for endpoint, method in [
        ("/api/agents/hannibal/status", "get"),
        ("/api/agents/hannibal/campaign", "get"),
        ("/api/agents/hannibal/log", "get"),
        ("/api/agents/hannibal/qtable", "get"),
        ("/api/agents/hannibal/briefing", "get"),
        ("/api/agents/hannibal/pause", "post"),
        ("/api/agents/hannibal/resume", "post"),
        ("/api/agents/hannibal/abort", "post"),
    ]:
        fn = getattr(client, method)
        kwargs = {
            "headers": base_headers,
            "environ_base": {"REMOTE_ADDR": "127.0.0.1"},
        }
        if method == "post":
            kwargs["data"] = "{}"
        response = fn(endpoint, **kwargs)
        assert response.status_code == 200


def test_hannibal_simulation_endpoint(monkeypatch):
    monkeypatch.setattr("sentinel_containment.web.app._is_authenticated", lambda: True)
    monkeypatch.setattr("sentinel_containment.web.app._hannibal", None)

    client = web_app.test_client()
    base_headers = {"Origin": "http://localhost", "Content-Type": "application/json"}

    client.post(
        "/api/agents/hannibal/instruct",
        json={"text": "Deploy Hannibal against 10.0.0.8"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    resp = client.post(
        "/api/agents/hannibal/simulate",
        json={"directive": "Shift to aggressive encirclement and enforce mode"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["predicted_outcome"] == "high_gain_high_risk"
    assert body["host_gain"] >= 1


def test_hannibal_briefing_in_status():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    agent.start_campaign("camp-risk", "10.0.0.4", "collect credentials")
    status = agent.status()
    assert "risk_score" in status
    assert "risk_band" in status
    assert "phase_velocity" in status
    agent.abort_campaign()


def test_hannibal_mission_control_workflow(monkeypatch):
    monkeypatch.setattr("sentinel_containment.web.app._is_authenticated", lambda: True)
    monkeypatch.setattr("sentinel_containment.web.app._hannibal", None)

    client = web_app.test_client()
    base_headers = {"Origin": "http://localhost", "Content-Type": "application/json"}

    client.post(
        "/api/agents/hannibal/instruct",
        json={"text": "Deploy Hannibal against 10.0.0.9 map network"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )

    create_task = client.post(
        "/api/agents/hannibal/mission-control/task",
        json={"title": "Validate dc pivot", "owner": "alpha", "priority": "high", "notes": ["seed note"]},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert create_task.status_code == 200
    task = create_task.get_json()

    update_task = client.patch(
        f"/api/agents/hannibal/mission-control/task/{task['task_id']}",
        json={"status": "in_progress", "append_note": "investigating"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert update_task.status_code == 200

    issue_order = client.post(
        "/api/agents/hannibal/mission-control/order",
        json={"action": "DEPLOY_SCOUT", "rationale": "expand map"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert issue_order.status_code == 200
    order = issue_order.get_json()

    close_order = client.post(
        f"/api/agents/hannibal/mission-control/order/{order['order_id']}/close",
        json={"outcome": "executed"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert close_order.status_code == 200

    directive = client.post(
        "/api/agents/hannibal/mission-control/directive",
        json={"title": "Contain", "objective": "stabilize", "mode": "balanced"},
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert directive.status_code == 200

    state = client.get(
        "/api/agents/hannibal/mission-control/state",
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert state.status_code == 200
    body = state.get_json()
    assert body["tasking"]["open"] >= 1
    assert len(body["playbooks"]) > 0

    decision_log = client.get(
        "/api/agents/hannibal/mission-control/decision-log",
        headers=base_headers,
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    )
    assert decision_log.status_code == 200
    assert decision_log.get_json()["log"]


def test_hannibal_mission_control_agent_methods():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    agent.start_campaign("camp-ops", "10.0.0.11", "campaign")
    task = agent.mission_control_create_task({"title": "map hvt", "owner": "ops", "priority": "high"})
    assert task["task_id"].startswith("task-")
    order = agent.mission_control_issue_order("DEPLOY_MAPPER", "needed", payload={"window": 60})
    assert order["action"] == "DEPLOY_MAPPER"
    closed = agent.mission_control_close_order(order["order_id"], "done")
    assert closed["state"] == "closed"
    directive = agent.mission_control_register_directive({"title": "Directive", "objective": "Expand"})
    assert directive["directive_id"].startswith("directive-")
    snapshot = agent.mission_control_snapshot()
    assert "campaign" in snapshot
    assert "tasks" in snapshot
    assert snapshot["playbooks"]
    agent.abort_campaign()
