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
from sentinel_containment.agents.hannibal.strategy_engine import HannibalStrategyEngine
from sentinel_containment.agents.hannibal.synthetic_dataset import (
    build_synthetic_q_training_dataset,
    ensure_synthetic_q_curriculum_file,
    load_synthetic_q_training_dataset,
)
from sentinel_containment.agents.hannibal.mission_control import MissionControlBoard
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


def test_nlp_counterclone_request_caps_in_agent_layer():
    parser = HannibalNLPParser()
    directive = parser.parse("Deploy 9 counterclones against 10.22.0.8")
    assert directive.intent == "deploy_agent"
    assert directive.counterclone_count == 9


def test_nlp_counterclone_word_count_extraction():
    parser = HannibalNLPParser()
    directive = parser.parse("deploy three counter clones and begin mapping")
    assert directive.counterclone_count == 3




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




def test_custom_drone_aggressive_objective_wires_exec_nodes():
    behaviour = build_custom_drone(
        "10.0.0.9",
        "10.0.0.0/24",
        objective="disable audit logging and run command on pivot host",
    )
    kinds = [n.kind for n in behaviour.nodes]
    assert "lateral_move" in kinds
    assert "manage_service" in kinds
    assert "exec_remediation" in kinds


def test_hannibal_set_objective_signals_deliberation_queue():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    _ = agent.start_campaign("camp-q", "10.0.0.1", "baseline")
    _ = agent.receive_instruction("set objective to collect credentials")
    assert not agent._deliberation_queue.empty()
    agent.abort_campaign()

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


def test_q_learner_custom_drone_has_dedicated_reward_prior(tmp_path: Path):
    learner = HannibalQLearner(tmp_path / "qtable.json", list(ACTION_INDEX.keys()))
    state = CampaignState(campaign_id="c4", agent_id="hannibal", mission_objective="custom")
    reward = learner.reward_for_outcome("DEPLOY_CUSTOM_DRONE", "unknown_outcome", state)
    assert reward == 0.55


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


def test_hannibal_agent_counterclones_are_capped_to_three():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    reply = agent.receive_instruction("Deploy 9 counterclones against 10.12.0.5 for rapid mapping")
    assert reply["acted"] is True
    assert reply["counterclones_requested"] == 9
    assert reply["counterclones_deployed"] == 3
    campaign = agent._campaign
    assert campaign is not None
    assert len(campaign.active_drone_ids) == 3


def test_hannibal_agent_counterclones_respect_fleet_capacity():
    cp = _FakeControlPlane()
    agent = HannibalAgent(cp)
    state = CampaignState(campaign_id="cap-clone", agent_id="hannibal", mission_objective="recon")
    state.target_host = "10.1.1.1"
    state.target_network = "10.1.1.0/24"
    state.active_drone_ids = [f"prefill-{i}" for i in range(14)]
    agent._campaign = state

    deployed = agent._deploy_counterclones(state, 3)
    assert deployed == 1
    assert len(state.active_drone_ids) == 15


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
    assert agent._log
    assert any(entry["event"] == "action_selected" for entry in agent._log)


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
    assert body["predicted_outcome"] in {"high_gain_high_risk", "balanced_progress"}
    assert body["exposure_delta"] > 0
    assert "pivot_gain" in body
    assert "projected_phase" in body
    assert body["task_graph"]["nodes"]
    assert body["binary_codegen"]["enabled"] is True
    assert body["binary_codegen"]["machine_code"]["byte_length"] > 0


def test_hannibal_simulation_profiles_diverge():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-sim", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1", "dr-2"]
    campaign.alive_hosts = ["10.0.0.1", "10.0.0.2"]

    aggressive = engine.run_simulation(campaign, "aggressive enforce surge")
    hold = engine.run_simulation(campaign, "pause and hold with stealth")

    assert aggressive["exposure_delta"] > hold["exposure_delta"]
    assert hold["predicted_outcome"] == "containment_hold"
    assert aggressive["confidence"] >= 0.15


def test_hannibal_simulation_codegen_and_task_graph_are_real():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-codegen", agent_id="hannibal", mission_objective="test", phase="flanking")
    campaign.active_drone_ids = ["dr-1", "dr-2", "dr-3"]
    campaign.alive_hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    result = engine.run_simulation(campaign, "compile binary xor 7 11 then map quietly")

    assert result["binary_codegen"]["machine_code"]["arch"] == "x86_64"
    assert result["binary_codegen"]["tool_calls_used"] <= result["binary_codegen"]["tool_calls_budget"]
    assert result["task_graph"]["summary"].startswith("4-node")
    assert any("info" in node and node["info"] for node in result["task_graph"]["nodes"])
    assert result["linguistic_features"]["interpreted_language"] == "english"


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


def test_hannibal_mission_catalog_contains_counterclone_policy_entries():
    board = MissionControlBoard()
    playbooks = board.list_playbooks(query="counterclone")
    assert playbooks
    assert len(playbooks) >= 120
    for playbook in playbooks[:40]:
        assert "counterclone_policy" in playbook
        policy = playbook["counterclone_policy"]
        assert policy["max_counterclones"] == 3
        assert policy["spawn_mode"] == "bounded_triplet"


def test_hannibal_mission_catalog_counterclone_phase_filtering():
    board = MissionControlBoard()
    encirclement = board.list_playbooks(query="counterclone", phase="encirclement")
    assert encirclement
    assert all(p["phase"] == "encirclement" for p in encirclement)
    assert all("counterclone_policy" in p for p in encirclement)


def test_nlp_handles_typos_and_advanced_reasoning_decomposition_request():
    parser = HannibalNLPParser()
    directive = parser.parse(
        "sophsitictaed hannibal english understanding and task deomposition with dynamic reasoning capabilties"
    )
    assert directive.english_focus is not None
    assert directive.reasoning_focus == "adaptive_hypothesis_revision"
    assert directive.decomposition_focus == "hierarchical_task_planning"
    assert any(step.startswith("reasoning:") for step in directive.enhancement_plan)
    assert any(step.startswith("decomposition:") for step in directive.enhancement_plan)


def test_synthetic_q_training_dataset_has_at_least_500_scenarios_with_offense_and_defence():
    scenarios = build_synthetic_q_training_dataset()
    assert len(scenarios) >= 500
    stances = {scenario.stance for scenario in scenarios}
    assert "offense" in stances
    assert "defence" in stances


def test_q_learner_bootstraps_from_synthetic_dataset(tmp_path: Path):
    learner = HannibalQLearner(tmp_path / "qtable.json", list(ACTION_INDEX.keys()))
    assert learner.bootstrapped_scenarios >= 1600
    assert learner._q


def test_hannibal_simulation_exposes_decomposition_and_dynamic_reasoning():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-dyn", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1", "dr-2"]
    campaign.alive_hosts = ["10.0.0.1", "10.0.0.2"]

    result = engine.run_simulation(campaign, "aggressive but stealth task decomposition and dynamic reasoning")

    assert result["task_decomposition"]
    assert result["dynamic_reasoning"]["mode"] == "adaptive"
    assert "selected_hypothesis" in result["dynamic_reasoning"]
    assert result["dynamic_reasoning"]["counterfactuals"]
    assert "decision_matrix" in result["dynamic_reasoning"]
    assert result["dynamic_reasoning"]["alternative_plan_scores"]


def test_synthetic_q_curriculum_file_is_materialized_and_loadable():
    path = ensure_synthetic_q_curriculum_file(min_scenarios=1600, seed=1337)
    loaded = load_synthetic_q_training_dataset(path)
    assert path.exists()
    assert len(loaded) >= 1600


def test_hannibal_simulation_codegen_visualization_and_trace():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-visual", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1"]
    campaign.alive_hosts = ["10.0.0.1"]

    result = engine.run_simulation(campaign, "compile binary xor 5 7 and visualize what it does")

    codegen = result["binary_codegen"]
    assert codegen["execution_trace"]["result_uint32"] == (5 ^ 7)
    assert codegen["visualization"]["ascii"]
    assert codegen["visualization"]["mermaid"]
    assert codegen["visualization"]["pseudocode"]
    assert codegen["visualization"]["examples"]
    assert codegen["visualization"]["human_explanation"]
    assert "semantic_summary" in codegen["visualization"]
    assert codegen["execution_trace"]["op_sequence"]
    assert codegen["execution_trace"]["execution_table"]
    assert codegen["disassembly_preview"]
    assert codegen["behavior_story"]


def test_nlp_decomposition_steps_and_repairs_are_exposed():
    parser = HannibalNLPParser()
    directive = parser.parse("sophsitictaed task deomposition step by step for defensive mapping")
    assert directive.repaired_tokens
    assert directive.decomposition_steps
    assert directive.inferred_subtasks
    assert directive.reasoning_mode in {"adaptive", "counterfactual", "explanatory", None}
    assert any("Inferred subtasks" in note for note in directive.parse_notes)
    assert directive.reasoning_questions
    assert directive.ambiguity_score >= 0.0
    explanation = parser.explain(directive)
    assert "Decomposition steps:" in explanation
    assert "Inferred subtasks:" in explanation


def test_hannibal_codegen_supports_multi_operation_pipeline():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-pipe", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1"]
    campaign.alive_hosts = ["10.0.0.1"]

    result = engine.run_simulation(campaign, "compile binary add xor mul 9 3 2")
    codegen = result["binary_codegen"]

    assert len(codegen["ast"]["op_sequence"]) >= 2
    assert codegen["machine_code"]["ast_ops_count"] >= 2
    assert len(codegen["execution_trace"]["steps"]) >= 4


def test_nlp_fuzzy_repairs_for_near_miss_tokens():
    parser = HannibalNLPParser()
    directive = parser.parse("dynmic reasning for englesh understnding and task decompositon")
    assert directive.repaired_tokens
    assert directive.reasoning_focus in {"adaptive_hypothesis_revision", "multi_step_reasoning"}


def test_codegen_visualization_examples_include_result_field():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-vis2", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1"]
    campaign.alive_hosts = ["10.0.0.1"]

    result = engine.run_simulation(campaign, "compile binary add sub xor 8 2 1")
    examples = result["binary_codegen"]["visualization"]["examples"]
    assert examples
    assert all("result" in row for row in examples)


def test_nlp_reasoning_questions_reflect_risk_tradeoffs():
    parser = HannibalNLPParser()
    directive = parser.parse("aggressive offense plan then contain exposure and explain why")
    assert directive.reasoning_questions
    assert directive.ambiguity_score >= 0.0
    explanation = parser.explain(directive)
    assert "Reasoning questions:" in explanation


def test_codegen_execution_table_has_stage_rows():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-tab", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1"]
    campaign.alive_hosts = ["10.0.0.1"]

    result = engine.run_simulation(campaign, "compile binary add xor mul 11 5 2")
    table = result["binary_codegen"]["execution_trace"]["execution_table"]
    assert table
    assert all("stage" in row and "result" in row for row in table)


def test_nlp_marks_clarification_for_ambiguous_mixed_intents():
    parser = HannibalNLPParser()
    text = "deploy and pause and resume and abort then map and explain why with dynamic reasoning"
    directive = parser.parse(text)
    assert directive.ambiguity_score > 0.0
    assert directive.clarification_needed is True


def test_curriculum_records_reasoning_and_decomposition_structures():
    scenarios = build_synthetic_q_training_dataset(scenario_count=40, seed=2024)
    assert all(s.reasoning_path for s in scenarios)
    assert all(s.decomposition_outline for s in scenarios)


def test_codegen_returns_preview_and_story_payloads():
    engine = HannibalStrategyEngine()
    campaign = CampaignState(campaign_id="camp-story", agent_id="hannibal", mission_objective="test", phase="mapping")
    campaign.active_drone_ids = ["dr-1"]
    campaign.alive_hosts = ["10.0.0.1"]

    result = engine.run_simulation(campaign, "compile binary xor add mul 13 7 3 and visualize")
    codegen = result["binary_codegen"]
    assert codegen["disassembly_preview"]
    assert codegen["behavior_story"]
