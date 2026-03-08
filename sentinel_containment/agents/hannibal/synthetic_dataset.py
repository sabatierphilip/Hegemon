from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path


StateKey = tuple[int, int, int, int, int]


@dataclass(frozen=True)
class QTrainingScenario:
    scenario_id: str
    stance: str
    directive: str
    state: StateKey
    action: str
    reward: float
    next_state: StateKey
    reasoning_path: list[str]
    decomposition_outline: list[str]


_ACTIONS_BY_STANCE: dict[str, list[str]] = {
    "offense": [
        "DEPLOY_SCOUT",
        "DEPLOY_MAPPER",
        "DEPLOY_FLANKER",
        "DEPLOY_HARVESTER",
        "DEPLOY_ENCIRCLER",
        "DEPLOY_STRIKER",
        "SPAWN_CHILD_SWARM",
        "ADVANCE_PHASE_RECONNAISSANCE",
        "ADVANCE_PHASE_MAPPING",
        "ADVANCE_PHASE_FLANKING",
        "ADVANCE_PHASE_ENCIRCLEMENT",
        "ADVANCE_PHASE_EXPLOITATION",
        "DEPLOY_CUSTOM_DRONE",
    ],
    "defence": [
        "DEPLOY_WATCHDOG",
        "RECALL_ALL_DRONES",
        "TERMINATE_HIGHEST_RISK_DRONE",
        "ADVANCE_PHASE_WITHDRAWAL",
        "DEPLOY_SCOUT",
        "DEPLOY_MAPPER",
        "DEPLOY_CUSTOM_DRONE",
    ],
}

_OPERATIONAL_MOTIFS = {
    "offense": [
        "encirclement burst",
        "credential surge",
        "pivot chain widening",
        "high-value hunt",
        "rapid exploitation",
    ],
    "defence": [
        "exposure suppression",
        "detection damping",
        "containment lock",
        "safe withdrawal",
        "telemetry hardening",
    ],
}

_OFFENSE_TEMPLATES = [
    "Drive {motif} on {target}: {action}, then {follow_up}, under {mode} tempo.",
    "Exploit pivot lanes around {target} with {action}; keep {mode} profile and {follow_up}.",
    "Aggressively advance toward {target} via {action}, execute {follow_up}, maximize campaign momentum.",
]

_DEFENCE_TEMPLATES = [
    "Stabilize around {target}: trigger {action}, apply {follow_up}, maintain {mode} containment.",
    "Reduce signature near {target} by {action}, then {follow_up}, preserving {mode} discipline.",
    "Hold defensive perimeter for {target} using {action}; enforce {follow_up} and audit exposure.",
]

_FOLLOW_UPS = {
    "offense": [
        "expand host graph",
        "harvest credentials",
        "prepare exploitation route",
        "map lateral pathways",
    ],
    "defence": [
        "re-evaluate risk window",
        "recall noisy assets",
        "freeze unsafe pivots",
        "verify containment checkpoints",
    ],
}

_TARGETS = [
    "10.10.0.0/24",
    "10.21.4.0/24",
    "172.16.8.0/24",
    "192.168.40.0/24",
    "10.55.12.0/24",
    "10.90.1.0/24",
    "172.30.14.0/24",
    "10.64.2.0/24",
]

_MODES = ["stealth", "balanced", "rapid", "resilient", "low-noise", "adaptive"]


def _clamp_state(value: int) -> int:
    return max(0, min(4, value))


def _reward_for(stance: str, action: str, state: StateKey, next_state: StateKey) -> float:
    phase, exposure, detections, active, objective_pressure = state
    n_phase, n_exposure, n_detections, n_active, n_objective = next_state

    if stance == "offense":
        reward = 0.42
        reward += phase * 0.07
        reward += objective_pressure * 0.05
        reward += max(0, n_phase - phase) * 0.09
        reward += max(0, n_active - active) * 0.04
        reward -= exposure * 0.045
        reward -= detections * 0.04
        if action in {"DEPLOY_HARVESTER", "DEPLOY_STRIKER", "ADVANCE_PHASE_EXPLOITATION", "SPAWN_CHILD_SWARM"}:
            reward += 0.08
        reward -= max(0, n_exposure - exposure) * 0.02
    else:
        reward = 0.4
        reward += exposure * 0.08
        reward += detections * 0.06
        reward += max(0, exposure - n_exposure) * 0.08
        reward += max(0, detections - n_detections) * 0.07
        reward += max(0, objective_pressure - n_objective) * 0.02
        reward -= max(0, n_active - active) * 0.03
        if action in {"RECALL_ALL_DRONES", "ADVANCE_PHASE_WITHDRAWAL", "DEPLOY_WATCHDOG", "TERMINATE_HIGHEST_RISK_DRONE"}:
            reward += 0.1

    return round(max(-1.0, min(1.6, reward)), 4)


def _sample_state(rng: random.Random) -> StateKey:
    return (rng.randrange(5), rng.randrange(5), rng.randrange(5), rng.randrange(5), rng.randrange(5))


def _transition_state(rng: random.Random, stance: str, state: StateKey) -> StateKey:
    phase, exposure, detections, active, objective_pressure = state
    if stance == "offense":
        return (
            _clamp_state(phase + rng.choice([0, 1, 1])),
            _clamp_state(exposure + rng.choice([-1, 0, 0, 1])),
            _clamp_state(detections + rng.choice([-1, 0, 1])),
            _clamp_state(active + rng.choice([0, 1])),
            _clamp_state(objective_pressure + rng.choice([0, 1])),
        )
    return (
        _clamp_state(phase + rng.choice([-1, 0, 0])),
        _clamp_state(exposure + rng.choice([-1, -1, 0])),
        _clamp_state(detections + rng.choice([-1, -1, 0, 1])),
        _clamp_state(active + rng.choice([-1, 0])),
        _clamp_state(objective_pressure + rng.choice([-1, 0, 0, 1])),
    )


def _build_directive(rng: random.Random, stance: str, action: str) -> str:
    template = rng.choice(_OFFENSE_TEMPLATES if stance == "offense" else _DEFENCE_TEMPLATES)
    return template.format(
        motif=rng.choice(_OPERATIONAL_MOTIFS[stance]),
        target=rng.choice(_TARGETS),
        action=action.lower(),
        follow_up=rng.choice(_FOLLOW_UPS[stance]),
        mode=rng.choice(_MODES),
    )




def _build_reasoning_path(stance: str, action: str, state: StateKey, next_state: StateKey) -> list[str]:
    phase, exposure, detections, _, objective_pressure = state
    n_phase, n_exposure, n_detections, _, _ = next_state
    path = [
        f"assess_phase:{phase}",
        f"evaluate_signal:exposure={exposure},detections={detections}",
        f"choose_action:{action.lower()}",
    ]
    if stance == "offense":
        path.append("optimize_gain_under_risk")
        if n_phase > phase:
            path.append("confirm_phase_progression")
    else:
        path.append("optimize_safety_under_objective_pressure")
        if n_exposure < exposure or n_detections < detections:
            path.append("confirm_risk_reduction")
    path.append(f"project_outcome:phase={n_phase},exp={n_exposure},det={n_detections},obj={objective_pressure}")
    return path


def _build_decomposition_outline(stance: str, directive: str) -> list[str]:
    base = [
        "parse_directive",
        "extract_constraints",
        "score_action_candidates",
        "emit_execution_subtasks",
    ]
    if stance == "offense":
        base.insert(3, "insert_stealth_checkpoint")
    else:
        base.insert(3, "insert_containment_checkpoint")
    if "then" in directive or ";" in directive:
        base.append("sequence_multistage_subtasks")
    base.append("finalize_plan")
    return base

def build_synthetic_q_training_dataset(
    *,
    scenario_count: int = 1600,
    seed: int = 1337,
) -> list[QTrainingScenario]:
    """Generate a diverse synthetic curriculum for Hannibal warm-start training.

    The generator uses a seeded stochastic grammar to produce broad directive/state
    coverage while keeping reproducibility for testability.
    """
    rng = random.Random(seed)
    scenarios: list[QTrainingScenario] = []

    for idx in range(scenario_count):
        stance = "offense" if idx % 2 == 0 else "defence"
        action = rng.choice(_ACTIONS_BY_STANCE[stance])
        state = _sample_state(rng)
        next_state = _transition_state(rng, stance, state)
        directive = _build_directive(rng, stance, action)

        scenarios.append(
            QTrainingScenario(
                scenario_id=f"{stance}-{idx:04d}",
                stance=stance,
                directive=directive,
                state=state,
                action=action,
                reward=_reward_for(stance, action, state, next_state),
                next_state=next_state,
                reasoning_path=_build_reasoning_path(stance, action, state, next_state),
                decomposition_outline=_build_decomposition_outline(stance, directive),
            )
        )

    return scenarios


def write_synthetic_q_training_dataset(path: Path, scenarios: list[QTrainingScenario]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for scenario in scenarios:
            handle.write(json.dumps(asdict(scenario), separators=(",", ":")) + "\n")


def load_synthetic_q_training_dataset(path: Path) -> list[QTrainingScenario]:
    if not path.exists():
        return []

    loaded: list[QTrainingScenario] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            row = raw.strip()
            if not row:
                continue
            data = json.loads(row)
            loaded.append(
                QTrainingScenario(
                    scenario_id=str(data["scenario_id"]),
                    stance=str(data["stance"]),
                    directive=str(data["directive"]),
                    state=tuple(data["state"]),
                    action=str(data["action"]),
                    reward=float(data["reward"]),
                    next_state=tuple(data["next_state"]),
                    reasoning_path=list(data.get("reasoning_path", [])),
                    decomposition_outline=list(data.get("decomposition_outline", [])),
                )
            )
    return loaded


def default_curriculum_path() -> Path:
    root = Path(__file__).resolve().parents[3]
    return root / "config" / "hannibal_q_curriculum.jsonl"


def ensure_synthetic_q_curriculum_file(*, min_scenarios: int = 1600, seed: int = 1337) -> Path:
    path = default_curriculum_path()
    existing = load_synthetic_q_training_dataset(path)
    if len(existing) >= min_scenarios:
        return path

    scenarios = build_synthetic_q_training_dataset(scenario_count=min_scenarios, seed=seed)
    write_synthetic_q_training_dataset(path, scenarios)
    return path
