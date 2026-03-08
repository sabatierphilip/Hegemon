from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .language_corpus import HannibalLanguageCorpus


@dataclass
class MissionDirective:
    raw_text: str
    intent: str
    target_host: str | None = None
    target_network: str | None = None
    objective: str | None = None
    autonomy_override: str | None = None
    confidence: float = 0.0
    parse_notes: list[str] = field(default_factory=list)
    recommended_drone_role: str | None = None
    codegen_focus: str | None = None
    intel_focus: str | None = None
    mission_style: str | None = None
    enhancement_plan: list[str] = field(default_factory=list)
    english_focus: str | None = None
    drone_build_focus: str | None = None
    custom_drone_requested: bool = False


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
_CIDR_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

_INTENT_PATTERNS: list[tuple[list[str], str, float]] = [
    (["deploy", "launch", "start", "begin", "run", "send", "activate", "unleash", "dispatch"], "deploy_agent", 0.85),
    (["pause", "hold", "stop temporarily", "freeze", "wait"], "pause_campaign", 0.90),
    (["resume", "continue", "unpause", "proceed", "go ahead"], "resume_campaign", 0.90),
    (["abort", "cancel", "kill", "terminate", "end", "shut down", "pull out", "withdraw"], "abort_campaign", 0.88),
    (["target", "attack", "scan", "probe", "investigate", "focus on", "go after", "hit"], "set_target", 0.80),
    (["objective", "goal", "mission", "task", "purpose", "find", "locate", "map", "harvest"], "set_objective", 0.75),
    (["status", "report", "what is", "how is", "update", "progress", "situation"], "query_status", 0.88),
    (["observe only", "watch only", "passive", "no action", "read only"], "adjust_autonomy", 0.92),
    (["enforce", "active", "engage", "take action", "full auto", "autonomous"], "adjust_autonomy", 0.88),
    (["contain", "limited action", "respond only", "defensive"], "adjust_autonomy", 0.85),
]

_AUTONOMY_MAP = {
    "observe only": "observe",
    "watch only": "observe",
    "passive": "observe",
    "no action": "observe",
    "read only": "observe",
    "contain": "contain",
    "limited action": "contain",
    "respond only": "contain",
    "defensive": "contain",
    "enforce": "enforce",
    "active": "enforce",
    "engage": "enforce",
    "take action": "enforce",
    "full auto": "enforce",
    "autonomous": "enforce",
}

_OBJECTIVE_KEYWORDS = [
    "find credentials",
    "harvest credentials",
    "map network",
    "identify targets",
    "locate domain controller",
    "find databases",
    "pivot to",
    "exfiltrate",
    "establish persistence",
    "recon",
    "reconnaissance",
    "enumerate services",
    "identify high value",
    "full campaign",
    "encirclement",
]

_ENGLISH_FOCUS_MAP = {
    "english understanding": "intent_disambiguation",
    "english": "operator_summarization",
    "grammar": "dialogue_repair",
    "comprehension": "constraint_extraction",
    "clarify": "clarification_loop",
}

_DRONE_BUILD_FOCUS_MAP = {
    "drone building": "modular_airframe",
    "custom drone": "custom_drone_synthesis",
    "sensor": "sensor_fusion_stack",
    "power": "power_budgeting",
    "navigation": "redundant_navigation",
}

_CODEGEN_FOCUS_MAP = {
    "code generation": "typed_python_scaffolding",
    "generate code": "test_first_generation",
    "refactor": "refactor_suggestions",
    "template": "config_driven_templates",
}

_INTEL_FOCUS_MAP = {
    "intelligence": "signal_correlation",
    "intel": "telemetry_normalization",
    "hypothesis": "hypothesis_tracking",
    "forensic": "timeline_reconstruction",
}

_MISSION_STYLE_MAP = {
    "mission conduct": "disciplined",
    "stealth": "stealth",
    "aggressive": "aggressive",
    "balanced": "balanced",
    "resilient": "resilient",
}

_SAFETY_FOCUS_MAP = {
    "mission conduct": "human_approval_required",
    "safe": "non_destructive_actions",
    "safety": "simulation_only",
    "non destructive": "non_destructive_actions",
    "audit": "audit_every_decision",
}

_CUSTOM_DRONE_TOKENS = (
    "custom drone",
    "bespoke drone",
    "drone on the fly",
    "create drone",
    "build drone",
)


class HannibalNLPParser:
    def __init__(self) -> None:
        root = Path(__file__).resolve().parents[3]
        corpus_path = root / "config" / "hannibal_language_curriculum.tsv"
        self._corpus = HannibalLanguageCorpus(corpus_path)

    @staticmethod
    def _pick_focus(lower: str, mapping: dict[str, str]) -> str | None:
        for phrase, value in mapping.items():
            if phrase in lower:
                return value
        return None

    def parse(self, text: str) -> MissionDirective:
        lower = text.lower().strip()
        directive = MissionDirective(raw_text=text, intent="unknown", confidence=0.0)

        cidrs = _CIDR_RE.findall(text)
        ips = [ip for ip in _IP_RE.findall(text) if ip not in cidrs]
        if cidrs:
            directive.target_network = cidrs[0]
            directive.parse_notes.append(f"CIDR extracted: {cidrs[0]}")
        if ips:
            directive.target_host = ips[0]
            directive.parse_notes.append(f"IP extracted: {ips[0]}")

        best_intent = "unknown"
        best_conf = 0.0
        for keywords, intent, base_conf in _INTENT_PATTERNS:
            for kw in keywords:
                if kw in lower:
                    score = base_conf + (0.05 if len(kw.split()) > 1 else 0.0)
                    if score > best_conf:
                        best_conf = score
                        best_intent = intent
                    break

        directive.intent = best_intent
        directive.confidence = best_conf

        for phrase, level in _AUTONOMY_MAP.items():
            if phrase in lower:
                directive.autonomy_override = level
                directive.parse_notes.append(f"Autonomy override: {level}")
                if best_intent == "unknown":
                    directive.intent = "adjust_autonomy"
                    directive.confidence = 0.85
                break

        for obj_kw in _OBJECTIVE_KEYWORDS:
            if obj_kw in lower:
                directive.objective = obj_kw
                directive.parse_notes.append(f"Objective keyword: {obj_kw}")
                if directive.intent in ("unknown", "set_target"):
                    directive.intent = "set_objective"
                    directive.confidence = max(directive.confidence, 0.78)
                break

        semantic_matches = self._corpus.semantic_match(text)
        semantic = self._corpus.summarize_axes(semantic_matches)
        if semantic:
            if directive.intent == "unknown" and semantic.get("intent"):
                directive.intent = semantic["intent"]
                directive.confidence = max(directive.confidence, 0.72)
                directive.parse_notes.append(f"Semantic intent: {directive.intent}")

            if not directive.autonomy_override and semantic.get("autonomy"):
                directive.autonomy_override = semantic["autonomy"]
                directive.parse_notes.append(f"Semantic autonomy: {directive.autonomy_override}")

            if not directive.objective and semantic.get("objective"):
                directive.objective = semantic["objective"]
                directive.parse_notes.append(f"Semantic objective: {directive.objective}")

            if semantic.get("drone_role"):
                directive.recommended_drone_role = semantic["drone_role"]
            if semantic.get("codegen_focus"):
                directive.codegen_focus = semantic["codegen_focus"]
            if semantic.get("intel_focus"):
                directive.intel_focus = semantic["intel_focus"]
            if semantic.get("mission_style"):
                directive.mission_style = semantic["mission_style"]

            if semantic_matches:
                directive.parse_notes.append(f"Semantic curriculum matches: {len(semantic_matches)}")

        directive.english_focus = self._pick_focus(lower, _ENGLISH_FOCUS_MAP)
        directive.drone_build_focus = self._pick_focus(lower, _DRONE_BUILD_FOCUS_MAP)
        codegen_focus = self._pick_focus(lower, _CODEGEN_FOCUS_MAP)
        intel_focus = self._pick_focus(lower, _INTEL_FOCUS_MAP)
        mission_style = self._pick_focus(lower, _MISSION_STYLE_MAP)
        safety_focus = self._pick_focus(lower, _SAFETY_FOCUS_MAP)

        if codegen_focus and not directive.codegen_focus:
            directive.codegen_focus = codegen_focus
        if intel_focus and not directive.intel_focus:
            directive.intel_focus = intel_focus
        if mission_style and not directive.mission_style:
            directive.mission_style = mission_style

        directive.custom_drone_requested = any(token in lower for token in _CUSTOM_DRONE_TOKENS)
        if directive.custom_drone_requested:
            directive.parse_notes.append("Custom drone request detected")

        enhancement_plan: list[str] = []
        if directive.english_focus:
            enhancement_plan.append(f"english:{directive.english_focus}")
        if directive.drone_build_focus:
            enhancement_plan.append(f"drone_build:{directive.drone_build_focus}")
        if directive.codegen_focus:
            enhancement_plan.append(f"codegen:{directive.codegen_focus}")
        if directive.intel_focus:
            enhancement_plan.append(f"intelligence:{directive.intel_focus}")
        if directive.mission_style:
            enhancement_plan.append(f"mission:{directive.mission_style}")
        if directive.custom_drone_requested:
            enhancement_plan.append("drone_runtime:custom_builder_enabled")
        if safety_focus:
            enhancement_plan.append(f"safety:{safety_focus}")
        if enhancement_plan:
            directive.enhancement_plan = enhancement_plan
            directive.parse_notes.append(f"Enhancement plan axes: {len(enhancement_plan)}")

        if directive.intent == "unknown" and enhancement_plan:
            directive.intent = "set_objective"
            directive.confidence = max(directive.confidence, 0.70)

        if directive.intent == "set_objective" and not directive.objective:
            directive.objective = text.strip()

        return directive

    def explain(self, directive: MissionDirective) -> str:
        lines = [f"Intent: {directive.intent} (confidence {directive.confidence:.0%})"]
        if directive.target_host:
            lines.append(f"Target host: {directive.target_host}")
        if directive.target_network:
            lines.append(f"Target network: {directive.target_network}")
        if directive.objective:
            lines.append(f"Objective: {directive.objective}")
        if directive.autonomy_override:
            lines.append(f"Autonomy: {directive.autonomy_override}")
        if directive.recommended_drone_role:
            lines.append(f"Recommended drone role: {directive.recommended_drone_role}")
        if directive.codegen_focus:
            lines.append(f"Code generation focus: {directive.codegen_focus}")
        if directive.intel_focus:
            lines.append(f"Intelligence focus: {directive.intel_focus}")
        if directive.mission_style:
            lines.append(f"Mission style: {directive.mission_style}")
        if directive.custom_drone_requested:
            lines.append("Custom drone creation: requested")
        if directive.enhancement_plan:
            lines.append("Enhancement plan:")
            lines.extend([f"- {step}" for step in directive.enhancement_plan])
        lines += [f"Note: {n}" for n in directive.parse_notes]
        if directive.confidence < 0.6:
            lines.append("⚠ Low confidence parse — please confirm before executing.")
        return "\n".join(lines)
