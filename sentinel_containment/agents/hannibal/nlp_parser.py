from __future__ import annotations

import difflib
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
    counterclone_count: int = 0
    reasoning_focus: str | None = None
    decomposition_focus: str | None = None
    decomposition_steps: list[str] = field(default_factory=list)
    repaired_tokens: list[str] = field(default_factory=list)
    inferred_subtasks: list[str] = field(default_factory=list)
    reasoning_mode: str | None = None
    reasoning_questions: list[str] = field(default_factory=list)
    ambiguity_score: float = 0.0
    clarification_needed: bool = False


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
    "sophisticated english understanding": "deep_intent_disambiguation",
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

_COUNTERCLONE_TOKENS = (
    "counterclone",
    "counter clone",
    "counter-clone",
    "counterclones",
    "counter clones",
)

_COUNTERCLONE_WORD_TO_INT = {
    "one": 1,
    "two": 2,
    "three": 3,
}

_REASONING_FOCUS_MAP = {
    "dynamic reasoning": "adaptive_hypothesis_revision",
    "reasoning": "multi_step_reasoning",
    "chain of thought": "structured_reasoning",
    "what if": "counterfactual_reasoning",
}

_DECOMPOSITION_FOCUS_MAP = {
    "task decomposition": "hierarchical_task_planning",
    "decomposition": "objective_graph_planning",
    "break down": "objective_graph_planning",
    "step by step": "sequential_task_planning",
}

_COMMON_TYPO_REPLACEMENTS = {
    "sophsitictaed": "sophisticated",
    "deomposition": "decomposition",
    "extesnsively": "extensively",
    "signifcnalty": "significantly",
    "syntethic": "synthetic",
    "capabilties": "capabilities",
    "incredbibly": "incredibly",
    "enreation": "generation",
    "shud": "should",
}


_REASONING_MODE_MAP = {
    "what if": "counterfactual",
    "simulate": "counterfactual",
    "adaptive": "adaptive",
    "dynamic": "adaptive",
    "explain": "explanatory",
    "why": "explanatory",
}

_SUBTASK_HINTS = (
    "then",
    "after",
    "before",
    "while",
    "and",
    "followed by",
)


_DIRECTIVE_VOCAB = {
    "english", "understanding", "task", "decomposition", "reasoning", "dynamic", "offense", "defence",
    "deploy", "simulate", "visualize", "code", "generation", "binary", "campaign", "aggressive", "defensive",
}

_FUZZY_CANONICAL = {
    "deomposition": "decomposition",
    "sophsitictaed": "sophisticated",
    "signifcnalty": "significantly",
    "incredbibly": "incredibly",
}


class HannibalNLPParser:
    def __init__(self) -> None:
        root = Path(__file__).resolve().parents[3]
        corpus_path = root / "config" / "hannibal_language_curriculum.tsv"
        self._corpus = HannibalLanguageCorpus(corpus_path)

    @staticmethod
    def _normalize_text(text: str) -> tuple[str, list[str]]:
        normalized = text.lower()
        repairs: list[str] = []
        for typo, correct in _COMMON_TYPO_REPLACEMENTS.items():
            if typo in normalized:
                normalized = normalized.replace(typo, correct)
                repairs.append(f"{typo}->{correct}")

        # lightweight fuzzy repair for frequent command words and core directive vocabulary
        tokens = normalized.split()
        for i, tok in enumerate(tokens):
            if tok in _FUZZY_CANONICAL:
                repairs.append(f"{tok}->{_FUZZY_CANONICAL[tok]}")
                tokens[i] = _FUZZY_CANONICAL[tok]
                continue
            if len(tok) >= 6 and tok.isalpha() and tok not in _DIRECTIVE_VOCAB:
                closest = difflib.get_close_matches(tok, list(_DIRECTIVE_VOCAB), n=1, cutoff=0.84)
                if closest:
                    repairs.append(f"{tok}->{closest[0]}")
                    tokens[i] = closest[0]
        normalized = " ".join(tokens)
        return normalized, repairs

    @staticmethod
    def _pick_focus(lower: str, mapping: dict[str, str]) -> str | None:
        for phrase, value in mapping.items():
            if phrase in lower:
                return value
        return None

    @staticmethod
    def _derive_decomposition_steps(lower: str) -> list[str]:
        steps = [
            "interpret_operator_goal",
            "extract_constraints",
            "construct_subtasks",
            "rank_by_risk_and_value",
            "emit_execution_plan",
        ]
        if "defen" in lower or "contain" in lower:
            steps.insert(3, "insert_containment_checkpoint")
        if "offen" in lower or "aggressive" in lower or "enforce" in lower:
            steps.insert(3, "insert_momentum_checkpoint")
        return steps

    @staticmethod
    def _infer_subtasks(lower: str) -> list[str]:
        normalized = lower
        for token in _SUBTASK_HINTS:
            normalized = normalized.replace(token, "|")
        parts = [p.strip() for p in normalized.split("|") if p.strip()]
        subtasks = []
        for part in parts:
            if len(part.split()) >= 2:
                subtasks.append(part)
        return subtasks[:6]

    @staticmethod
    def _build_reasoning_questions(lower: str, subtasks: list[str]) -> list[str]:
        questions: list[str] = []
        if "offen" in lower or "aggressive" in lower:
            questions.append("What containment control offsets offensive expansion risk?")
        if "defen" in lower or "contain" in lower:
            questions.append("What mission objective can still progress under strict containment?")
        if "code" in lower or "binary" in lower:
            questions.append("How should generated code behavior be validated before deployment?")
        if len(subtasks) >= 2:
            questions.append("Which subtask ordering minimizes detection pressure?")
        if not questions:
            questions.append("Which interpretation of intent best matches operator constraints?")
        return questions[:4]

    @staticmethod
    def _compute_ambiguity(intent_hits: int, subtasks: list[str], repaired_tokens: list[str]) -> float:
        score = 0.0
        if intent_hits > 1:
            score += min(0.6, intent_hits * 0.18)
        if len(subtasks) > 4:
            score += 0.15
        if len(repaired_tokens) >= 3:
            score += 0.15
        return round(min(1.0, score), 3)

    def parse(self, text: str) -> MissionDirective:
        lower, repaired = self._normalize_text(text)
        lower = lower.strip()
        directive = MissionDirective(raw_text=text, intent="unknown", confidence=0.0)
        directive.repaired_tokens = repaired
        if repaired:
            directive.parse_notes.append(f"Token repairs applied: {len(repaired)}")

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
        intent_hits = 0
        for keywords, intent, base_conf in _INTENT_PATTERNS:
            for kw in keywords:
                if kw in lower:
                    intent_hits += 1
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

        semantic_matches = self._corpus.semantic_match(lower)
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
        directive.reasoning_focus = self._pick_focus(lower, _REASONING_FOCUS_MAP)
        directive.decomposition_focus = self._pick_focus(lower, _DECOMPOSITION_FOCUS_MAP)
        directive.drone_build_focus = self._pick_focus(lower, _DRONE_BUILD_FOCUS_MAP)
        directive.reasoning_mode = self._pick_focus(lower, _REASONING_MODE_MAP)
        if directive.reasoning_mode:
            directive.parse_notes.append(f"Reasoning mode inferred: {directive.reasoning_mode}")
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

        counterclone_requested = any(token in lower for token in _COUNTERCLONE_TOKENS)
        if counterclone_requested:
            requested_count = 1
            digit_match = re.search(r"\b([1-9])\b", lower)
            if digit_match:
                requested_count = int(digit_match.group(1))
            else:
                for word, value in _COUNTERCLONE_WORD_TO_INT.items():
                    if re.search(rf"\b{re.escape(word)}\b", lower):
                        requested_count = value
                        break
            directive.counterclone_count = requested_count
            directive.parse_notes.append(f"Counterclone request detected: {requested_count}")
            if directive.intent == "unknown":
                directive.intent = "deploy_agent"
                directive.confidence = max(directive.confidence, 0.74)

        if directive.decomposition_focus or "task" in lower:
            directive.decomposition_steps = self._derive_decomposition_steps(lower)
        directive.inferred_subtasks = self._infer_subtasks(lower)
        if directive.inferred_subtasks:
            directive.parse_notes.append(f"Inferred subtasks: {len(directive.inferred_subtasks)}")

        directive.reasoning_questions = self._build_reasoning_questions(lower, directive.inferred_subtasks)
        directive.ambiguity_score = self._compute_ambiguity(intent_hits, directive.inferred_subtasks, directive.repaired_tokens)
        directive.clarification_needed = directive.ambiguity_score >= 0.55 or directive.confidence < 0.6
        if directive.clarification_needed:
            directive.parse_notes.append("Clarification recommended before autonomous execution")

        enhancement_plan: list[str] = []
        if directive.english_focus:
            enhancement_plan.append(f"english:{directive.english_focus}")
        if directive.reasoning_focus:
            enhancement_plan.append(f"reasoning:{directive.reasoning_focus}")
        if directive.decomposition_focus:
            enhancement_plan.append(f"decomposition:{directive.decomposition_focus}")
        if directive.decomposition_steps:
            enhancement_plan.append(f"decomposition_steps:{len(directive.decomposition_steps)}")
        if directive.reasoning_mode:
            enhancement_plan.append(f"reasoning_mode:{directive.reasoning_mode}")
        if directive.reasoning_questions:
            enhancement_plan.append(f"reasoning_questions:{len(directive.reasoning_questions)}")
        if directive.clarification_needed:
            enhancement_plan.append("clarification:required")
        if directive.inferred_subtasks:
            enhancement_plan.append(f"subtasks:{len(directive.inferred_subtasks)}")
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
        if directive.reasoning_focus:
            lines.append(f"Reasoning focus: {directive.reasoning_focus}")
        if directive.decomposition_focus:
            lines.append(f"Task decomposition focus: {directive.decomposition_focus}")
        if directive.decomposition_steps:
            lines.append("Decomposition steps:")
            lines.extend([f"- {step}" for step in directive.decomposition_steps])
        if directive.reasoning_mode:
            lines.append(f"Reasoning mode: {directive.reasoning_mode}")
        if directive.inferred_subtasks:
            lines.append("Inferred subtasks:")
            lines.extend([f"- {step}" for step in directive.inferred_subtasks])
        if directive.reasoning_questions:
            lines.append("Reasoning questions:")
            lines.extend([f"- {q}" for q in directive.reasoning_questions])
        lines.append(f"Ambiguity score: {directive.ambiguity_score:.2f}")
        if directive.clarification_needed:
            lines.append("Clarification needed: yes")
        if directive.codegen_focus:
            lines.append(f"Code generation focus: {directive.codegen_focus}")
        if directive.intel_focus:
            lines.append(f"Intelligence focus: {directive.intel_focus}")
        if directive.mission_style:
            lines.append(f"Mission style: {directive.mission_style}")
        if directive.custom_drone_requested:
            lines.append("Custom drone creation: requested")
        if directive.counterclone_count:
            lines.append(f"Counterclone deployment requested: {directive.counterclone_count}")
        if directive.enhancement_plan:
            lines.append("Enhancement plan:")
            lines.extend([f"- {step}" for step in directive.enhancement_plan])
        if directive.repaired_tokens:
            lines.append(f"Repaired tokens: {', '.join(directive.repaired_tokens[:6])}")
        lines += [f"Note: {n}" for n in directive.parse_notes]
        if directive.confidence < 0.6:
            lines.append("⚠ Low confidence parse — please confirm before executing.")
        return "\n".join(lines)
