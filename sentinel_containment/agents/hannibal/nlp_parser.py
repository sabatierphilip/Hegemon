from __future__ import annotations

import re
from dataclasses import dataclass, field


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


class HannibalNLPParser:
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
        lines += [f"Note: {n}" for n in directive.parse_notes]
        if directive.confidence < 0.6:
            lines.append("⚠ Low confidence parse — please confirm before executing.")
        return "\n".join(lines)
