from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CorpusExample:
    text: str
    intent: str
    autonomy: str
    objective: str
    drone_role: str
    codegen_focus: str
    intel_focus: str
    mission_style: str


class HannibalLanguageCorpus:
    """Loads a large curriculum of mission-language examples for semantic matching."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.examples = self._load(path)

    def _load(self, path: Path) -> list[CorpusExample]:
        if not path.exists():
            return []
        examples: list[CorpusExample] = []
        with path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) != 8:
                    continue
                examples.append(
                    CorpusExample(
                        text=parts[0],
                        intent=parts[1],
                        autonomy=parts[2],
                        objective=parts[3],
                        drone_role=parts[4],
                        codegen_focus=parts[5],
                        intel_focus=parts[6],
                        mission_style=parts[7],
                    )
                )
        return examples

    @staticmethod
    def _tokenize(text: str) -> set[str]:
        cleaned = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
        return {tok for tok in cleaned.split() if len(tok) > 2}

    def semantic_match(self, text: str, *, min_overlap: int = 3) -> list[CorpusExample]:
        tokens = self._tokenize(text)
        if not tokens or not self.examples:
            return []

        scored: list[tuple[int, CorpusExample]] = []
        for example in self.examples:
            overlap = len(tokens.intersection(self._tokenize(example.text)))
            if overlap >= min_overlap:
                scored.append((overlap, example))

        scored.sort(key=lambda row: row[0], reverse=True)
        return [example for _, example in scored[:5]]

    def summarize_axes(self, matches: Iterable[CorpusExample]) -> dict[str, str]:
        ranked = list(matches)
        if not ranked:
            return {}

        def pick(attr: str) -> str:
            counts: dict[str, int] = {}
            for ex in ranked:
                value = getattr(ex, attr)
                if not value or value == "none":
                    continue
                counts[value] = counts.get(value, 0) + 1
            if not counts:
                return ""
            return max(counts.items(), key=lambda kv: kv[1])[0]

        return {
            "intent": pick("intent"),
            "autonomy": pick("autonomy"),
            "objective": pick("objective"),
            "drone_role": pick("drone_role"),
            "codegen_focus": pick("codegen_focus"),
            "intel_focus": pick("intel_focus"),
            "mission_style": pick("mission_style"),
        }
