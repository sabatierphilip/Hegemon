from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_LANGUAGE_EXTENSIONS: dict[str, set[str]] = {
    "python": {".py", ".pyi"},
    "javascript": {".js", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "go": {".go"},
    "rust": {".rs"},
    "c": {".c", ".h"},
    "cpp": {".cc", ".cpp", ".cxx", ".hpp"},
    "csharp": {".cs"},
    "ruby": {".rb"},
    "php": {".php"},
    "swift": {".swift"},
    "kotlin": {".kt", ".kts"},
    "shell": {".sh", ".bash", ".zsh"},
    "json": {".json"},
    "yaml": {".yaml", ".yml"},
    "toml": {".toml"},
}

_SHEBANG_HINTS = {
    "python": ("python",),
    "shell": ("sh", "bash", "zsh"),
    "ruby": ("ruby",),
    "php": ("php",),
}


@dataclass
class ScannerFinding:
    path: str
    language: str
    is_binary: bool
    entropy: float
    mbt_score: float
    indicators: list[str]


class MultiByteThreatScanner:
    """Binary-aware MBT-style scanner for mixed-language repositories."""

    def __init__(self, max_read_bytes: int = 256_000):
        self.max_read_bytes = max_read_bytes

    def scan_path(self, root: Path, *, max_files: int = 500) -> dict[str, Any]:
        findings: list[ScannerFinding] = []
        scanned = 0
        for path in sorted(root.rglob("*")):
            if scanned >= max_files:
                break
            if not path.is_file() or "/.git/" in f"/{path.as_posix()}/":
                continue
            scanned += 1
            findings.append(self.scan_file(path, base=root))

        findings.sort(key=lambda f: f.mbt_score, reverse=True)
        return {
            "scanner": "multi_byte_threat_scanner",
            "scanned_files": scanned,
            "high_risk_findings": [f.__dict__ for f in findings[:25]],
            "language_counts": self._language_counts(findings),
            "binary_file_count": sum(1 for f in findings if f.is_binary),
        }

    def scan_file(self, path: Path, *, base: Path | None = None) -> ScannerFinding:
        raw = path.read_bytes()[: self.max_read_bytes]
        entropy = self._shannon_entropy(raw)
        is_binary = self._is_binary(raw)
        language = self._detect_language(path, raw)
        indicators = self._indicators(raw, is_binary)
        mbt_score = self._score(entropy, is_binary, indicators)
        rel = str(path.relative_to(base)) if base else str(path)
        return ScannerFinding(
            path=rel,
            language=language,
            is_binary=is_binary,
            entropy=round(entropy, 4),
            mbt_score=round(mbt_score, 4),
            indicators=indicators,
        )

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts if c)

    @staticmethod
    def _is_binary(data: bytes) -> bool:
        if not data:
            return False
        if b"\x00" in data:
            return True
        control = sum(1 for b in data if b < 9 or (13 < b < 32))
        return (control / max(1, len(data))) > 0.15

    def _detect_language(self, path: Path, data: bytes) -> str:
        suffix = path.suffix.lower()
        for language, exts in _LANGUAGE_EXTENSIONS.items():
            if suffix in exts:
                return language

        first_line = data.splitlines()[0].decode("utf-8", errors="ignore") if data else ""
        if first_line.startswith("#!"):
            for language, hints in _SHEBANG_HINTS.items():
                if any(hint in first_line for hint in hints):
                    return language

        if self._is_binary(data):
            return "binary"
        return "text"

    @staticmethod
    def _indicators(data: bytes, is_binary: bool) -> list[str]:
        indicators: list[str] = []
        lower = data.lower()
        for marker in (b"eval(", b"exec(", b"system(", b"subprocess", b"powershell", b"/bin/sh", b"base64", b"token", b"apikey"):
            if marker in lower:
                indicators.append(marker.decode("utf-8", errors="ignore"))
        if is_binary:
            indicators.append("binary_payload")
        if b"-----BEGIN" in data:
            indicators.append("embedded_key_material")
        return indicators[:10]

    @staticmethod
    def _score(entropy: float, is_binary: bool, indicators: list[str]) -> float:
        score = entropy * 6.5
        if is_binary:
            score += 18.0
        score += len(indicators) * 3.2
        return min(100.0, score)

    @staticmethod
    def _language_counts(findings: list[ScannerFinding]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.language] = counts.get(finding.language, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: item[0]))
