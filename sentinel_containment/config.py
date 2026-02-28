from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import yaml


@dataclass
class Settings:
    data: dict[str, Any]

    @classmethod
    def load(cls, path: str = "config/config.yaml") -> "Settings":
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cls(cfg)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def env(self, key: str, default: Any = None) -> Any:
        return os.getenv(key, default)
