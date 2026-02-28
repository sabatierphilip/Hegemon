from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class CloudProviderAdapter:
    simulated: bool = True

    def list_instances(self) -> list[dict[str, Any]]:
        if self.simulated:
            return [
                {"id": "i-local-1", "name": "sim-app-1", "ip": "10.0.0.21", "provider": "sim"},
                {"id": "i-local-2", "name": "sim-model-1", "ip": "10.0.0.22", "provider": "sim"},
            ]
        return []

    def list_iam_roles(self) -> list[dict[str, Any]]:
        if self.simulated:
            return [
                {"id": "role-reader", "permissions": ["read:logs"]},
                {"id": "role-admin", "permissions": ["iam:write", "model:invoke"]},
            ]
        return []

    def list_buckets(self) -> list[dict[str, Any]]:
        if self.simulated:
            return [{"id": "bucket-audit-archive"}, {"id": "bucket-model-prompts"}]
        return []

    def list_model_endpoints(self) -> list[dict[str, Any]]:
        if self.simulated:
            return [
                {"id": "model-endpoint-1", "url": "https://model.internal/invoke", "model": "llm-safe-v1"}
            ]
        return []
