from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from typing import Any


@dataclass
class CloudProviderAdapter:
    simulated: bool = False
    provider: str | None = None

    def __post_init__(self) -> None:
        if self.provider is None:
            self.provider = self._detect_provider()

    def _detect_provider(self) -> str:
        if os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"):
            return "aws"
        if os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT"):
            return "gcp"
        if os.getenv("AZURE_SUBSCRIPTION_ID") or os.getenv("AZURE_TENANT_ID"):
            return "azure"
        return "local"

    def _local_instance(self) -> list[dict[str, Any]]:
        host = socket.gethostname()
        return [{"id": f"local-{host}", "name": host, "ip": "127.0.0.1", "provider": "local"}]

    def list_instances(self) -> list[dict[str, Any]]:
        if self.simulated:
            return [
                {"id": "i-local-1", "name": "sim-app-1", "ip": "10.0.0.21", "provider": "sim"},
                {"id": "i-local-2", "name": "sim-model-1", "ip": "10.0.0.22", "provider": "sim"},
            ]
        if self.provider == "aws":
            try:
                import boto3

                ec2 = boto3.client("ec2")
                reservations = ec2.describe_instances().get("Reservations", [])
                instances: list[dict[str, Any]] = []
                for reservation in reservations:
                    for item in reservation.get("Instances", []):
                        instances.append(
                            {
                                "id": item.get("InstanceId", "unknown"),
                                "name": next(
                                    (
                                        tag.get("Value")
                                        for tag in item.get("Tags", [])
                                        if tag.get("Key") == "Name"
                                    ),
                                    item.get("InstanceId", "unknown"),
                                ),
                                "ip": item.get("PrivateIpAddress", ""),
                                "provider": "aws",
                            }
                        )
                if instances:
                    return instances
            except Exception:
                pass
        return self._local_instance()

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
