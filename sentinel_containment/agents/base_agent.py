from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseAgent(ABC):
    AGENT_ID: str

    @abstractmethod
    def receive_instruction(self, text: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def start_campaign(self, campaign_id: str, target: str, objective: str) -> Any:
        raise NotImplementedError

    @abstractmethod
    def abort_campaign(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def status(self) -> dict[str, Any]:
        raise NotImplementedError
