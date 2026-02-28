from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean
from typing import Any


@dataclass
class BaselineAnomaly:
    metric: str
    host: str
    current: float
    avg: float
    deviation_ratio: float
    severity: int


class BehavioralBaseline:
    def __init__(self, threshold: float = 2.0, window: int = 14):
        self.threshold = threshold
        self.window = window
        self.series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def update_and_detect(self, host: str, metrics: dict[str, float]) -> list[BaselineAnomaly]:
        anomalies: list[BaselineAnomaly] = []
        for metric, current in metrics.items():
            key = (host, metric)
            history = self.series[key]
            avg = mean(history) if history else current
            ratio = (current / avg) if avg > 0 else 1.0
            if history and ratio > self.threshold:
                severity = min(100, int(40 + (ratio - self.threshold) * 20))
                anomalies.append(BaselineAnomaly(metric, host, current, avg, ratio, severity))
            history.append(current)
        return anomalies
