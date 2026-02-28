from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean, median
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
    def __init__(self, threshold: float = 2.0, window: int = 30, min_history: int = 5):
        self.threshold = threshold
        self.window = window
        self.min_history = min_history
        self.series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def update_and_detect(self, host: str, metrics: dict[str, float]) -> list[BaselineAnomaly]:
        anomalies: list[BaselineAnomaly] = []
        for metric, current in metrics.items():
            key = (host, metric)
            history = self.series[key]
            avg = mean(history) if history else current
            ratio = (current / avg) if avg > 0 else 1.0
            score = self._robust_score(list(history), current)

            if len(history) >= self.min_history and score > self.threshold:
                severity = min(100, int(45 + (score - self.threshold) * 18))
                anomalies.append(BaselineAnomaly(metric, host, current, avg, ratio, severity))
            history.append(current)
        return anomalies

    @staticmethod
    def _robust_score(history: list[float], current: float) -> float:
        if not history:
            return 0.0

        hist_median = median(history)
        abs_dev = [abs(x - hist_median) for x in history]
        mad = median(abs_dev)
        if mad > 0:
            # 0.6745 scales MAD to std-dev equivalent under normal distribution.
            return (0.6745 * abs(current - hist_median)) / mad

        avg = mean(history)
        if avg <= 0:
            return 0.0
        return max(0.0, current / avg)
