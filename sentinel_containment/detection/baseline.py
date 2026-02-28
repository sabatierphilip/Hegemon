from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean, median


@dataclass
class BaselineAnomaly:
    metric: str
    host: str
    current: float
    avg: float
    deviation_ratio: float
    severity: int
    method: str


class BehavioralBaseline:
    def __init__(self, threshold: float = 2.0, window: int = 14, min_history: int = 5):
        self.threshold = threshold
        self.window = window
        self.min_history = min_history
        self.series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window))

    def ready_for_detection(self, host: str, metric: str) -> bool:
        return len(self.series[(host, metric)]) >= self.min_history

    def update_and_detect(self, host: str, metrics: dict[str, float]) -> list[BaselineAnomaly]:
        anomalies: list[BaselineAnomaly] = []
        for metric, current in metrics.items():
            key = (host, metric)
            history = self.series[key]

            if len(history) >= self.min_history:
                avg = mean(history)
                ratio = (current / avg) if avg > 0 else 1.0

                # robust MAD based score
                med = median(history)
                mad = median([abs(v - med) for v in history]) or 1e-9
                robust_z = abs(current - med) / (1.4826 * mad)

                triggered = ratio > self.threshold or robust_z > 3.5
                if triggered:
                    sev_ratio = max(0.0, ratio - self.threshold)
                    sev_robust = max(0.0, robust_z - 3.5)
                    severity = min(100, int(50 + sev_ratio * 15 + sev_robust * 8))
                    method = "mad" if robust_z > 3.5 else "ratio"
                    anomalies.append(BaselineAnomaly(metric, host, current, avg, ratio, severity, method))

            history.append(current)
        return anomalies
