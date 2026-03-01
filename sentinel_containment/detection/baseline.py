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


class BehavioralBaseline:
    def __init__(self, threshold: float = 2.0, window: int = 30, min_history: int = 5):
        self.threshold = threshold
        self.window = window
        self.min_history = min_history
        self.series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self._anchor_mean: dict[tuple[str, str], float] = {}

    def update_and_detect(self, host: str, metrics: dict[str, float]) -> list[BaselineAnomaly]:
        anomalies: list[BaselineAnomaly] = []
        for metric, current in metrics.items():
            key = (host, metric)
            history = self.series[key]
            avg = mean(history) if history else current

            anchor = self._anchor_mean.get(key, avg)
            protected_avg = max(avg, anchor)
            ratio = (current / protected_avg) if protected_avg > 0 else 1.0
            score = self._robust_score(list(history), current, anchor)

            if len(history) >= self.min_history and score > self.threshold:
                severity = min(100, int(45 + (score - self.threshold) * 18))
                anomalies.append(BaselineAnomaly(metric, host, current, protected_avg, ratio, severity))

            history.append(current)
            if key not in self._anchor_mean:
                self._anchor_mean[key] = current
            else:
                # Slow-decay anchor prevents fast baseline flushing from instantly redefining normal.
                alpha = 0.03 if current < self._anchor_mean[key] else 0.10
                self._anchor_mean[key] = (1.0 - alpha) * self._anchor_mean[key] + alpha * current

        return anomalies

    @staticmethod
    def _robust_score(history: list[float], current: float, anchor: float | None = None) -> float:
        if not history:
            return 0.0

        hist_median = median(history)
        abs_dev = [abs(x - hist_median) for x in history]
        mad = median(abs_dev)
        if mad > 0:
            # 0.6745 scales MAD to std-dev equivalent under normal distribution.
            return (0.6745 * abs(current - hist_median)) / mad

        # Perfectly-flat windows are suspicious and should not permit a 2x blind spot.
        reference = max(mean(history), hist_median)
        if anchor is not None:
            reference = max(reference, anchor)
        if reference <= 0:
            return 0.0

        pseudo_mad = max(0.05 * reference, 0.25)
        return (0.6745 * abs(current - hist_median)) / pseudo_mad
