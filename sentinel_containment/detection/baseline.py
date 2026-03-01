from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import math
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


@dataclass
class DynamicModelState:
    fast_mean: float
    resilient_mean: float
    volatility: float
    contamination_score: float
    last_update_ts: float


class DynamicAutoModeller:
    """Blend fast/reactive and resilient/slow models to resist poisoned baselines."""

    def __init__(self, contamination_half_life_seconds: float = 180.0):
        self._state: dict[tuple[str, str], DynamicModelState] = {}
        self._half_life = max(30.0, float(contamination_half_life_seconds))

    def update(
        self,
        key: tuple[str, str],
        current: float,
        trusted_signal: bool = False,
        event_ts: str | None = None,
    ) -> DynamicModelState:
        current_ts = self._to_epoch_seconds(event_ts)
        state = self._state.get(key)
        if state is None:
            state = DynamicModelState(
                fast_mean=current,
                resilient_mean=current,
                volatility=max(0.25, abs(current) * 0.05),
                contamination_score=0.0,
                last_update_ts=current_ts,
            )
            self._state[key] = state
            return state

        # Fast model adapts quickly to genuine behavior shifts.
        fast_alpha = 0.28 if not trusted_signal else 0.34
        state.fast_mean = (1.0 - fast_alpha) * state.fast_mean + fast_alpha * current

        # Resilient model moves slowly and is harder to poison.
        resilient_alpha = 0.08 if not trusted_signal else 0.22
        state.resilient_mean = (1.0 - resilient_alpha) * state.resilient_mean + resilient_alpha * current

        deviation = abs(current - state.fast_mean)
        state.volatility = (state.volatility * 0.85) + (deviation * 0.15)

        divergence = abs(state.fast_mean - state.resilient_mean)
        poison_pressure = divergence / max(state.volatility, 0.25)
        elapsed_seconds = max(0.0, current_ts - state.last_update_ts)
        decay = math.exp(-math.log(2.0) * (elapsed_seconds / self._half_life))
        if trusted_signal:
            decay = max(0.82, decay)
        state.contamination_score = max(0.0, (state.contamination_score * decay) + max(0.0, poison_pressure - 1.4))
        state.last_update_ts = current_ts
        return state

    @staticmethod
    def _to_epoch_seconds(event_ts: str | None) -> float:
        if not event_ts:
            return 0.0
        try:
            return datetime.fromisoformat(event_ts.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
        except (TypeError, ValueError):
            return 0.0


class BehavioralBaseline:
    def __init__(
        self,
        threshold: float = 2.0,
        window: int = 30,
        min_history: int = 5,
        contamination_half_life_seconds: float = 180.0,
    ):
        self.threshold = threshold
        self.window = window
        self.min_history = min_history
        self.series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self._anchor_mean: dict[tuple[str, str], float] = {}
        self._automodeller = DynamicAutoModeller(contamination_half_life_seconds=contamination_half_life_seconds)

    def update_and_detect(
        self,
        host: str,
        metrics: dict[str, Any],
        context: dict[str, float | bool | str] | None = None,
    ) -> list[BaselineAnomaly]:
        anomalies: list[BaselineAnomaly] = []
        source_type = str((context or {}).get("source_type", "unknown"))
        trusted_signal = bool((context or {}).get("counterclone_participant", False)) and source_type == "counterclone"
        trusted_signal = trusted_signal and bool((context or {}).get("counterclone_integrity_verified", False))
        event_ts = str((context or {}).get("event_timestamp", "")) or None
        for metric, raw_current in metrics.items():
            current = self._coerce_float(raw_current)
            if current is None:
                continue
            key = (host, metric)
            history = self.series[key]
            avg = mean(history) if history else current

            anchor = self._anchor_mean.get(key, avg)
            dynamic_state = self._automodeller.update(
                key,
                current,
                trusted_signal=trusted_signal,
                event_ts=event_ts,
            )
            dynamic_reference = max(dynamic_state.fast_mean, dynamic_state.resilient_mean)
            protected_avg = max(avg, anchor, dynamic_reference)
            ratio = (current / protected_avg) if protected_avg > 0 else 1.0
            score = self._robust_score(list(history), current, max(anchor, dynamic_state.resilient_mean))

            contamination_bias = min(2.5, dynamic_state.contamination_score / 4.0)
            adjusted_score = score + contamination_bias
            effective_threshold = self.threshold - min(0.55, contamination_bias * 0.35)

            if len(history) >= self.min_history and adjusted_score > effective_threshold:
                severity = min(100, int(45 + (adjusted_score - effective_threshold) * 18))
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
    def _coerce_float(value: Any) -> float | None:
        if value is None:
            return None
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(numeric):
            return None
        return numeric

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
