from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel_containment.config import Settings
from sentinel_containment.main import run_cycle


if __name__ == "__main__":
    settings = Settings.load()
    state = run_cycle(settings)
    out = Path("data/latest_state.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(f"Simulation complete. State saved to {out}")
