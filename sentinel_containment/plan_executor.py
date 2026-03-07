from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class ExecutionStepResult:
    step_id: str
    opcode: str
    ok: bool
    message: str


class SophisticatedBinaryPlanExecutor:
    """Deterministic executor for graph-derived plans encoded as binary payload blobs.

    The executor intentionally supports a constrained opcode set so plans can be
    validated/executed in tests and preview environments without arbitrary command execution.
    """

    SUPPORTED_OPCODES = {"visit_node", "collect_context", "emit_report", "sleep_ms", "set_flag"}

    def build_blob(self, *, plan: list[dict[str, Any]], rag_context: list[str] | None = None) -> str:
        payload = {
            "version": "1.0",
            "kind": "binary_executor",
            "engine": "sophisticated_plan_executor_v1",
            "created_at": int(time.time()),
            "rag_context": [str(item)[:180] for item in (rag_context or [])][:24],
            "plan": plan,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        payload["checksum_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return base64.b64encode(json.dumps(payload, sort_keys=True).encode("utf-8")).decode("ascii")

    def decode_blob(self, blob: str) -> dict[str, Any]:
        raw = base64.b64decode(blob.encode("ascii"), validate=True)
        decoded = json.loads(raw.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("executor payload must decode to an object")
        plan = decoded.get("plan")
        if not isinstance(plan, list):
            raise ValueError("executor payload missing plan list")
        return decoded

    def execute_blob(self, blob: str) -> dict[str, Any]:
        payload = self.decode_blob(blob)
        rag_context = payload.get("rag_context", [])
        if not isinstance(rag_context, list):
            rag_context = []

        flags: dict[str, Any] = {}
        results: list[ExecutionStepResult] = []
        for index, step in enumerate(payload.get("plan", [])):
            if not isinstance(step, dict):
                results.append(ExecutionStepResult(str(index), "invalid", False, "step must be object"))
                continue
            opcode = str(step.get("opcode", "")).strip()
            step_id = str(step.get("id", f"step-{index}"))
            if opcode not in self.SUPPORTED_OPCODES:
                results.append(ExecutionStepResult(step_id, opcode or "unknown", False, "unsupported opcode"))
                continue

            if opcode == "sleep_ms":
                sleep_ms = int(step.get("ms", 0) or 0)
                sleep_ms = max(0, min(250, sleep_ms))
                if sleep_ms:
                    time.sleep(sleep_ms / 1000.0)
                results.append(ExecutionStepResult(step_id, opcode, True, f"slept {sleep_ms}ms"))
                continue

            if opcode == "set_flag":
                key = str(step.get("key", "flag"))[:64]
                flags[key] = step.get("value", True)
                results.append(ExecutionStepResult(step_id, opcode, True, f"flag set: {key}"))
                continue

            if opcode == "collect_context":
                hint = str(step.get("query", "")).lower()
                hits = [ctx for ctx in rag_context if hint and hint in str(ctx).lower()]
                results.append(ExecutionStepResult(step_id, opcode, True, f"context hits={len(hits)}"))
                continue

            if opcode == "emit_report":
                summary = str(step.get("summary", "report"))[:120]
                results.append(ExecutionStepResult(step_id, opcode, True, f"reported: {summary}"))
                continue

            node_kind = str(step.get("kind", step.get("node_kind", "node")))[:80]
            results.append(ExecutionStepResult(step_id, opcode, True, f"visited {node_kind}"))

        success = all(item.ok for item in results)
        return {
            "success": success,
            "steps_total": len(results),
            "steps_ok": sum(1 for r in results if r.ok),
            "flags": flags,
            "results": [r.__dict__ for r in results],
        }
