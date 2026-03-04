"""Phase 4 kernel-adjacent telemetry (safe vectors only; no kernel drivers).

Linux path:
- Supports signed eBPF source admission checks before load.
- Uses BCC when available; otherwise degrades to safe host counters.

Windows path:
- Provides ETW consumer abstraction and safe fallback event generation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import platform
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from nacl import exceptions as nacl_exceptions, signing


class KernelTelemetryError(RuntimeError):
    pass


@dataclass
class KernelTelemetryConfig:
    enabled: bool = True
    ebpf_program_path: Optional[Path] = None
    ebpf_signature_path: Optional[Path] = None
    etw_providers: Sequence[str] = ()


class SignedProgramVerifier:
    def __init__(self, trusted_verify_keys: Sequence[signing.VerifyKey]) -> None:
        self.trusted_verify_keys = trusted_verify_keys

    def verify_file(self, program_path: Path, signature_path: Path) -> str:
        digest = hashlib.sha256(program_path.read_bytes()).hexdigest()
        signature = base64.b64decode(signature_path.read_text().strip())
        for verifier in self.trusted_verify_keys:
            try:
                verifier.verify(digest.encode("utf-8"), signature)
                return digest
            except nacl_exceptions.BadSignatureError:
                continue
        raise KernelTelemetryError("signed program verification failed")


class LinuxEBPFCollector:
    """Kernel-adjacent collector using BCC where present, safe fallback otherwise."""

    def __init__(self) -> None:
        self._bcc_available = False
        self._bpf = None

    def load_if_available(self, program_path: Path) -> bool:
        try:
            from bcc import BPF  # type: ignore

            source = program_path.read_text()
            self._bpf = BPF(text=source)
            self._bcc_available = True
            return True
        except Exception:
            self._bcc_available = False
            return False

    def snapshot(self) -> Dict[str, Any]:
        if self._bcc_available:
            return {
                "mode": "ebpf_bcc",
                "events": {
                    "exec": [],
                    "tcp_connect": [],
                    "tcp_accept": [],
                    "syscall_counts": {},
                },
            }

        # Safe fallback from proc/net, no kernel driver and no raw kernel hooks.
        tcp_established = 0
        try:
            out = subprocess.check_output(["bash", "-lc", "ss -tan state established | wc -l"], text=True)
            tcp_established = max(int(out.strip()) - 1, 0)
        except Exception:
            tcp_established = 0

        return {
            "mode": "safe_fallback",
            "events": {
                "exec": [],
                "tcp_connect": [],
                "tcp_accept": [],
                "syscall_counts": {},
            },
            "counters": {"tcp_established": tcp_established},
        }


class WindowsETWCollector:
    """ETW consumer abstraction; safe fallback when provider subscriptions unavailable."""

    def __init__(self, providers: Sequence[str]) -> None:
        self.providers = list(providers)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "mode": "etw_fallback",
            "providers": self.providers,
            "events": {
                "process_start_stop": [],
                "network": [],
                "image_load": [],
            },
        }


class KernelTelemetryManager:
    def __init__(self, config: KernelTelemetryConfig, trusted_verify_keys: Sequence[signing.VerifyKey]) -> None:
        self.config = config
        self.verifier = SignedProgramVerifier(trusted_verify_keys)
        self.system = platform.system().lower()
        self._linux = LinuxEBPFCollector() if self.system == "linux" else None
        self._windows = WindowsETWCollector(config.etw_providers) if self.system.startswith("win") else None
        self.last_program_digest: Optional[str] = None

    def initialize(self) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"enabled": False, "status": "disabled"}

        if self.system == "linux" and self._linux:
            if self.config.ebpf_program_path and self.config.ebpf_signature_path:
                self.last_program_digest = self.verifier.verify_file(self.config.ebpf_program_path, self.config.ebpf_signature_path)
                loaded = self._linux.load_if_available(self.config.ebpf_program_path)
                return {
                    "enabled": True,
                    "platform": "linux",
                    "program_sha256": self.last_program_digest,
                    "runtime": "bcc" if loaded else "safe_fallback",
                }
            return {"enabled": True, "platform": "linux", "runtime": "safe_fallback", "status": "unsigned_program_not_configured"}

        if self.system.startswith("win") and self._windows:
            return {"enabled": True, "platform": "windows", "runtime": "etw"}

        return {"enabled": False, "status": f"unsupported_platform:{self.system}"}

    def snapshot(self) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"enabled": False}
        if self.system == "linux" and self._linux:
            return {"enabled": True, "platform": "linux", "captured_at": datetime.now(timezone.utc).isoformat(), **self._linux.snapshot()}
        if self.system.startswith("win") and self._windows:
            return {"enabled": True, "platform": "windows", "captured_at": datetime.now(timezone.utc).isoformat(), **self._windows.snapshot()}
        return {"enabled": False, "status": "unsupported_platform"}
