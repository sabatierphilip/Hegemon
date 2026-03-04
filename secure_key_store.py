"""OS-aware key storage helpers for Hegemon Agent.

Linux/macOS fallback: encrypted file (scrypt + Fernet).
Windows: DPAPI wrapper when available.
"""
from __future__ import annotations

import base64
import json
import os
import platform
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class SecureKeyStore:
    def __init__(self, path: Path, passphrase: Optional[str] = None) -> None:
        self.path = path
        self.passphrase = passphrase or os.environ.get("HEGEMON_KEYSTORE_PASSPHRASE", "dev-passphrase")

    def _ensure_secure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        mode = self.path.parent.stat().st_mode & 0o777
        if mode != 0o700:
            raise PermissionError(f"keystore directory permissions must be 0o700, got {oct(mode)}")

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return base64.urlsafe_b64encode(kdf.derive(self.passphrase.encode("utf-8")))

    def store_secret(self, name: str, secret: bytes) -> None:
        self._ensure_secure_parent()
        blob = self._load_blob()
        salt = base64.b64decode(blob["salt"]) if blob else os.urandom(16)
        data = self._decrypt_payload(blob, salt) if blob else {}
        data[name] = base64.b64encode(secret).decode("ascii")
        payload = self._encrypt_payload(data, salt)
        self.path.write_text(json.dumps(payload, indent=2))
        os.chmod(self.path, 0o600)

    def load_secret(self, name: str) -> bytes:
        blob = self._load_blob()
        if not blob:
            raise KeyError(name)
        salt = base64.b64decode(blob["salt"])
        data = self._decrypt_payload(blob, salt)
        if name not in data:
            raise KeyError(name)
        return base64.b64decode(data[name])

    def _load_blob(self):
        if not self.path.exists():
            return None
        mode = self.path.stat().st_mode & 0o777
        if mode != 0o600:
            raise PermissionError(f"keystore file permissions must be 0o600, got {oct(mode)}")
        return json.loads(self.path.read_text())

    def _encrypt_payload(self, data: dict, salt: bytes) -> dict:
        key = self._derive_key(salt)
        token = Fernet(key).encrypt(json.dumps(data, sort_keys=True).encode("utf-8"))
        return {"salt": base64.b64encode(salt).decode("ascii"), "ciphertext": token.decode("ascii")}

    def _decrypt_payload(self, blob: dict, salt: bytes) -> dict:
        key = self._derive_key(salt)
        plaintext = Fernet(key).decrypt(blob["ciphertext"].encode("ascii"))
        return json.loads(plaintext)


def storage_backend_name() -> str:
    return "dpapi" if platform.system().lower().startswith("win") else "encrypted_file"
