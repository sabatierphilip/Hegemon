from pathlib import Path

import pytest
from nacl import signing

from phase6_controlplane import TransparencyPublisher
from secure_key_store import SecureKeyStore


def test_transparency_publisher_supports_multi_anchor(monkeypatch):
    called = []

    class Resp:
        status_code = 200

    def fake_post(url, json, timeout):
        called.append(url)
        return Resp()

    monkeypatch.setattr("phase6_controlplane.requests.post", fake_post)
    pub = TransparencyPublisher("https://a.example,https://b.example")
    responses = pub.publish({"decision": "ok"})
    assert len(responses) == 2
    assert called == ["https://a.example", "https://b.example"]


def test_secure_keystore_enforces_permissions(tmp_path: Path):
    store_path = tmp_path / "keys" / "store.json"
    store = SecureKeyStore(store_path, passphrase="pw")
    store.store_secret("k", b"v")
    assert (store_path.parent.stat().st_mode & 0o777) == 0o700
    assert (store_path.stat().st_mode & 0o777) == 0o600

    store_path.chmod(0o644)
    with pytest.raises(PermissionError):
        store.load_secret("k")


def test_signed_ledger_writes_anchor_file(tmp_path: Path):
    from signed_ledger import SignedLedger

    signer = signing.SigningKey.generate()
    ledger_path = tmp_path / "ledger.log"
    ledger = SignedLedger(ledger_path, signer)
    ledger.append("evt", {"x": 1})
    anchor_path = tmp_path / "ledger.log.anchor"
    assert anchor_path.exists()
