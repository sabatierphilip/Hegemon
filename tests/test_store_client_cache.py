from pathlib import Path

from sentinel_containment.store_client import StoreClient


def test_store_client_uses_sqlite_cache(tmp_path: Path):
    cache_path = tmp_path / "store_cache.sqlite"
    c = StoreClient(cache_path=str(cache_path))
    c._cache_set("k1", {"ok": True})
    assert c._cache_get("k1") == {"ok": True}
    assert cache_path.exists()
    assert cache_path.suffix == ".sqlite"
    assert not list(tmp_path.glob("*.shelve*"))
