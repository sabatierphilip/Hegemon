"""
StoreClient: fetches live package/app metadata from trusted store APIs.
All results are cached in SQLite with a 24hr TTL.
Never hard-fails — returns empty result on any network error.
"""
from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class StoreSearchResult:
    store_id: str
    name: str
    publisher: str
    version: str
    bundle_id: str | None
    icon_url: str | None
    category: str | None
    description: str | None
    score: float
    trust_tier: str
    raw: dict[str, Any]


class StoreClient:
    def __init__(self, cache_path: str = "data/store_cache.sqlite"):
        self._cache_path = cache_path
        self._ttl_seconds = 86400
        self._init_db()

    def _init_db(self) -> None:
        Path(self._cache_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._cache_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS store_cache (
                    cache_key TEXT PRIMARY KEY,
                    ts REAL NOT NULL,
                    value_json TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_store_cache_ts ON store_cache(ts)")
            conn.commit()

    def _cache_get(self, key: str) -> Any | None:
        try:
            with sqlite3.connect(self._cache_path) as conn:
                row = conn.execute(
                    "SELECT ts, value_json FROM store_cache WHERE cache_key = ?",
                    (key,),
                ).fetchone()
                if not row:
                    return None
                ts, value_json = float(row[0]), str(row[1])
                if time.time() - ts > self._ttl_seconds:
                    conn.execute("DELETE FROM store_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                    return None
                return json.loads(value_json)
        except Exception:
            return None

    def _cache_set(self, key: str, value: Any) -> None:
        try:
            encoded = json.dumps(value, sort_keys=True, ensure_ascii=False)
            with sqlite3.connect(self._cache_path) as conn:
                conn.execute(
                    """
                    INSERT INTO store_cache(cache_key, ts, value_json)
                    VALUES(?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                      ts=excluded.ts,
                      value_json=excluded.value_json
                    """,
                    (key, time.time(), encoded),
                )
                # lightweight GC of stale records
                conn.execute("DELETE FROM store_cache WHERE ts < ?", (time.time() - self._ttl_seconds * 2,))
                conn.commit()
        except Exception:
            return

    def _fetch(self, url: str, timeout: int = 8) -> dict | list | None:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "hegemon-store-client/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, Exception):
            return None

    @staticmethod
    def _score(query: str, name: str) -> float:
        q = query.lower()
        n = name.lower()
        if n == q:
            return 1.0
        if n.startswith(q):
            return 0.8
        if q in n:
            return 0.6
        return 0.3

    def search(self, query: str, store_ids: list[str] | None = None, limit: int = 10) -> list[StoreSearchResult]:
        from sentinel_containment.controlplane import STORE_REGISTRY

        out: list[StoreSearchResult] = []
        q = query.strip()
        for store in STORE_REGISTRY:
            sid = str(store.get("store_id", ""))
            if store_ids and sid not in store_ids:
                continue
            ck = f"search:{sid}:{q.lower()}"
            cached = self._cache_get(ck)
            if cached is not None:
                rows = cached
            else:
                rows = []
                meta_api = str(store.get("search_api") or "")
                if "{query}" in meta_api:
                    url = meta_api.format(query=urllib.parse.quote(q), package=urllib.parse.quote(q))
                    data = self._fetch(url)
                    if isinstance(data, dict):
                        rows = data.get("results") or data.get("objects") or data.get("data") or []
                    elif isinstance(data, list):
                        rows = data
                self._cache_set(ck, rows)
            for row in rows[:limit]:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("name") or row.get("package") or row.get("title") or row.get("trackName") or q)
                publisher = str(row.get("publisher") or row.get("developer") or row.get("artistName") or row.get("maintainer") or "unknown")
                if q.lower() not in name.lower() and not name.lower().startswith(q.lower()):
                    continue
                out.append(
                    StoreSearchResult(
                        store_id=sid,
                        name=name,
                        publisher=publisher,
                        version=str(row.get("version") or row.get("latest") or "unknown"),
                        bundle_id=row.get("bundleId") if isinstance(row.get("bundleId"), str) else None,
                        icon_url=row.get("icon") if isinstance(row.get("icon"), str) else row.get("artworkUrl100"),
                        category=row.get("category") if isinstance(row.get("category"), str) else None,
                        description=row.get("description") if isinstance(row.get("description"), str) else None,
                        score=self._score(q, name),
                        trust_tier=str(store.get("trust_tier", "community")),
                        raw=row,
                    )
                )
        dedup: dict[tuple[str, str], StoreSearchResult] = {}
        for r in out:
            key = (r.name.lower(), r.publisher.lower())
            if key not in dedup or r.score > dedup[key].score:
                dedup[key] = r
        return sorted(dedup.values(), key=lambda r: r.score, reverse=True)[:limit]

    def get_metadata(self, package: str, store_id: str, version: str | None = None) -> StoreSearchResult | None:
        q = package.strip()
        ck = f"meta:{store_id}:{q.lower()}"
        cached = self._cache_get(ck)
        if isinstance(cached, dict):
            return StoreSearchResult(**cached)
        hits = self.search(q, [store_id], limit=10)
        if not hits:
            return None
        best = hits[0]
        if version:
            best.version = version
        self._cache_set(ck, best.__dict__)
        return best
