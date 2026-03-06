"""
StoreClient: fetches live package/app metadata from trusted store APIs.
All results cached in data/store_cache.shelve with 24hr TTL.
Never hard-fails — returns empty result on any network error.
"""
from __future__ import annotations

import json
import shelve
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
    def __init__(self, cache_path: str = "data/store_cache.shelve"):
        self._cache_path = cache_path
        self._ttl_seconds = 86400

    def _cache_get(self, key: str) -> Any | None:
        Path(self._cache_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with shelve.open(self._cache_path) as db:
                row = db.get(key)
                if not row:
                    return None
                if time.time() - float(row.get("ts", 0)) > self._ttl_seconds:
                    return None
                return row.get("value")
        except Exception:
            return None

    def _cache_set(self, key: str, value: Any) -> None:
        Path(self._cache_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            with shelve.open(self._cache_path) as db:
                db[key] = {"ts": time.time(), "value": value}
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
                out.append(StoreSearchResult(
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
                ))
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
        if cached:
            return StoreSearchResult(**cached)
        hits = self.search(q, [store_id], limit=10)
        if not hits:
            return None
        best = hits[0]
        if version:
            best.version = version
        self._cache_set(ck, best.__dict__)
        return best
