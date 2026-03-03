from __future__ import annotations

import argparse
import concurrent.futures
import statistics
import time
from urllib import request


def _single_call(url: str, token: str, timeout: float) -> tuple[int, float]:
    start = time.perf_counter()
    req = request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        code = int(resp.status)
        resp.read()
    return code, (time.perf_counter() - start) * 1000.0


def run_profile(url: str, token: str, concurrency: int, requests_total: int, timeout: float) -> dict[str, float]:
    latencies: list[float] = []
    ok = 0
    failed = 0

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(_single_call, url, token, timeout) for _ in range(requests_total)]
        for fut in concurrent.futures.as_completed(futures):
            try:
                status, latency_ms = fut.result()
                latencies.append(latency_ms)
                if status == 200:
                    ok += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
    elapsed = max(0.001, time.perf_counter() - started)
    sorted_latencies = sorted(latencies)
    p95_index = int(len(sorted_latencies) * 0.95) - 1 if sorted_latencies else 0

    return {
        "requests": float(requests_total),
        "ok": float(ok),
        "failed": float(failed),
        "rps": requests_total / elapsed,
        "p50_ms": statistics.median(sorted_latencies) if sorted_latencies else 0.0,
        "p95_ms": sorted_latencies[max(0, p95_index)] if sorted_latencies else 0.0,
        "max_ms": max(sorted_latencies) if sorted_latencies else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Production WSGI burst load profile for Sentinel dashboard endpoints")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/health")
    parser.add_argument("--token", default="")
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--requests", type=int, default=2000)
    parser.add_argument("--timeout", type=float, default=2.0)
    args = parser.parse_args()

    if not args.token:
        raise SystemExit("--token is required")

    summary = run_profile(args.url, args.token, max(1, args.concurrency), max(1, args.requests), args.timeout)
    print("WSGI load profile summary")
    for key, value in summary.items():
        print(f"{key}: {value:.2f}")


if __name__ == "__main__":
    main()
