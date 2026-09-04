"""Bounded latency probe for a managed proxy HTTP endpoint.

This harness records measurements; it does not create credentials, infer SLOs,
or print request/response bodies. Run it against an already configured test
proxy, for example:

    python mcp_proxy_loadtest.py --url https://127.0.0.1:18460/health \
        --proxies 1,2,8 --concurrency 1,8,32
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import statistics
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


def positive_csv(value: str) -> list[int]:
    values = [int(part) for part in value.split(",")]
    if not values or any(item < 1 or item > 128 for item in values):
        raise argparse.ArgumentTypeError("values must be between 1 and 128")
    return values


def probe(url: str, timeout: float) -> tuple[float, bool]:
    started = time.perf_counter()
    try:
        request = Request(url, headers={"accept": "*/*"})
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is an explicit test target
            response.read(4096)
            return (time.perf_counter() - started) * 1000, 200 <= response.status < 400
    except (OSError, URLError, TimeoutError):
        return (time.perf_counter() - started) * 1000, False


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * fraction))
    return round(ordered[index], 3)


def run(url: str, proxy_count: int, concurrency: int, samples: int, timeout: float) -> dict[str, object]:
    total = max(samples, concurrency * 2)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda _: probe(url, timeout), range(total)))
    elapsed = time.perf_counter() - started
    timings = [duration for duration, ok in results if ok]
    return {
        "proxies": proxy_count,
        "concurrency": concurrency,
        "samples": total,
        "successes": len(timings),
        "failures": total - len(timings),
        "throughput_per_second": round(len(timings) / elapsed, 3) if elapsed else 0,
        "latency_ms": {
            "min": round(min(timings), 3) if timings else None,
            "mean": round(statistics.mean(timings), 3) if timings else None,
            "p50": percentile(timings, 0.50),
            "p95": percentile(timings, 0.95),
            "p99": percentile(timings, 0.99),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18460/health")
    parser.add_argument("--proxies", type=positive_csv, default=[1, 2, 8])
    parser.add_argument("--concurrency", type=positive_csv, default=[1, 8, 32])
    parser.add_argument("--samples", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if args.samples < 1 or args.samples > 10_000 or args.timeout <= 0 or args.timeout > 30:
        parser.error("samples must be 1..10000 and timeout must be >0..30")
    measurements = [run(args.url, proxies, concurrency, args.samples, args.timeout) for proxies in args.proxies for concurrency in args.concurrency]
    print(json.dumps({"url": args.url, "measurements": measurements}, indent=2, sort_keys=True))
    return 0 if all(measurement["failures"] == 0 for measurement in measurements) else 1


if __name__ == "__main__":
    raise SystemExit(main())
