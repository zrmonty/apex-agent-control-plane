"""Bounded MCP Streamable HTTP latency and throughput probe.

This harness measures an already configured proxy; it does not create
credentials or print request/response bodies. A bearer token may be supplied
with ``--bearer-token`` or ``APEX_MCP_LOADTEST_TOKEN``.

Example::

    python mcp_proxy_loadtest.py --url http://127.0.0.1:18460/mcp \
        --bearer-token "$APEX_MCP_LOADTEST_TOKEN" \
        --origin https://console.example.test \
        --tool portfolio.read --input-json '{"portfolioId":"fixture"}' \
        --concurrency 1,8,32
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import os
import statistics
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_SESSION_CONCURRENCY = 256
INITIALIZE_METHOD = "initialize"


@dataclass(frozen=True)
class JsonResponse:
    status: int
    headers: dict[str, str]
    payload: object | None
    elapsed_ms: float


class ProbeFailure(Exception):
    """A classified probe failure that is safe to expose in test output."""

    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


def positive_csv(value: str) -> list[int]:
    values = [int(part) for part in value.split(",")]
    if not values or any(item < 1 or item > 128 for item in values):
        raise argparse.ArgumentTypeError("values must be between 1 and 128")
    return values


def build_json_rpc_request(method: str, request_id: int | None, params: dict[str, object]) -> dict[str, object]:
    request: dict[str, object] = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        request["id"] = request_id
    return request


def parse_json_rpc_response(payload: object, request_id: int) -> dict[str, object]:
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
        return {"ok": False, "error": "json-rpc response mismatch"}
    if "error" in payload:
        return {"ok": False, "error": "json-rpc error"}
    if "result" not in payload:
        return {"ok": False, "error": "json-rpc result missing"}
    return {"ok": True}


def post_json(
    url: str,
    payload: dict[str, object],
    bearer_token: str | None,
    session_id: str | None,
    timeout: float,
    origin: str | None,
) -> JsonResponse:
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    if bearer_token:
        headers["authorization"] = f"Bearer {bearer_token}"
    if session_id:
        headers["mcp-session-id"] = session_id
    if origin:
        headers["origin"] = origin
    request = Request(url, data=encoded, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is an explicit test target
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise ProbeFailure("response too large")
            return JsonResponse(
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                payload=decode_payload(response_body),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )
    except HTTPError as error:
        return JsonResponse(
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            payload=None,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
    except ProbeFailure:
        raise
    except (OSError, URLError, TimeoutError) as error:
        raise ProbeFailure("transport failure") from error


def decode_payload(response_body: bytes) -> object | None:
    if not response_body:
        return None
    text = response_body.decode("utf-8")
    data_lines = [line[5:].lstrip() for line in text.splitlines() if line.startswith("data:")]
    if data_lines:
        text = "\n".join(data_lines).strip()
    try:
        return json.loads(text)
    except (TypeError, ValueError) as error:
        raise ProbeFailure("invalid JSON-RPC response") from error


def require_response(response: JsonResponse, request_id: int) -> None:
    if response.status < 200 or response.status >= 300:
        raise ProbeFailure("HTTP failure")
    if response.payload is None:
        raise ProbeFailure("empty JSON-RPC response")
    result = parse_json_rpc_response(response.payload, request_id)
    if not result["ok"]:
        raise ProbeFailure(str(result["error"]))


def initialize_session(
    url: str,
    bearer_token: str | None,
    timeout: float,
    origin: str | None,
) -> tuple[str | None, float, float]:
    initialize = post_json(
        url,
        build_json_rpc_request(
            INITIALIZE_METHOD,
            1,
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "apex-mcp-loadtest", "version": "1.0.0"},
            },
        ),
        bearer_token,
        None,
        timeout,
        origin,
    )
    require_response(initialize, 1)
    session_id = initialize.headers.get("mcp-session-id")
    initialized = post_json(
        url,
        build_json_rpc_request("notifications/initialized", None, {}),
        bearer_token,
        session_id,
        timeout,
        origin,
    )
    if initialized.status < 200 or initialized.status >= 300:
        raise ProbeFailure("HTTP failure")
    listed = post_json(
        url,
        build_json_rpc_request("tools/list", 2, {}),
        bearer_token,
        session_id,
        timeout,
        origin,
    )
    require_response(listed, 2)
    return session_id, initialize.elapsed_ms, listed.elapsed_ms


def run_worker(
    url: str,
    bearer_token: str | None,
    tool: str,
    input_value: object,
    calls: int,
    timeout: float,
    origin: str | None,
) -> dict[str, Any]:
    try:
        session_id, initialize_ms, list_tools_ms = initialize_session(url, bearer_token, timeout, origin)
        calls_ms: list[float] = []
        failures = 0
        for request_id in range(3, calls + 3):
            try:
                response = post_json(
                    url,
                    build_json_rpc_request("tools/call", request_id, {"name": tool, "arguments": input_value}),
                    bearer_token,
                    session_id,
                    timeout,
                    origin,
                )
                require_response(response, request_id)
            except ProbeFailure:
                failures += 1
                continue
            calls_ms.append(response.elapsed_ms)
        return {
            "initialize_ms": initialize_ms,
            "list_tools_ms": list_tools_ms,
            "cold_start_ms": initialize_ms + list_tools_ms,
            "call_ms": calls_ms,
            "failures": failures,
        }
    except ProbeFailure as error:
        return {"initialize_ms": None, "list_tools_ms": None, "cold_start_ms": None, "call_ms": [], "failures": calls, "error": error.category}


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, round((len(ordered) - 1) * fraction))
    return round(ordered[index], 3)


def latency_summary(values: list[float]) -> dict[str, float | None]:
    return {
        "min": round(min(values), 3) if values else None,
        "mean": round(statistics.mean(values), 3) if values else None,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
    }


def run(
    url: str,
    proxy_count: int,
    concurrency: int,
    samples: int,
    timeout: float,
    bearer_token: str | None = None,
    tool: str = "portfolio.read",
    input_value: object | None = None,
    origin: str | None = None,
) -> dict[str, object]:
    total = max(samples, concurrency * 2)
    worker_count = min(max(1, proxy_count * concurrency), total, MAX_SESSION_CONCURRENCY)
    call_counts = [total // worker_count + (index < total % worker_count) for index in range(worker_count)]
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        results = list(
            pool.map(
                lambda count: run_worker(
                    url,
                    bearer_token,
                    tool,
                    input_value if input_value is not None else {},
                    count,
                    timeout,
                    origin,
                ),
                call_counts,
            )
        )
    elapsed = time.perf_counter() - started
    call_timings = [duration for result in results for duration in result["call_ms"]]
    initialize_timings = [result["initialize_ms"] for result in results if result["initialize_ms"] is not None]
    list_timings = [result["list_tools_ms"] for result in results if result["list_tools_ms"] is not None]
    cold_timings = [result["cold_start_ms"] for result in results if result["cold_start_ms"] is not None]
    failures = sum(int(result["failures"]) for result in results)
    return {
        "proxies": proxy_count,
        "concurrency": concurrency,
        "sessions": worker_count,
        "samples": total,
        "successes": len(call_timings),
        "failures": failures,
        "throughput_per_second": round(len(call_timings) / elapsed, 3) if elapsed else 0,
        "latency_ms": latency_summary(call_timings),
        "initialize_latency_ms": latency_summary(initialize_timings),
        "list_tools_latency_ms": latency_summary(list_timings),
        "cold_start_latency_ms": latency_summary(cold_timings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18460/mcp")
    parser.add_argument("--bearer-token", default=os.environ.get("APEX_MCP_LOADTEST_TOKEN"))
    parser.add_argument("--tool", default="portfolio.read")
    parser.add_argument("--input-json", default="{}")
    parser.add_argument(
        "--origin",
        default=None,
        help="Origin header required by the configured proxy, when applicable",
    )
    parser.add_argument("--proxies", type=positive_csv, default=[1, 2, 8])
    parser.add_argument("--concurrency", type=positive_csv, default=[1, 8, 32])
    parser.add_argument("--samples", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if args.samples < 1 or args.samples > 10_000 or args.timeout <= 0 or args.timeout > 30:
        parser.error("samples must be 1..10000 and timeout must be >0..30")
    try:
        input_value = json.loads(args.input_json)
    except json.JSONDecodeError:
        parser.error("--input-json must be valid JSON")
    measurements = [
        run(
            args.url,
            proxies,
            concurrency,
            args.samples,
            args.timeout,
            args.bearer_token,
            args.tool,
            input_value,
            args.origin,
        )
        for proxies in args.proxies
        for concurrency in args.concurrency
    ]
    print(json.dumps({"url": args.url, "measurements": measurements}, indent=2, sort_keys=True))
    return 0 if all(measurement["failures"] == 0 for measurement in measurements) else 1


if __name__ == "__main__":
    raise SystemExit(main())
