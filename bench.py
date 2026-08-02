"""
bench.py — threaded vs async, at 10 / 100 / 500 concurrent clients.

Starts each server as a subprocess, waits for the port to open, drives it with
N concurrent clients, kills it, then does the same for the other server. Prints
a markdown table you can paste straight into the README, and writes
bench_results.json for later plotting.

    python bench.py
    python bench.py --quick                 # smaller run while developing
    python bench.py --clients 10 100        # skip the 500-client case
    python bench.py --count 200 --size 256

Each client opens ONE connection and reuses it for every message, so what is
being measured is the protocol and the server's concurrency model — not the
cost of the TCP handshake.
"""

import argparse
import json
import socket
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

from client import percentile, run_client

HOST = "127.0.0.1"

SERVERS = {
    "threaded": ("server_threaded.py", 9600),
    "async": ("server_async.py", 9601),
}

HERE = Path(__file__).resolve().parent


def wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    """Poll until the server is actually accepting, or give up.

    Sleeping a fixed 2 seconds instead would either be flaky on a slow
    machine or waste time on a fast one.
    """
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} never opened")


def start_server(script: str, port: int) -> subprocess.Popen:
    """Launch a server in its own process, with output suppressed.

    The servers print a line per connection. At 500 clients that is 1000
    lines of I/O competing with the thing we are trying to measure, so it
    goes to DEVNULL.
    """
    proc = subprocess.Popen(
        [sys.executable, "-u", str(HERE / script), "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(HERE),
    )
    wait_for_port(HOST, port)
    return proc


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_load(port: int, clients: int, count: int, size: int) -> dict:
    """Drive `clients` concurrent connections, each sending `count` messages."""
    all_latencies: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(clients)

    def worker() -> None:
        try:
            # Every thread waits here until all of them are ready, so the
            # load actually starts at the same instant. Without this the
            # first threads finish before the last ones have connected and
            # you never reach the concurrency you claim to be testing.
            barrier.wait(timeout=60)
            lat = run_client(HOST, port, count, size, warmup=5)
        except Exception as exc:                      # noqa: BLE001
            with lock:
                errors.append(f"{type(exc).__name__}: {exc}")
            return
        with lock:
            all_latencies.extend(lat)

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(clients)]

    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - started

    if errors:
        raise RuntimeError(f"{len(errors)} client(s) failed, first: {errors[0]}")

    ordered = sorted(all_latencies)
    return {
        "clients": clients,
        "messages": len(ordered),
        "seconds": round(wall, 3),
        "throughput": round(len(ordered) / wall),
        "p50": round(percentile(ordered, 50), 3),
        "p95": round(percentile(ordered, 95), 3),
        "p99": round(percentile(ordered, 99), 3),
        "max": round(ordered[-1], 3),
        "mean": round(statistics.fmean(ordered), 3),
    }


def markdown_table(results: list[dict]) -> str:
    lines = [
        "| server | clients | msgs | throughput (msg/s) | p50 (ms) "
        "| p95 (ms) | p99 (ms) | max (ms) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['server']} | {r['clients']} | {r['messages']:,} "
            f"| {r['throughput']:,} | {r['p50']} | {r['p95']} "
            f"| {r['p99']} | {r['max']} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="threaded vs async benchmark")
    parser.add_argument("--clients", type=int, nargs="+",
                        default=[10, 100, 500])
    parser.add_argument("--count", type=int, default=100,
                        help="messages per client")
    parser.add_argument("--size", type=int, default=64)
    parser.add_argument("--quick", action="store_true",
                        help="10/50 clients, 30 messages — for development")
    parser.add_argument("--out", default="bench_results.json")
    args = parser.parse_args()

    if args.quick:
        args.clients, args.count = [10, 50], 30

    results: list[dict] = []

    for name, (script, port) in SERVERS.items():
        print(f"\n=== {name} ===")
        for clients in args.clients:
            proc = start_server(script, port)
            try:
                row = run_load(port, clients, args.count, args.size)
            finally:
                stop_server(proc)

            row["server"] = name
            results.append(row)
            print(f"  {clients:4} clients  "
                  f"{row['throughput']:>8,} msg/s   "
                  f"p50 {row['p50']:>7.3f}   "
                  f"p95 {row['p95']:>7.3f}   "
                  f"p99 {row['p99']:>7.3f} ms")

            # Let TIME_WAIT sockets from this round drain before the next
            # one, so a fresh server can bind and we do not run out of
            # ephemeral ports.
            time.sleep(1.0)

    print("\n" + markdown_table(results) + "\n")

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
