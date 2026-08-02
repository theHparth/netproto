"""
client.py — load generator and latency measurement tool.

Opens ONE connection, sends N echo messages on it, verifies every reply
matches what was sent, and reports throughput plus p50 / p95 / p99 latency.

    python client.py
    python client.py --count 5000 --size 1024
    python client.py --port 9001            # point it at the async server

bench.py imports run_client() from here, so the measurement code lives in
exactly one place.
"""

import argparse
import math
import os
import socket
import time

from protocol import Message, MsgType, read_message, send_message

HOST = "127.0.0.1"
PORT = 9000


def percentile(sorted_values: list[float], p: float) -> float:
    """The value below which p percent of the samples fall.

    Input MUST already be sorted. We use nearest-rank: no interpolation, so
    the number returned is always a real measurement that actually happened.
    """
    if not sorted_values:
        return 0.0
    n = len(sorted_values)
    rank = math.ceil(p / 100.0 * n)          # 1-based rank
    index = min(max(rank - 1, 0), n - 1)     # clamp into the list
    return sorted_values[index]


def run_client(host: str, port: int, count: int, size: int,
               warmup: int = 20) -> list[float]:
    """Send `count` echo messages on one connection. Return latencies in ms.

    Latency here is round-trip time: the clock starts before sendall and
    stops after the whole reply has been decoded.
    """
    payload = os.urandom(size)
    latencies: list[float] = []

    sock = socket.create_connection((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        # Warmup: the first few requests pay for TCP slow start, DNS caches,
        # and Python importing/JIT-warming code paths. Measuring them would
        # pollute the percentiles with numbers that never repeat.
        for i in range(warmup):
            send_message(sock, Message(MsgType.ECHO, i, payload))
            read_message(sock)

        for i in range(count):
            seq = warmup + i

            start = time.perf_counter_ns()
            send_message(sock, Message(MsgType.ECHO, seq, payload))
            reply = read_message(sock)
            elapsed_ns = time.perf_counter_ns() - start

            # A benchmark that does not verify correctness is measuring
            # nothing. Check both fields we control.
            if reply.seq != seq:
                raise AssertionError(f"seq mismatch: sent {seq}, got {reply.seq}")
            if reply.payload != payload:
                raise AssertionError(f"payload mismatch on seq {seq}")

            latencies.append(elapsed_ns / 1_000_000)  # ns -> ms

        send_message(sock, Message(MsgType.GOODBYE, warmup + count))
        read_message(sock)

    finally:
        sock.close()

    return latencies


def report(latencies: list[float], wall_seconds: float, size: int) -> None:
    """Print a human-readable summary of one run."""
    ordered = sorted(latencies)
    n = len(ordered)

    msgs_per_sec = n / wall_seconds
    # Each message crosses the wire twice (request + echoed reply).
    bytes_moved = n * (18 + size) * 2
    mib_per_sec = bytes_moved / wall_seconds / (1024 * 1024)

    print(f"  messages      : {n}")
    print(f"  payload size  : {size} bytes")
    print(f"  wall time     : {wall_seconds:.3f} s")
    print(f"  throughput    : {msgs_per_sec:,.0f} msg/s"
          f"   ({mib_per_sec:.1f} MiB/s both directions)")
    print(f"  latency min   : {ordered[0]:.3f} ms")
    print(f"  latency p50   : {percentile(ordered, 50):.3f} ms")
    print(f"  latency p95   : {percentile(ordered, 95):.3f} ms")
    print(f"  latency p99   : {percentile(ordered, 99):.3f} ms")
    print(f"  latency max   : {ordered[-1]:.3f} ms")
    print(f"  latency mean  : {sum(ordered) / n:.3f} ms"
          f"   (shown last on purpose — see README)")


def main() -> None:
    parser = argparse.ArgumentParser(description="NPTK echo client / bench")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--count", type=int, default=1000,
                        help="messages to measure")
    parser.add_argument("--size", type=int, default=64,
                        help="payload bytes per message")
    parser.add_argument("--warmup", type=int, default=20,
                        help="unmeasured messages sent first")
    args = parser.parse_args()

    print(f"connecting to {args.host}:{args.port}")

    started = time.perf_counter()
    latencies = run_client(args.host, args.port, args.count,
                           args.size, args.warmup)
    wall = time.perf_counter() - started

    print("all replies verified OK")
    report(latencies, wall, args.size)


if __name__ == "__main__":
    main()
