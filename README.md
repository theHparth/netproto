# Custom Network Protocol Toolkit

A binary application-layer protocol implemented from scratch in Python, with two
server architectures (thread-per-client and asyncio), a reliable-delivery layer
over UDP, a packet-crafting tool, and a benchmark harness.

**Status:** in progress — building step by step.

## Components

| File | What it does | Done |
|---|---|---|
| `protocol.py` | `Message` frame: magic, type, seq, length, CRC32. Encode/decode + `ProtocolError`. | ☐ |
| `server_threaded.py` | Thread-per-client TCP server speaking the protocol. | ☐ |
| `server_async.py` | Same behaviour on asyncio. | ☐ |
| `client.py` | Load generator: throughput + p50/p95/p99 latency. | ☐ |
| `udp_reliable.py` | Stop-and-wait ARQ over UDP with artificial packet loss. | ☐ |
| `craft.py` | Scapy tool: build, sniff, and decode our own frames. | ☐ |
| `bench.py` | Threaded vs async at 10 / 100 / 500 concurrent clients. | ☐ |
| `tests/` | pytest suite for the framing layer. | ☐ |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Wire format

_(header diagram goes here — added in Step 1)_

## Benchmarks

_(results table goes here — added in Step 7)_

## Design decisions

_(added as the project grows)_
