# Custom Network Protocol Toolkit

A binary application-layer protocol written from scratch in Python, with two
server architectures, a reliable-delivery layer over UDP, a Scapy packet
crafter, and a benchmark harness that measures both of them.

No frameworks. `struct`, `socket`, `asyncio`, `zlib` and `scapy` only.

---

## Contents

| File | What it does |
|---|---|
| `protocol.py` | The wire format. `Message`, `encode`, `decode`, `recv_exact`, and a 5-way `ProtocolError` hierarchy. |
| `server_threaded.py` | Thread-per-client TCP server. |
| `server_async.py` | The same server on `asyncio`, using `readexactly`. |
| `client.py` | Load generator. Verifies every reply, reports throughput and p50/p95/p99. |
| `udp_reliable.py` | Stop-and-wait ARQ over UDP with artificial packet loss. |
| `craft.py` | Scapy layer for the protocol: build packets, write a pcap, decode with our own parser. |
| `bench.py` | Threaded vs async at 10 / 100 / 500 concurrent clients. |
| `tests/` | 44 pytest cases covering framing, validation and socket edge cases. |

---

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt

pytest                          # 44 passed
```

Two terminals:

```bash
python server_threaded.py                        # terminal 1
python client.py --count 3000 --size 64          # terminal 2
```

```bash
python server_async.py                           # terminal 1 (port 9001)
python client.py --port 9001 --count 3000        # terminal 2
```

Everything else:

```bash
python udp_reliable.py --loss 0.2 --count 5 --seed 3
python craft.py --mode build
python craft.py --mode pcap
python bench.py --clients 10 100 500 --count 100
```

---

## Wire format

Every message is a fixed 18-byte header followed by a variable-length payload.
All multi-byte integers are big-endian (network byte order).

```
  byte  0       1       2       3       4       5
       +-------+-------+-------+-------+-------+-------+
     0 |           MAGIC = "NPTK"      |  VER  | TYPE  |
       +-------+-------+-------+-------+-------+-------+
     6 |             SEQ (uint32)      |   LENGTH      |
       +-------+-------+-------+-------+-------+-------+
    12 |    LENGTH     |         CRC32 (uint32)        |
       +-------+-------+-------+-------+-------+-------+
    18 |  PAYLOAD ... exactly LENGTH bytes ...
       +--------------------------------------------
```

| Field | Offset | Size | Purpose |
|---|---|---|---|
| `MAGIC` | 0 | 4 | Constant `NPTK`. Wrong value means the peer doesn't speak this protocol, or the stream desynced. |
| `VERSION` | 4 | 1 | Currently `1`. Lets a future format be rejected explicitly instead of misparsed. |
| `TYPE` | 5 | 1 | `MsgType` enum — see below. |
| `SEQ` | 6 | 4 | Sequence number. Duplicate detection and request/response matching. Wraps at 2³². |
| `LENGTH` | 10 | 4 | Payload size in bytes. Capped at 16 MiB. |
| `CRC32` | 14 | 4 | Checksum of **bytes 0–13 plus the payload** — the header is covered, the CRC field itself is not. |

Message types: `HELLO=1`, `DATA=2`, `ACK=3`, `ECHO=4`, `ERROR=5`, `GOODBYE=6`.

An ECHO carrying `b"hello world"` — 29 bytes total:

```
4e 50 54 4b  01  04  00 00 00 07  00 00 00 0b  39 85 ed 52  68 65 6c ...
└─ "NPTK" ─┘ ver typ └─ seq = 7 ─┘└─ len = 11 ┘└── crc32 ──┘└─ payload ─┘
```

---

## Benchmarks

`bench.py`, 100 messages per client, 64-byte payloads, connections reused for
the whole run. Ubuntu 22.04, Python 3.10, client and server on one machine.

| server | clients | messages | throughput (msg/s) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---|---|---|---|---|---|---|
| threaded | 10 | 1,000 | 10,303 | 0.581 | 2.398 | 3.145 | 6.983 |
| threaded | 100 | 10,000 | 10,518 | 4.078 | 13.473 | 19.741 | 40.184 |
| threaded | 500 | 50,000 | 11,641 | 5.878 | 16.940 | **25.358** | 60.875 |
| async | 10 | 1,000 | **14,439** | 0.494 | 1.143 | 3.270 | 3.858 |
| async | 100 | 10,000 | **14,147** | 5.509 | 13.572 | 19.193 | 42.435 |
| async | 500 | 50,000 | **17,162** | 23.427 | 40.885 | 52.835 | 93.443 |

### What the numbers say

**Async wins throughput at every level** — +40% at 10 clients, +47% at 500.
No per-connection thread stacks and no kernel context switching between 500
threads.

**Threaded wins tail latency at 500 clients** — p99 of 25 ms versus 53 ms.
This is the opposite of the usual claim, and it is reproducible:

- The async server is **one thread**. All 500 connections are serialised
  through a single event loop, so every request queues behind the others.
  Its p50 of 23 ms is already close to its p99.
- The threaded server has 500 OS threads, and blocking syscalls release the
  GIL, so the kernel overlaps them across cores. Scheduling is also per
  thread, so the 500-thread process gets a larger share of CPU than the
  single-threaded one.
- Little's Law predicts it exactly: `500 concurrent ÷ 17,162 msg/s ≈ 29 ms`,
  which is essentially the measured p50 of 23 ms. The queue is behaving as
  theory says it should.

**Throughput flattens after 10 clients.** The server is already saturated at
that point; additional clients add queueing, not work. That is why latency
climbs while throughput barely moves.

**To make async win on both axes**, run one event loop per core as separate
processes sharing the port via `SO_REUSEPORT` — the nginx / gunicorn model.
Several short queues instead of one long one.

### Benchmark caveats

- Client and server share one machine. At 500 clients the load generator's
  500 threads compete with the server for CPU, so absolute numbers are
  directional rather than authoritative.
- Loopback only: no real network latency, packet loss or reordering.
- One run per configuration; no confidence intervals.

---

## Reliable UDP

`udp_reliable.py` implements stop-and-wait ARQ. `--loss` drops a fraction of
datagrams in each direction so the recovery path actually executes — on
loopback, UDP essentially never drops anything, so without injected loss the
retransmission code would never run.

| loss | messages | transmissions | efficiency | delivered exactly once |
|---|---|---|---|---|
| 0% | 6 | 6 | 100% | yes |
| 20% | 5 | 7 | 71% | yes |
| 30% | 6 | 19 | 32% | yes |

Reliability holds at every loss rate; efficiency collapses. That is the
trade-off stop-and-wait makes.

The interesting case is a **lost ACK**, not a lost DATA. The sender cannot
distinguish them — both look like silence — so it always retransmits. The
receiver therefore sees duplicates, must not deliver them twice, and must
still re-acknowledge them, because the only reason a duplicate arrived is
that the previous ACK was lost. Staying silent would livelock the sender.

Stop-and-wait caps throughput at one message per round trip: fine on
loopback, roughly 5 messages/second on a 200 ms link. The fix is a sliding
window — stop-and-wait is simply window size 1.

---

## Design decisions

**Length-prefix framing, not a delimiter.**
TCP is a byte stream with no message boundaries. A delimiter such as `\n`
requires escaping it inside the payload, which makes the encoded size
unpredictable and adds a scan over every byte. A length prefix passes
arbitrary binary data untouched and lets the receiver allocate exactly the
right buffer. Cost: the receiver must do two reads instead of one.

**Fixed-size header.**
The receiver has to know how many bytes to read before it knows anything
else. 18 bytes is the only number it can trust blindly; everything else is
derived from what those 18 bytes say.

**CRC32 over the header as well as the payload.**
Checksumming only the payload would let a flipped bit in `LENGTH` or `SEQ`
pass undetected — and a corrupted length is far more dangerous than a
corrupted payload. CRC32 is error *detection*, not authentication: an
attacker can recompute it after tampering. If the threat model included an
adversary rather than a bad cable, this would be an HMAC. TCP's own checksum
is 16-bit, covers a single hop, and does not validate this codebase's own
encode/decode path.

**16 MiB payload cap.**
`LENGTH` is a 4-byte unsigned integer, so a peer can legally declare
4,294,967,295 bytes. Allocating that from an 18-byte packet is a
denial-of-service hole. The cap is checked in `decode_header`, before any
payload is read or allocated.

**`decode_header` split out from `decode`.**
The server must validate the header and learn the payload length *before*
reading the payload. If validation happened after, the size cap would already
have been bypassed.

**Validation ordered cheapest-first.**
Length, magic, version, size cap and type are all O(1). The CRC touches every
byte, so it runs last: a flood of malformed frames is rejected without
hashing any of them.

**`recv_exact` instead of `recv`.**
`recv(n)` returns *up to* n bytes. On loopback it almost always returns all
of them, which is why this bug survives testing and fails in production. The
loop requests only the remaining bytes each time — asking for the full amount
again could consume the start of the next message and desynchronise the
stream permanently.

**Stop-and-wait for the UDP layer.**
The goal was to demonstrate the three mechanisms that make delivery reliable —
sequence numbers, acknowledgements, timeout-driven retransmission — with the
smallest amount of machinery that exercises all three. A sliding window adds
buffer management, cumulative or selective ACKs, and congestion control, none
of which teach anything new about the core loop.

**`Message` carries only `msg_type`, `seq` and `payload`.**
`magic` and `version` are constants; `length` and `crc32` are derived at
encode time. Storing them would make it possible to construct a message whose
header contradicts its own payload.

---

## Testing

```bash
pytest              # 44 tests
pytest -v           # one line each
pytest -k crc       # filter by name
```

Coverage includes round-trip equality across nine payload sizes chosen around
the 18-byte header boundary, every message type, empty and 1 MB payloads,
each of the five error types with its specific exception, two frames written
in a single `sendall` and split correctly, a peer closing mid-frame, and a
`recv_exact(sock, 0)` regression guard.

---

## Known limitations

- **No authentication or encryption.** CRC32 detects accidents, not attacks.
- **No sliding window.** UDP throughput is one message per round trip.
- **No connection-level flow control** beyond what TCP and `drain()` provide.
- **No graceful drain on shutdown** — Ctrl-C drops in-flight connections.
- **Benchmarks are single-machine and single-run.**
- **Scapy live sniffing needs Npcap on Windows.** `--mode build` and
  `--mode pcap` need no privileges and demonstrate the same dissection.

## Next steps

- One event loop per core via `SO_REUSEPORT`, then re-run the benchmark.
- Sliding-window ARQ with selective acknowledgement.
- HMAC-SHA256 alongside the CRC for authenticated framing.
- A Wireshark Lua dissector so captures decode natively.
- Property-based tests with Hypothesis over arbitrary payloads.
