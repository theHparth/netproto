"""
udp_reliable.py — reliable delivery on top of UDP, using stop-and-wait ARQ.

UDP gives you no delivery guarantee, no ordering and no duplicate detection.
This file rebuilds the three things TCP would have given you, by hand:

    sequence numbers  -> the receiver can spot a duplicate
    acknowledgements  -> the sender learns a datagram arrived
    timeout + retry   -> a lost datagram is sent again

ARQ = Automatic Repeat reQuest. Stop-and-wait is its simplest form: send one
message, refuse to send the next until this one is acknowledged.

    sender                       receiver
      | --- DATA seq=0 --------->  |
      | <-------------- ACK 0 ---  |
      | --- DATA seq=1 ---X        |   lost
      |     (timeout)              |
      | --- DATA seq=1 --------->  |   retransmit
      | <-------------- ACK 1 ---  |

Run the self-contained demo (receiver runs in a background thread):
    python udp_reliable.py
    python udp_reliable.py --loss 0.3 --count 10

Or run the two halves in two terminals:
    python udp_reliable.py --role receiver --loss 0.2
    python udp_reliable.py --role sender   --loss 0.2
"""

import argparse
import random
import socket
import threading
import time

from protocol import (
    MAX_PAYLOAD_SIZE,
    HEADER_SIZE,
    Message,
    MsgType,
    ProtocolError,
    decode,
)

HOST = "127.0.0.1"
PORT = 9500

# One datagram must fit in one UDP packet. 65507 is the theoretical maximum
# payload of an IPv4 UDP datagram; anything near it will be fragmented at the
# IP layer and is far more likely to be lost.
MAX_DATAGRAM = 65507

TIMEOUT = 0.25          # seconds to wait for an ACK before retransmitting
MAX_RETRIES = 20        # give up eventually instead of looping forever


# --------------------------------------------------------------------------
# Artificial packet loss
# --------------------------------------------------------------------------

def lossy_send(sock: socket.socket, data: bytes, addr, loss: float,
               label: str) -> bool:
    """sendto() that silently drops the datagram `loss` fraction of the time.

    This is the whole point of the --loss flag: a real localhost UDP socket
    basically never drops anything, so the retransmission logic would never
    execute and we could not prove it works.
    """
    if random.random() < loss:
        print(f"    x  DROPPED {label}")
        return False

    sock.sendto(data, addr)
    return True


# --------------------------------------------------------------------------
# Receiver
# --------------------------------------------------------------------------

def run_receiver(host: str, port: int, loss: float,
                 stop: threading.Event | None = None) -> None:
    """Accept datagrams, ACK every one, deliver each seq exactly once."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)

    print(f"receiver listening on {host}:{port}  (ack loss {loss:.0%})")

    expected = 0          # the next seq we have NOT yet delivered
    delivered = 0
    duplicates = 0

    try:
        while stop is None or not stop.is_set():
            try:
                data, addr = sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue

            # A corrupt datagram is simply not acknowledged. The sender's
            # timer will fire and it will retransmit. Never ACK something
            # you could not verify.
            try:
                msg = decode(data)
            except ProtocolError as exc:
                print(f"  !! corrupt datagram dropped: {type(exc).__name__}")
                continue

            if msg.msg_type is MsgType.GOODBYE:
                lossy_send(sock, Message(MsgType.ACK, msg.seq).encode(),
                           addr, 0.0, "final ack")
                break

            if msg.seq == expected:
                print(f"  <- DATA seq={msg.seq}  delivered: {msg.payload!r}")
                expected += 1
                delivered += 1
            else:
                # Already delivered. Do NOT deliver again — but DO re-ACK,
                # because the only reason we are seeing it twice is that our
                # previous ACK never arrived.
                duplicates += 1
                print(f"  <- DATA seq={msg.seq}  DUPLICATE, not delivered")

            lossy_send(sock, Message(MsgType.ACK, msg.seq).encode(),
                       addr, loss, f"ACK {msg.seq}")

    finally:
        sock.close()
        print(f"receiver done: {delivered} delivered, "
              f"{duplicates} duplicates suppressed")


# --------------------------------------------------------------------------
# Sender
# --------------------------------------------------------------------------

def run_sender(host: str, port: int, count: int, loss: float,
               timeout: float = TIMEOUT) -> dict:
    """Send `count` messages, one at a time, retrying until each is ACKed."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    addr = (host, port)

    transmissions = 0
    retransmissions = 0
    started = time.perf_counter()

    try:
        for seq in range(count):
            payload = f"message-{seq}".encode()
            frame = Message(MsgType.DATA, seq, payload).encode()

            if len(frame) > MAX_DATAGRAM:
                raise ValueError("frame too large for one UDP datagram")

            for attempt in range(MAX_RETRIES):
                if attempt:
                    retransmissions += 1
                    print(f"  ** timeout, retransmitting seq={seq} "
                          f"(attempt {attempt + 1})")

                transmissions += 1
                lossy_send(sock, frame, addr, loss, f"DATA {seq}")

                # Wait for the matching ACK. Anything else is ignored.
                deadline = time.perf_counter() + timeout
                acked = False
                while time.perf_counter() < deadline:
                    remaining = deadline - time.perf_counter()
                    sock.settimeout(max(remaining, 0.001))
                    try:
                        data, _ = sock.recvfrom(MAX_DATAGRAM)
                    except socket.timeout:
                        break

                    try:
                        ack = decode(data)
                    except ProtocolError:
                        continue

                    # A stale ACK for an older seq is normal after a
                    # retransmit. Ignore it and keep waiting.
                    if ack.msg_type is MsgType.ACK and ack.seq == seq:
                        print(f"  -> ACK  seq={seq}")
                        acked = True
                        break

                if acked:
                    break
            else:
                raise TimeoutError(f"seq {seq} never acknowledged "
                                   f"after {MAX_RETRIES} attempts")

        sock.sendto(Message(MsgType.GOODBYE, count).encode(), addr)

    finally:
        sock.close()

    elapsed = time.perf_counter() - started
    return {
        "messages": count,
        "transmissions": transmissions,
        "retransmissions": retransmissions,
        "efficiency": count / transmissions if transmissions else 0.0,
        "seconds": elapsed,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stop-and-wait ARQ over UDP")
    parser.add_argument("--role", choices=["demo", "sender", "receiver"],
                        default="demo")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--count", type=int, default=8)
    parser.add_argument("--loss", type=float, default=0.2,
                        help="fraction of datagrams to drop, 0.0 to 1.0")
    parser.add_argument("--timeout", type=float, default=TIMEOUT)
    parser.add_argument("--seed", type=int, default=None,
                        help="fix the RNG so a run is reproducible")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.role == "receiver":
        run_receiver(args.host, args.port, args.loss)
        return

    if args.role == "sender":
        stats = run_sender(args.host, args.port, args.count,
                           args.loss, args.timeout)
        print_stats(stats, args.loss)
        return

    # demo: receiver in a background thread, sender in this one
    stop = threading.Event()
    t = threading.Thread(
        target=run_receiver,
        args=(args.host, args.port, args.loss, stop),
        daemon=True,
    )
    t.start()
    time.sleep(0.2)                     # let the receiver bind

    try:
        stats = run_sender(args.host, args.port, args.count,
                           args.loss, args.timeout)
        print_stats(stats, args.loss)
    finally:
        stop.set()
        t.join(timeout=1.0)


def print_stats(stats: dict, loss: float) -> None:
    print()
    print(f"  loss setting   : {loss:.0%} per direction")
    print(f"  messages sent  : {stats['messages']}")
    print(f"  transmissions  : {stats['transmissions']}")
    print(f"  retransmissions: {stats['retransmissions']}")
    print(f"  efficiency     : {stats['efficiency']:.0%} "
          f"(messages / transmissions)")
    print(f"  wall time      : {stats['seconds']:.2f} s")
    print("  every message delivered exactly once")


if __name__ == "__main__":
    main()
