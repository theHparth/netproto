"""
server_async.py — the same echo server, on asyncio instead of threads.

Identical wire behaviour to server_threaded.py. The only thing that changes
is HOW concurrency is achieved:

    threaded : one OS thread per client, the kernel switches between them
    asyncio  : one thread, one event loop, tasks yield at every await

Because the protocol is unchanged, client.py works against either server
without modification. That is the whole point of the benchmark in Step 7.

Run it:
    python server_async.py
    python server_async.py --port 9001
"""

import argparse
import asyncio
import socket

from protocol import (
    HEADER_SIZE,
    Message,
    MsgType,
    ProtocolError,
    TruncatedFrameError,
    decode,
    decode_header,
)

HOST = "127.0.0.1"
PORT = 9001

_live = 0          # no lock needed — see the comment in handle_client


async def read_message_async(reader: asyncio.StreamReader) -> Message:
    """asyncio's answer to recv_exact().

    StreamReader.readexactly(n) already loops for us and raises
    IncompleteReadError if the peer closes early — so the hand-written loop
    from protocol.py is not needed here. We translate its exception into ours
    so callers still only have to catch ProtocolError.
    """
    try:
        head = await reader.readexactly(HEADER_SIZE)
    except asyncio.IncompleteReadError as exc:
        raise TruncatedFrameError(
            f"connection closed after {len(exc.partial)} of {HEADER_SIZE} bytes"
        ) from None

    # Validate the header BEFORE trusting the length it declares.
    _msg_type, _seq, length, _crc = decode_header(head)

    if length:
        try:
            payload = await reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            raise TruncatedFrameError(
                f"connection closed after {len(exc.partial)} of {length} "
                f"payload bytes"
            ) from None
    else:
        payload = b""

    return decode(head + payload)


async def handle_client(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> None:
    """One coroutine per client. asyncio.start_server calls this for us."""
    global _live

    addr = writer.get_extra_info("peername")

    # Same reason as the threaded server: our replies are tiny, and Nagle
    # would sit on them for up to 40 ms.
    sock = writer.get_extra_info("socket")
    if sock is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # No lock here, unlike the threaded server. A coroutine can only be
    # interrupted at an `await`, and there is no await between these two
    # lines, so the increment cannot be interleaved.
    _live += 1
    print(f"[+] {addr} connected  ({_live} live)")

    try:
        while True:
            msg = await read_message_async(reader)

            if msg.msg_type is MsgType.GOODBYE:
                writer.write(Message(MsgType.GOODBYE, msg.seq).encode())
                await writer.drain()
                break

            writer.write(Message(msg.msg_type, msg.seq, msg.payload).encode())

            # drain() applies backpressure: if the OS send buffer is full it
            # suspends this task until it drains. Without it a fast producer
            # would queue replies in RAM until the process dies.
            await writer.drain()

    except ProtocolError as exc:
        print(f"[!] {addr} protocol error: {type(exc).__name__}: {exc}")

    except (ConnectionResetError, BrokenPipeError):
        print(f"[!] {addr} reset the connection")

    finally:
        _live -= 1
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
        print(f"[-] {addr} closed     ({_live} live)")


async def serve(host: str = HOST, port: int = PORT) -> None:
    server = await asyncio.start_server(
        handle_client, host, port, backlog=128, reuse_address=True
    )
    bound = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"async server listening on {bound}  (backlog 128)")

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="NPTK asyncio echo server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    try:
        asyncio.run(serve(args.host, args.port))
    except KeyboardInterrupt:
        print("\nshutting down")


if __name__ == "__main__":
    main()
