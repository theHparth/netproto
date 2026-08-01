"""
server_threaded.py — thread-per-client TCP server speaking the NPTK protocol.

Model: one OS thread per connected client. The main thread does nothing but
accept() in a loop and hand each new connection to a worker thread.

    main thread            worker threads
    -----------            --------------
    accept()  --------->   handle_client(conn A)
    accept()  --------->   handle_client(conn B)
    accept()  --------->   handle_client(conn C)

Run it:
    python server_threaded.py
    python server_threaded.py --host 0.0.0.0 --port 9000
"""

import argparse
import socket
import threading

from protocol import (
    Message,
    MsgType,
    ProtocolError,
    read_message,
    send_message,
)

HOST = "127.0.0.1"
PORT = 9000

# How many connections the OS may queue up while we are busy between two
# accept() calls. Not a client limit — a *pending* client limit.
BACKLOG = 128

# Shared counter of live connections. Threads touch it, so it needs a lock.
_live = 0
_live_lock = threading.Lock()


def handle_client(conn: socket.socket, addr) -> None:
    """Serve one client until it disconnects. Runs in its own thread.

    Loops forever reading messages. Every exit path goes through the finally
    block, so a socket is never leaked no matter how the client misbehaves.
    """
    global _live

    with _live_lock:
        _live += 1
        live_now = _live
    print(f"[+] {addr} connected  ({live_now} live)")

    try:
        while True:
            # Blocks until a whole frame arrives, or the client goes away.
            msg = read_message(conn)

            if msg.msg_type is MsgType.GOODBYE:
                send_message(conn, Message(MsgType.GOODBYE, msg.seq))
                break

            # Echo service: same type, same seq, same payload back.
            send_message(conn, Message(msg.msg_type, msg.seq, msg.payload))

    except ProtocolError as exc:
        # A malformed frame kills THIS connection only. Everyone else keeps
        # running. Never let one bad client take down the process.
        print(f"[!] {addr} protocol error: {type(exc).__name__}: {exc}")

    except (ConnectionResetError, BrokenPipeError):
        # Client vanished without a clean close. Normal on the internet.
        print(f"[!] {addr} reset the connection")

    finally:
        conn.close()
        with _live_lock:
            _live -= 1
            live_now = _live
        print(f"[-] {addr} closed     ({live_now} live)")


def serve(host: str = HOST, port: int = PORT) -> None:
    """Bind, listen, and accept forever, one thread per client."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Without this, restarting the server within ~60s fails with
    # "Address already in use" because the old port is still in TIME_WAIT.
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listener.bind((host, port))
    listener.listen(BACKLOG)
    print(f"threaded server listening on {host}:{port}  (backlog {BACKLOG})")

    try:
        while True:
            conn, addr = listener.accept()

            # Nagle's algorithm delays small writes to batch them. Our echo
            # replies are tiny, so leaving it on adds ~40ms to every reply.
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            t = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,          # don't block interpreter exit
                name=f"client-{addr[1]}",
            )
            t.start()

    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        listener.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="NPTK threaded echo server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    serve(args.host, args.port)


if __name__ == "__main__":
    main()
