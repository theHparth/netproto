"""
protocol.py — wire format for the Custom Network Protocol Toolkit.

Every message on the wire is one FRAME: a fixed-size 18-byte header followed by
a variable-length payload.

     0       1       2       3
     +-------+-------+-------+-------+
   0 |            MAGIC (4)          |   b'NPTK'
     +-------+-------+-------+-------+
   4 | VER(1)| TYP(1)|    SEQ (hi)   |
     +-------+-------+-------+-------+
   8 |   SEQ (lo)    |  LENGTH (hi)  |
     +-------+-------+-------+-------+
  12 | LENGTH (lo)   |    CRC32 (hi) |
     +-------+-------+-------+-------+
  16 |  CRC32 (lo)   |
     +-------+-------+
  18 |         PAYLOAD (LENGTH bytes)        ...
     +---------------------------------------

All multi-byte integers are BIG-ENDIAN (network byte order).
"""

import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum

# --------------------------------------------------------------------------
# Wire constants
# --------------------------------------------------------------------------

# Sentinel that starts every frame. If the first 4 bytes are not this, we are
# either not talking to a peer that speaks our protocol, or we have lost sync
# with the byte stream. Either way, fail loudly.
MAGIC = b"NPTK"

# Bumping this lets a future version of the protocol be rejected cleanly
# instead of being silently misparsed.
VERSION = 1

# struct format string for the header.
#   !  = big-endian, no padding between fields (network byte order)
#   4s = 4 raw bytes         -> magic
#   B  = unsigned char, 1 B  -> version
#   B  = unsigned char, 1 B  -> msg_type
#   I  = unsigned int, 4 B   -> seq
#   I  = unsigned int, 4 B   -> length
#   I  = unsigned int, 4 B   -> crc32
HEADER_FORMAT = "!4sBBIII"

# The same header WITHOUT the trailing crc32 field. This is the exact run of
# bytes the CRC is computed over (together with the payload), so having it as
# its own format string means we never slice by hand.
HEADER_PREFIX_FORMAT = "!4sBBII"

# 18. Computed, never hard-coded, so the two can't drift apart.
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

# The CRC covers every header byte EXCEPT the CRC field itself, plus the
# payload. This offset marks where the CRC field starts (byte 14).
CRC_OFFSET = HEADER_SIZE - 4

# Upper bound on a single payload. A length-prefixed protocol without this is a
# denial-of-service hole: a peer sends length=4294967295 and we try to allocate
# 4 GB. 16 MiB is generous for our use and cheap to refuse.
MAX_PAYLOAD_SIZE = 16 * 1024 * 1024

# seq is a 4-byte unsigned int, so it wraps at 2**32.
SEQ_MODULO = 2 ** 32    


class MsgType(IntEnum):
    """What a frame means. Values are what actually travel on the wire."""

    HELLO = 1     # handshake / connection open
    DATA = 2      # ordinary payload
    ACK = 3       # acknowledgement of a given seq (used by udp_reliable.py)
    ECHO = 4      # request: send this payload straight back
    ERROR = 5     # payload is a UTF-8 error string
    GOODBYE = 6   # orderly shutdown


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------

class ProtocolError(Exception):
    """Base class for every framing failure.

    Callers that don't care about the specific cause can catch this one type
    and close the connection.
    """


class BadMagicError(ProtocolError):
    """First 4 bytes were not MAGIC — not our protocol, or stream desynced."""


class UnsupportedVersionError(ProtocolError):
    """Header parsed, but the version byte is one we don't implement."""


class ChecksumError(ProtocolError):
    """Header and payload arrived, but the CRC32 does not match."""


class TruncatedFrameError(ProtocolError):
    """The peer closed (or the buffer ended) mid-frame."""


class PayloadTooLargeError(ProtocolError):
    """Declared length exceeds MAX_PAYLOAD_SIZE — refused before allocating."""


# --------------------------------------------------------------------------
# The Message object
# --------------------------------------------------------------------------

@dataclass
class Message:
    """One protocol message, as a normal Python object.

    Only three things are yours to choose. Everything else in the header
    (magic, version, length, crc) is derived at encode time, so it is
    impossible to construct a Message with an inconsistent header.
    """

    msg_type: MsgType
    seq: int = 0
    payload: bytes = b""

    def __post_init__(self) -> None:
        """Runs automatically right after the object is built. Rejects bad
        input at construction time rather than letting it reach the wire."""
        if not isinstance(self.payload, (bytes, bytearray)):
            raise TypeError(
                f"payload must be bytes, got {type(self.payload).__name__}"
            )
        self.payload = bytes(self.payload)

        if len(self.payload) > MAX_PAYLOAD_SIZE:
            raise PayloadTooLargeError(
                f"payload is {len(self.payload)} bytes, "
                f"limit is {MAX_PAYLOAD_SIZE}"
            )

        # seq is a 4-byte field, so wrap instead of overflowing struct.
        self.seq = self.seq % SEQ_MODULO
        self.msg_type = MsgType(self.msg_type)

    def encode(self) -> bytes:
        """Turn this object into the bytes that go on the wire.

        Order matters: build the 14-byte header prefix, checksum it together
        with the payload, then glue prefix + crc + payload.
        """
        prefix = struct.pack(
            HEADER_PREFIX_FORMAT,
            MAGIC,
            VERSION,
            int(self.msg_type),
            self.seq,
            len(self.payload),
        )

        crc = zlib.crc32(prefix + self.payload)

        return prefix + struct.pack("!I", crc) + self.payload

    def __len__(self) -> int:
        """len(msg) == number of bytes this message occupies on the wire."""
        return HEADER_SIZE + len(self.payload)

    def __repr__(self) -> str:
        """Never dump a 1 MB payload into a log line or a traceback."""
        preview = self.payload[:16]
        tail = "..." if len(self.payload) > 16 else ""
        return (
            f"Message(type={self.msg_type.name}, seq={self.seq}, "
            f"len={len(self.payload)}, payload={preview!r}{tail})"
        )


# --------------------------------------------------------------------------
# Decoding — bytes back into a Message
# --------------------------------------------------------------------------

def decode_header(head: bytes) -> tuple[MsgType, int, int, int]:
    """Validate and unpack the 18-byte header only.

    Returns (msg_type, seq, payload_length, crc).

    A server calls this FIRST, before reading the payload, because the
    payload length it is about to trust comes from here. Every check below
    happens before a single payload byte is allocated.
    """
    if len(head) < HEADER_SIZE:
        raise TruncatedFrameError(
            f"header is {len(head)} bytes, need {HEADER_SIZE}"
        )

    magic, version, raw_type, seq, length, crc = struct.unpack(
        HEADER_FORMAT, head[:HEADER_SIZE]
    )

    # 1. Is this even our protocol? Cheapest check, so it goes first.
    if magic != MAGIC:
        raise BadMagicError(f"expected {MAGIC!r}, got {magic!r}")

    # 2. Do we understand this version?
    if version != VERSION:
        raise UnsupportedVersionError(
            f"peer speaks version {version}, we speak {VERSION}"
        )

    # 3. Is the declared size sane? THIS is the line that stops a peer from
    #    making us allocate 4 GB. It must run before we read the payload.
    if length > MAX_PAYLOAD_SIZE:
        raise PayloadTooLargeError(
            f"peer declared {length} bytes, limit is {MAX_PAYLOAD_SIZE}"
        )

    # 4. Is the type one we know? MsgType() raises ValueError on unknown
    #    values, so translate it into our own exception family.
    try:
        msg_type = MsgType(raw_type)
    except ValueError:
        raise ProtocolError(f"unknown message type {raw_type}") from None

    return msg_type, seq, length, crc


def decode(frame: bytes) -> Message:
    """Turn a complete frame (header + payload) back into a Message.

    The CRC is checked last, on purpose: it is the most expensive check, and
    there is no point hashing a payload we already know is malformed.
    """
    msg_type, seq, length, crc_claimed = decode_header(frame)

    payload = frame[HEADER_SIZE:]

    if len(payload) != length:
        raise TruncatedFrameError(
            f"header declared {length} payload bytes, frame carries "
            f"{len(payload)}"
        )

    crc_actual = zlib.crc32(frame[:CRC_OFFSET] + payload)
    if crc_actual != crc_claimed:
        raise ChecksumError(
            f"crc mismatch: header says {crc_claimed}, computed {crc_actual}"
        )

    return Message(msg_type, seq, payload)


# --------------------------------------------------------------------------
# Socket helpers — reading a whole frame off a live TCP connection
# --------------------------------------------------------------------------

def recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from sock, or raise.

    sock.recv(n) returns UP TO n bytes — it can and will return fewer. This
    loops until the buffer is full, asking each time only for what is still
    missing.
    """
    if n == 0:
        # A zero-length payload is legal (e.g. GOODBYE). Never call recv(0):
        # it returns b"" and we would mistake that for a closed connection.
        return b""

    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            # b"" means the peer performed a clean shutdown mid-frame.
            raise TruncatedFrameError(
                f"connection closed after {len(buf)} of {n} bytes"
            )
        buf.extend(chunk)

    return bytes(buf)


def read_message(sock) -> Message:
    """Read one complete Message from a blocking TCP socket.

    This is the two-read dance:
      1. read a fixed HEADER_SIZE bytes  -> we now know the payload length
      2. read exactly that many more     -> we now have the whole frame
    """
    head = recv_exact(sock, HEADER_SIZE)

    # Validate the header BEFORE trusting its length field.
    _msg_type, _seq, length, _crc = decode_header(head)

    payload = recv_exact(sock, length)

    return decode(head + payload)


def send_message(sock, msg: Message) -> int:
    """Write one Message to a blocking TCP socket. Returns bytes sent.

    sendall() loops internally until every byte is written, so there is no
    send-side equivalent of recv_exact to write here.
    """
    frame = msg.encode()
    sock.sendall(frame)
    return len(frame)


# --------------------------------------------------------------------------
# Self-check. Only runs when you execute this file directly:
#     python protocol.py
# When another file does `import protocol`, this block is skipped.
# --------------------------------------------------------------------------

if __name__ == "__main__":
    print("HEADER_SIZE    :", HEADER_SIZE, "bytes")
    print("CRC_OFFSET     :", CRC_OFFSET)
    print("message types  :", [f"{m.name}={m.value}" for m in MsgType])
    print()

    msg = Message(MsgType.ECHO, seq=7, payload=b"hello world")
    frame = msg.encode()

    print("the object     :", msg)
    print("wire size      :", len(msg), "=", HEADER_SIZE, "header +",
          len(msg.payload), "payload")
    print("encoded bytes  :", frame)
    print("as hex         :", " ".join(f"{b:02x}" for b in frame))
    print()

    # --- round trip -----------------------------------------------------
    back = decode(frame)
    print("decoded back   :", back)
    print("identical      :", back == msg)
    print()

    # --- every way it can go wrong --------------------------------------
    print("failure cases")

    def show(label, bad_bytes):
        try:
            decode(bad_bytes)
            print(f"  {label:<18} NO ERROR (bug!)")
        except ProtocolError as exc:
            print(f"  {label:<18} {type(exc).__name__}: {exc}")

    show("bad magic", b"XXXX" + frame[4:])
    show("wrong version", frame[:4] + b"\x09" + frame[5:])
    show("truncated header", frame[:10])
    show("truncated payload", frame[:-3])
    show("flipped payload", frame[:-1] + b"X")
    show("huge length", struct.pack(HEADER_FORMAT, MAGIC, VERSION,
                                    MsgType.DATA, 1, 4_000_000_000, 0))

    # --- over a real socket ---------------------------------------------
    import socket

    print()
    print("over a real socket pair")

    left, right = socket.socketpair()
    try:
        sent = send_message(left, Message(MsgType.DATA, 42, b"over a socket"))
        got = read_message(right)
        print("  sent           :", sent, "bytes")
        print("  read back      :", got)

        # zero-length payload must survive the round trip too
        send_message(left, Message(MsgType.GOODBYE))
        print("  empty payload  :", read_message(right))

        # peer closes mid-frame -> TruncatedFrameError
        left.sendall(Message(MsgType.DATA, 1, b"cut me off").encode()[:20])
        left.close()
        try:
            read_message(right)
        except ProtocolError as exc:
            print("  half a frame   :", f"{type(exc).__name__}: {exc}")
    finally:
        left.close()
        right.close()

    print()
    print("self-check OK")
