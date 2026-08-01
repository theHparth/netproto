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

    empty = Message(MsgType.GOODBYE)
    print("empty payload  :", empty)
    print("still valid    :", len(empty.encode()), "bytes (header only)")
    print()

    try:
        Message(MsgType.DATA, payload="i am text, not bytes")
    except TypeError as exc:
        print("rejected       :", exc)

    print()
    print("self-check OK")
