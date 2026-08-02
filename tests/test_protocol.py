"""
tests/test_protocol.py — the framing layer under test.

Run from the project root:
    pytest
    pytest -v                  # one line per test
    pytest -k crc              # only tests with "crc" in the name

Every test follows arrange / act / assert and asserts ONE thing, so a red
test tells you exactly what broke.
"""

import socket
import struct

import pytest

from protocol import (
    CRC_OFFSET,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    MAX_PAYLOAD_SIZE,
    VERSION,
    BadMagicError,
    ChecksumError,
    Message,
    MsgType,
    PayloadTooLargeError,
    ProtocolError,
    TruncatedFrameError,
    UnsupportedVersionError,
    decode,
    read_message,
    recv_exact,
    send_message,
)


# ==========================================================================
# Happy path
# ==========================================================================

def test_round_trip_preserves_everything():
    original = Message(MsgType.ECHO, seq=42, payload=b"hello world")

    decoded = decode(original.encode())

    assert decoded == original


@pytest.mark.parametrize("size", [0, 1, 17, 18, 19, 64, 1023, 1024, 65535])
def test_round_trip_at_many_sizes(size):
    """Sizes around the 18-byte header boundary are where off-by-one bugs
    live, so they are all covered explicitly."""
    original = Message(MsgType.DATA, seq=1, payload=b"x" * size)

    decoded = decode(original.encode())

    assert decoded.payload == original.payload


def test_empty_payload_is_legal():
    original = Message(MsgType.GOODBYE)

    frame = original.encode()

    assert len(frame) == HEADER_SIZE
    assert decode(frame).payload == b""


def test_one_megabyte_payload():
    payload = b"z" * (1024 * 1024)
    original = Message(MsgType.DATA, seq=7, payload=payload)

    decoded = decode(original.encode())

    assert decoded.payload == payload


@pytest.mark.parametrize("msg_type", list(MsgType))
def test_every_message_type_survives(msg_type):
    decoded = decode(Message(msg_type, 1, b"abc").encode())

    assert decoded.msg_type is msg_type


def test_wire_size_matches_len():
    msg = Message(MsgType.DATA, 1, b"y" * 100)

    assert len(msg) == len(msg.encode()) == HEADER_SIZE + 100


def test_first_four_bytes_are_the_magic():
    frame = Message(MsgType.HELLO, 1, b"").encode()

    assert frame[:4] == MAGIC


# ==========================================================================
# Malformed input — one test per failure mode
# ==========================================================================

def test_bad_magic():
    frame = Message(MsgType.DATA, 1, b"payload").encode()
    corrupted = b"XXXX" + frame[4:]

    with pytest.raises(BadMagicError):
        decode(corrupted)


def test_unsupported_version():
    frame = Message(MsgType.DATA, 1, b"payload").encode()
    corrupted = frame[:4] + bytes([VERSION + 1]) + frame[5:]

    with pytest.raises(UnsupportedVersionError):
        decode(corrupted)


def test_truncated_header():
    frame = Message(MsgType.DATA, 1, b"payload").encode()

    with pytest.raises(TruncatedFrameError):
        decode(frame[:HEADER_SIZE - 1])


def test_truncated_payload():
    frame = Message(MsgType.DATA, 1, b"payload").encode()

    with pytest.raises(TruncatedFrameError):
        decode(frame[:-2])


def test_bad_crc_when_payload_is_flipped():
    frame = bytearray(Message(MsgType.DATA, 1, b"payload").encode())
    frame[-1] ^= 0xFF                       # flip every bit of the last byte

    with pytest.raises(ChecksumError):
        decode(bytes(frame))


def test_bad_crc_when_a_header_field_is_flipped():
    """Proves the CRC covers the HEADER too, not just the payload."""
    frame = bytearray(Message(MsgType.DATA, seq=1, payload=b"payload").encode())
    frame[9] ^= 0xFF                        # last byte of the seq field

    with pytest.raises(ChecksumError):
        decode(bytes(frame))


def test_declared_length_beyond_the_cap_is_refused():
    """The DoS case: an 18-byte header claiming a 4 GB payload."""
    evil = struct.pack(HEADER_FORMAT, MAGIC, VERSION, MsgType.DATA,
                       1, 4_000_000_000, 0)

    with pytest.raises(PayloadTooLargeError):
        decode(evil)


def test_unknown_message_type():
    evil = struct.pack(HEADER_FORMAT, MAGIC, VERSION, 200, 1, 0, 0)

    with pytest.raises(ProtocolError):
        decode(evil)


def test_empty_input():
    with pytest.raises(TruncatedFrameError):
        decode(b"")


@pytest.mark.parametrize("exc", [
    BadMagicError,
    UnsupportedVersionError,
    ChecksumError,
    TruncatedFrameError,
    PayloadTooLargeError,
])
def test_every_error_is_a_protocol_error(exc):
    """A server writing `except ProtocolError:` must catch all of them."""
    assert issubclass(exc, ProtocolError)


# ==========================================================================
# Construction-time validation
# ==========================================================================

def test_str_payload_is_rejected():
    with pytest.raises(TypeError):
        Message(MsgType.DATA, 1, "text not bytes")


def test_oversized_payload_is_rejected_at_construction():
    with pytest.raises(PayloadTooLargeError):
        Message(MsgType.DATA, 1, b"x" * (MAX_PAYLOAD_SIZE + 1))


def test_seq_wraps_instead_of_overflowing():
    msg = Message(MsgType.DATA, seq=2 ** 32 + 5)

    assert msg.seq == 5


def test_crc_offset_is_where_the_crc_field_starts():
    msg = Message(MsgType.DATA, 1, b"abc")
    frame = msg.encode()

    _, _, _, _, _, crc_in_frame = struct.unpack(HEADER_FORMAT,
                                                frame[:HEADER_SIZE])
    crc_bytes = frame[CRC_OFFSET:HEADER_SIZE]

    assert struct.unpack("!I", crc_bytes)[0] == crc_in_frame


def test_repr_does_not_dump_a_huge_payload():
    msg = Message(MsgType.DATA, 1, b"q" * 100_000)

    assert len(repr(msg)) < 120


# ==========================================================================
# Socket helpers — real sockets, no server needed
# ==========================================================================

@pytest.fixture
def socket_pair():
    """Two connected sockets. Closed automatically after each test."""
    left, right = socket.socketpair()
    yield left, right
    left.close()
    right.close()


def test_send_and_read_over_a_socket(socket_pair):
    left, right = socket_pair
    original = Message(MsgType.ECHO, 99, b"over the wire")

    send_message(left, original)

    assert read_message(right) == original


def test_empty_payload_over_a_socket(socket_pair):
    """Regression guard: recv_exact(sock, 0) must NOT look like a hang-up."""
    left, right = socket_pair

    send_message(left, Message(MsgType.GOODBYE, 5))

    assert read_message(right).payload == b""


def test_two_messages_in_one_write_are_split_correctly(socket_pair):
    """The framing test that matters: both frames sent in a single write."""
    left, right = socket_pair
    first = Message(MsgType.DATA, 1, b"first")
    second = Message(MsgType.DATA, 2, b"second message")

    left.sendall(first.encode() + second.encode())

    assert read_message(right) == first
    assert read_message(right) == second


def test_peer_closing_mid_frame(socket_pair):
    left, right = socket_pair
    frame = Message(MsgType.DATA, 1, b"cut me off").encode()

    left.sendall(frame[:12])        # only part of the header
    left.close()

    with pytest.raises(TruncatedFrameError):
        read_message(right)


def test_recv_exact_returns_nothing_for_zero(socket_pair):
    _left, right = socket_pair

    assert recv_exact(right, 0) == b""
