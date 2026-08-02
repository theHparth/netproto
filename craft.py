"""
craft.py — build, capture and dissect our own protocol with Scapy.

Three things happen here:

  1. NPTK is registered as a real Scapy layer, so Scapy can pretty-print our
     header field by field instead of showing an opaque blob of bytes.
  2. Packets are built by hand — Ethernet / IP / UDP / NPTK — and written to
     a .pcap you can open in Wireshark.
  3. They are read back and decoded with protocol.decode(), proving the
     hand-built bytes are byte-for-byte what our own parser expects.

Modes:
    python craft.py --mode build     # build one packet and show it (no admin)
    python craft.py --mode pcap      # build -> capture.pcap -> read -> decode
    python craft.py --mode sniff     # live capture (NEEDS ADMIN/ROOT)
    python craft.py --mode send      # transmit real datagrams (NEEDS ADMIN)

`build` and `pcap` need no special privileges and work everywhere. Start
there. Live sniffing needs root on Linux/macOS and Npcap on Windows.
"""

import argparse
import struct
import zlib

from scapy.all import (
    IP,
    UDP,
    ByteEnumField,
    ByteField,
    Ether,
    FieldLenField,
    IntField,
    Packet,
    Raw,
    StrFixedLenField,
    StrLenField,
    bind_layers,
    hexdump,
    rdpcap,
    send,
    sniff,
    wrpcap,
)

from protocol import (
    CRC_OFFSET,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    Message,
    MsgType,
    ProtocolError,
    decode,
)

NPTK_PORT = 9500
PCAP_FILE = "capture.pcap"


# --------------------------------------------------------------------------
# Teaching Scapy our protocol
# --------------------------------------------------------------------------

class NPTK(Packet):
    """Our 18-byte header, described declaratively for Scapy.

    fields_desc mirrors HEADER_FORMAT exactly. Once this class exists,
    pkt.show() prints named fields, pkt.seq works, and Scapy can build a
    valid frame with the length and CRC filled in automatically.
    """

    name = "NPTK"

    fields_desc = [
        StrFixedLenField("magic", MAGIC, 4),
        ByteField("version", VERSION),
        ByteEnumField("msg_type", int(MsgType.DATA),
                      {int(m): m.name for m in MsgType}),
        IntField("seq", 0),
        # None means "work it out from the payload" — Scapy fills it in at
        # build time, the same way our Message.encode() does.
        FieldLenField("length", None, fmt="I", length_of="body"),
        IntField("crc32", 0),
        StrLenField("body", b"", length_from=lambda pkt: pkt.length),
    ]

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        """Called after the fields are serialised. Fills in the CRC.

        Exactly the same rule as protocol.encode(): checksum bytes 0..13 of
        the header plus the payload, then write the result at CRC_OFFSET.
        """
        if self.crc32 == 0:
            body = pkt[:CRC_OFFSET] + pkt[HEADER_SIZE:]
            crc = zlib.crc32(body)
            pkt = (pkt[:CRC_OFFSET]
                   + struct.pack("!I", crc)
                   + pkt[HEADER_SIZE:])
        return pkt + pay


# "A UDP packet on port 9500 contains an NPTK message." Now Scapy dissects
# our protocol automatically instead of showing Raw bytes.
bind_layers(UDP, NPTK, dport=NPTK_PORT)
bind_layers(UDP, NPTK, sport=NPTK_PORT)


# --------------------------------------------------------------------------
# Building
# --------------------------------------------------------------------------

def craft(seq: int, payload: bytes,
          msg_type: MsgType = MsgType.DATA,
          src: str = "127.0.0.1", dst: str = "127.0.0.1"):
    """Build a full Ethernet/IP/UDP/NPTK packet from scratch."""
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=40000 + seq, dport=NPTK_PORT)
        / NPTK(seq=seq, msg_type=int(msg_type), body=payload)
    )


def nptk_bytes(pkt) -> bytes:
    """Pull just our protocol's bytes out of a captured packet."""
    if NPTK in pkt:
        return bytes(pkt[NPTK])
    if Raw in pkt:
        return bytes(pkt[Raw])
    return b""


def decode_with_our_parser(raw: bytes) -> str:
    """The point of the whole exercise: Scapy built it, WE parse it."""
    try:
        return f"OK   {decode(raw)}"
    except ProtocolError as exc:
        return f"FAIL {type(exc).__name__}: {exc}"


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------

def mode_build() -> None:
    pkt = craft(7, b"hello world", MsgType.ECHO)

    print("=== scapy's view, layer by layer ===")
    pkt.show2()               # show2() builds first, so length/crc are filled

    print("=== raw bytes of our layer only ===")
    raw = bytes(NPTK(bytes(pkt[NPTK])))
    hexdump(raw)

    print("\n=== the same message built by protocol.py ===")
    ours = Message(MsgType.ECHO, 7, b"hello world").encode()
    hexdump(ours)

    print(f"\nscapy bytes == protocol.py bytes : {raw == ours}")
    print(f"our parser on scapy's bytes      : {decode_with_our_parser(raw)}")


def mode_pcap(count: int) -> None:
    packets = [craft(i, f"crafted-{i}".encode()) for i in range(count)]

    # A deliberately corrupt one, to prove our CRC check earns its keep.
    broken = craft(99, b"corrupted")
    broken_bytes = bytearray(bytes(broken))
    broken_bytes[-1] ^= 0xFF
    packets.append(Ether(bytes(broken_bytes)))

    wrpcap(PCAP_FILE, packets)
    print(f"wrote {len(packets)} packets to {PCAP_FILE}")
    print("open it in Wireshark if you want to see it graphically\n")

    print(f"reading {PCAP_FILE} back and decoding with protocol.decode()")
    for i, pkt in enumerate(rdpcap(PCAP_FILE)):
        raw = nptk_bytes(pkt)
        print(f"  packet {i}: {decode_with_our_parser(raw)}")


def mode_sniff(count: int, iface: str | None, timeout: int) -> None:
    print(f"sniffing udp port {NPTK_PORT} — send some traffic now")
    print("(needs root on linux/macos, npcap on windows)\n")

    def on_packet(pkt) -> None:
        raw = nptk_bytes(pkt)
        if raw:
            print(f"  captured {len(raw):>3} bytes: "
                  f"{decode_with_our_parser(raw)}")

    sniff(filter=f"udp port {NPTK_PORT}", prn=on_packet,
          count=count, timeout=timeout, iface=iface, store=False)
    print("\nsniff finished")


def mode_send(count: int, dst: str) -> None:
    print(f"sending {count} crafted datagrams to {dst}:{NPTK_PORT}")
    for i in range(count):
        pkt = IP(dst=dst) / UDP(sport=40000 + i, dport=NPTK_PORT) \
              / NPTK(seq=i, body=f"crafted-{i}".encode())
        send(pkt, verbose=False)
    print("done — run --mode sniff in another terminal to see them")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="craft, capture and dissect NPTK packets with scapy")
    parser.add_argument("--mode",
                        choices=["build", "pcap", "sniff", "send"],
                        default="build")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--dst", default="127.0.0.1")
    parser.add_argument("--iface", default=None)
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    if args.mode == "build":
        mode_build()
    elif args.mode == "pcap":
        mode_pcap(args.count)
    elif args.mode == "sniff":
        mode_sniff(args.count, args.iface, args.timeout)
    else:
        mode_send(args.count, args.dst)


if __name__ == "__main__":
    main()
