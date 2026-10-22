"""IPv4 handling SP needs [SP-01 5, 6.3, 9]: parsing, flow keys, ICMP
"destination unreachable", fragmentation [RFC791] and ECN [RFC6040]."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
TCP_FIN, TCP_RST = 0x01, 0x04
NOT_ECT, ECT1, ECT0, CE = 0, 1, 2, 3


class PacketError(ValueError):
    """Not a well-formed IPv4 datagram."""


@dataclass(frozen=True, slots=True)
class IPv4:
    """The fields SP reads of an inner packet."""

    raw: bytes
    header_length: int
    tos: int
    total_length: int
    identification: int
    flags_fragment: int
    ttl: int
    protocol: int
    source: str
    destination: str

    @property
    def ecn(self) -> int:
        return self.tos & 0x03

    @property
    def dscp(self) -> int:
        return self.tos >> 2

    @property
    def dont_fragment(self) -> bool:
        return bool(self.flags_fragment & 0x4000)

    @property
    def more_fragments(self) -> bool:
        return bool(self.flags_fragment & 0x2000)

    @property
    def fragment_offset(self) -> int:
        return self.flags_fragment & 0x1FFF

    @property
    def payload(self) -> bytes:
        return self.raw[self.header_length:self.total_length]

    def ports(self) -> tuple[int, int]:
        """TCP/UDP ports of a first fragment, (0, 0) otherwise [6.3]."""
        if self.protocol in (PROTO_TCP, PROTO_UDP) and self.fragment_offset == 0:
            payload = self.payload
            if len(payload) >= 4:
                return struct.unpack_from("!HH", payload)
        return 0, 0

    def tcp_flags(self) -> int:
        if self.protocol == PROTO_TCP and self.fragment_offset == 0 and len(self.payload) >= 14:
            return self.payload[13]
        return 0

    def flow(self) -> tuple[int, str, int, str, int]:
        """(protocol, source, source port, destination, destination port)."""
        sport, dport = self.ports()
        return self.protocol, self.source, sport, self.destination, dport


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def parse(raw: bytes) -> IPv4:
    """A well-formed IPv4 datagram, or PacketError [5.2]."""
    if len(raw) < 20:
        raise PacketError("shorter than an IPv4 header")
    version_ihl, tos, total, ident, flags, ttl, proto, _csum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s", raw[:20]
    )
    if version_ihl >> 4 != 4:
        raise PacketError("not IPv4")
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or total < ihl or total > len(raw):
        raise PacketError("inconsistent lengths")
    if checksum(raw[:ihl]) != 0:
        raise PacketError("bad header checksum")
    return IPv4(raw[:total], ihl, tos, total, ident, flags, ttl, proto,
                str(ipaddress.IPv4Address(src)), str(ipaddress.IPv4Address(dst)))


def build(  # pylint: disable=too-many-arguments
    source: str, destination: str, protocol: int, payload: bytes, *,
    ttl: int = 64, tos: int = 0, identification: int = 0, flags_fragment: int = 0,
    options: bytes = b"",
) -> bytes:
    """An IPv4 datagram with a correct checksum."""
    ihl = 20 + len(options)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x40 | ihl // 4, tos, ihl + len(payload), identification,
        flags_fragment, ttl, protocol, 0,
        ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed,
    ) + options
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def icmp_unreachable(original: IPv4, code: int, *, source: str, mtu: int = 0) -> bytes:
    """ICMP type 3 to the source of *original* [RFC792, RFC1191].

    Code 1 (host unreachable, [SP 5.2]) or 4 (fragmentation needed, with the
    next-hop MTU, [SP 9.1]). Carries the original header and 8 bytes.
    """
    quoted = original.raw[:original.header_length + 8]
    body = struct.pack("!BBHHH", 3, code, 0, 0, mtu if code == 4 else 0) + quoted
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return build(source, original.source, PROTO_ICMP, body)


def fragment(packet: IPv4, mtu: int) -> list[bytes]:
    """Split *packet* to fit *mtu* [RFC791]; DF must have been checked."""
    if packet.total_length <= mtu:
        return [packet.raw]
    header = packet.raw[:packet.header_length]
    options = header[20:]
    data = packet.payload
    chunk = (mtu - packet.header_length) // 8 * 8
    if chunk <= 0:
        raise PacketError("MTU smaller than the header")
    out = []
    for start in range(0, len(data), chunk):
        piece = data[start:start + chunk]
        last = start + chunk >= len(data)
        more = 0 if last and not packet.more_fragments else 0x2000
        offset = packet.fragment_offset + start // 8
        out.append(build(
            packet.source, packet.destination, packet.protocol, piece, ttl=packet.ttl,
            tos=packet.tos, identification=packet.identification,
            flags_fragment=more | offset, options=options if start == 0 else b"",
        ))
    return out


def with_ecn(raw: bytes, ecn: int) -> bytes:
    """*raw* with its ECN field replaced and the checksum fixed."""
    packet = parse(raw)
    tos = (packet.tos & ~0x03) | ecn
    header = bytearray(raw[:packet.header_length])
    header[1] = tos
    header[10:12] = b"\x00\x00"
    header[10:12] = struct.pack("!H", checksum(bytes(header)))
    return bytes(header) + raw[packet.header_length:]


def decapsulate_ecn(inner: bytes, outer_ecn: int) -> bytes | None:
    """[RFC6040] normal mode, [SP 9.2]: None when the packet must be dropped."""
    packet = parse(inner)
    if outer_ecn == CE:
        if packet.ecn == NOT_ECT:
            return None
        if packet.ecn in (ECT0, ECT1):
            return with_ecn(inner, CE)
    return inner
