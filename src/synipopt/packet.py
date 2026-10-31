"""IPv4 and TCP packet building and parsing.

The module works on bytes only. No sockets, no privileges, so every function
here can be exercised in unit tests on any machine.
"""

from __future__ import annotations

import ipaddress
import random
import struct
from dataclasses import dataclass
from typing import Optional

IPPROTO_ICMP = 1
IPPROTO_TCP = 6

SYN = 0x02
ACK = 0x10
RST = 0x04

# Ranges reserved for private and test traffic. The CLI refuses targets outside
# these unless the caller passes an explicit override.
LAB_NETS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)


def ones_complement_checksum(data: bytes) -> int:
    """RFC 1071 checksum: pad odd lengths, add 16-bit words, fold, invert."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def looks_like_lab_target(address: str) -> bool:
    """True when the address sits in a range reserved for private or test use."""
    ip = ipaddress.ip_address(address)
    return any(ip.version == net.version and ip in net for net in LAB_NETS)


@dataclass(frozen=True)
class SynSpec:
    """Everything needed to build one SYN segment."""

    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    seq: int
    options: bytes = b""
    ttl: int = 64
    ip_id: Optional[int] = None

    def __post_init__(self) -> None:
        for name in ("src_ip", "dst_ip"):
            if ipaddress.ip_address(getattr(self, name)).version != 4:
                raise ValueError(f"{name} must be an IPv4 address")
        if not (1 <= self.sport <= 65535 and 1 <= self.dport <= 65535):
            raise ValueError("ports must be in 1..65535")
        if not 0 <= self.seq <= 0xFFFFFFFF:
            raise ValueError("seq must fit in 32 bits")
        if not 0 <= self.ttl <= 255:
            raise ValueError("ttl must be in 0..255")
        if len(self.options) % 4:
            raise ValueError("IP options must be a multiple of 4 bytes (IHL granularity)")
        if len(self.options) > 40:
            raise ValueError("IP options max out at 40 bytes (60-byte header limit)")


def build_syn(spec: SynSpec) -> bytes:
    """Return a complete IPv4 packet holding a single SYN segment."""
    src = ipaddress.ip_address(spec.src_ip).packed
    dst = ipaddress.ip_address(spec.dst_ip).packed
    header_len = 20 + len(spec.options)
    ihl = header_len // 4
    total_len = header_len + 20
    ip_id = random.randrange(0x10000) if spec.ip_id is None else spec.ip_id

    fields = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | ihl,
        0,                    # TOS
        total_len,
        ip_id,
        0x4000,               # DF
        spec.ttl,
        IPPROTO_TCP,
        0,                    # checksum placeholder
        src,
        dst,
    ) + spec.options
    checksum = ones_complement_checksum(fields)
    ip_header = fields[:10] + struct.pack("!H", checksum) + fields[12:]

    offset_flags = 5 << 4  # data offset 5 words, no reserved bits
    segment = struct.pack(
        "!HHLLBBHHH",
        spec.sport,
        spec.dport,
        spec.seq,
        0,
        offset_flags,
        SYN,
        65535,
        0,
        0,
    )
    pseudo = src + dst + struct.pack("!BBH", 0, IPPROTO_TCP, len(segment))
    tcp_checksum = ones_complement_checksum(pseudo + segment)
    segment = struct.pack(
        "!HHLLBBHHH",
        spec.sport,
        spec.dport,
        spec.seq,
        0,
        offset_flags,
        SYN,
        65535,
        tcp_checksum,
        0,
    )

    return ip_header + segment


@dataclass
class TcpSegment:
    sport: int
    dport: int
    seq: int
    ack: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    payload: bytes

    @property
    def syn(self) -> bool:
        return bool(self.flags & SYN)

    @property
    def ack_flag(self) -> bool:
        return bool(self.flags & ACK)

    @property
    def rst(self) -> bool:
        return bool(self.flags & RST)


@dataclass
class PacketView:
    version: int
    header_len: int
    total_len: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str
    ip_options: bytes
    header_checksum_ok: bool
    tcp: Optional[TcpSegment]
    tcp_error: Optional[str]


def parse_ipv4(data: bytes) -> PacketView:
    """Parse an IPv4 datagram. TCP fields are filled when the protocol is TCP."""
    if len(data) < 20:
        raise ValueError(f"runt datagram: {len(data)} bytes")
    version = data[0] >> 4
    if version != 4:
        raise ValueError(f"not IPv4 (version nibble {version})")
    ihl_words = data[0] & 0x0F
    if ihl_words < 5:
        raise ValueError(f"IHL of {ihl_words} words is below the 5-word minimum")
    header_len = ihl_words * 4
    if len(data) < header_len:
        raise ValueError("datagram truncated inside the IP header")

    total_len = struct.unpack("!H", data[2:4])[0]
    ttl = data[8]
    protocol = data[9]
    src_ip = str(ipaddress.ip_address(data[12:16]))
    dst_ip = str(ipaddress.ip_address(data[16:20]))

    stored_checksum = struct.unpack("!H", data[10:12])[0]
    blanked = data[:10] + b"\x00\x00" + data[12:header_len]
    header_checksum_ok = ones_complement_checksum(blanked) == stored_checksum

    tcp: Optional[TcpSegment] = None
    tcp_error: Optional[str] = None
    if protocol == IPPROTO_TCP:
        segment = data[header_len:total_len] if total_len >= header_len else data[header_len:]
        try:
            tcp = _parse_tcp(segment)
        except ValueError as exc:
            tcp_error = str(exc)

    return PacketView(
        version=version,
        header_len=header_len,
        total_len=total_len,
        ttl=ttl,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_options=data[20:header_len],
        header_checksum_ok=header_checksum_ok,
        tcp=tcp,
        tcp_error=tcp_error,
    )


def _parse_tcp(segment: bytes) -> TcpSegment:
    if len(segment) < 20:
        raise ValueError(f"TCP header truncated ({len(segment)} bytes)")
    sport, dport, seq, ack, offset_byte, flags, window, checksum, _urg = struct.unpack(
        "!HHLLBBHHH", segment[:20]
    )
    data_offset = (offset_byte >> 4) * 4
    if data_offset < 20:
        raise ValueError(f"invalid TCP data offset ({data_offset} bytes)")
    if len(segment) < data_offset:
        raise ValueError("segment truncated inside TCP options")
    return TcpSegment(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        data_offset=data_offset,
        flags=flags,
        window=window,
        checksum=checksum,
        payload=segment[data_offset:],
    )


def hexdump(data: bytes) -> str:
    """Offset, hex bytes, ASCII, in the usual 16-byte rows."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:04x}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)
