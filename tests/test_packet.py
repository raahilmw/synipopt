import struct

import pytest

from synipopt.packet import (
    ACK,
    SYN,
    SynSpec,
    build_syn,
    looks_like_lab_target,
    ones_complement_checksum,
    parse_ipv4,
)

# Packet logged by the original auto-script (exploit_log.jsonl, race 0) and
# reported by it as a SYN-ACK. 84 bytes: a kernel-built 20-byte IPv4 header
# wrapping the script's own 64-byte "crafted SYN". The script never set
# IP_HDRINCL, so its packet went out as TCP payload instead of on the wire.
ORIGINAL_LOG_HEX = (
    "45000054ad8640007f06501b7f0000017f000001"
    "4b0000402f75000040063b357f0000017f000001"
    "010101010101010101010101010101010101010101010101"
    "9c4001bb562dd54b000000005002ffffe86b0000"
)


def _spec(**overrides):
    fields = dict(
        src_ip="192.0.2.10",
        dst_ip="192.0.2.20",
        sport=40000,
        dport=443,
        seq=0x11223344,
        options=b"\x01" * 24,
        ttl=64,
        ip_id=0x1234,
    )
    fields.update(overrides)
    return SynSpec(**fields)


def test_build_syn_sets_ihl_and_lengths():
    packet = build_syn(_spec())
    assert len(packet) == 64
    assert packet[0] == 0x4B  # version 4, IHL 11 words
    assert struct.unpack("!H", packet[2:4])[0] == 64


def test_checksum_fields_verify_to_zero():
    packet = build_syn(_spec())
    assert ones_complement_checksum(packet[:44]) == 0
    pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, 20)
    assert ones_complement_checksum(pseudo + packet[44:]) == 0


def test_roundtrip_parses_what_it_built():
    packet = build_syn(_spec())
    view = parse_ipv4(packet)
    assert view.header_len == 44
    assert view.total_len == 64
    assert view.ip_options == b"\x01" * 24
    assert view.header_checksum_ok is True
    assert view.src_ip == "192.0.2.10"
    assert view.dst_ip == "192.0.2.20"
    tcp = view.tcp
    assert tcp is not None
    assert (tcp.sport, tcp.dport) == (40000, 443)
    assert tcp.seq == 0x11223344
    assert tcp.flags == SYN
    assert tcp.data_offset == 20


def test_option_size_limits():
    _spec(options=b"\x01" * 40)  # 60-byte IP header, the maximum
    with pytest.raises(ValueError):
        _spec(options=b"\x01" * 3)
    with pytest.raises(ValueError):
        _spec(options=b"\x01" * 44)


def test_lab_target_ranges():
    assert looks_like_lab_target("127.0.0.1")
    assert looks_like_lab_target("192.168.56.101")
    assert looks_like_lab_target("10.66.0.5")
    assert looks_like_lab_target("192.0.2.10")
    assert not looks_like_lab_target("8.8.8.8")
    assert not looks_like_lab_target("93.184.216.34")


def test_original_log_packet_is_not_a_synack():
    data = bytes.fromhex(ORIGINAL_LOG_HEX)
    assert len(data) == 84
    view = parse_ipv4(data)
    assert view.header_len == 20
    assert view.total_len == 84
    assert view.ip_options == b""
    tcp = view.tcp
    assert tcp is not None
    assert tcp.flags == 0x00
    assert not (tcp.flags & SYN)
    assert not (tcp.flags & ACK)
    # A second IPv4 header sits at offset 20: the crafted SYN (0x4b = v4, IHL 11)
    assert data[20] == 0x4B
    # The old parser's "sport 257" came from the NOP filler at offset 55
    assert data[55:57] == b"\x01\x01"
    assert struct.unpack("!H", data[55:57])[0] == 257
    # And its "seq 16843009" was four filler bytes
    assert struct.unpack("!L", data[59:63])[0] == 16843009


def test_hexdump_layout():
    from synipopt.packet import hexdump

    packet = build_syn(_spec())
    text = hexdump(packet)
    assert text.splitlines()[0].startswith("0000  ")
    assert len(text.splitlines()) == 4  # 64 bytes in four 16-byte rows

