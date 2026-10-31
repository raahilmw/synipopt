import socket
import struct
import subprocess
import sys

from synipopt.packet import ACK, RST, SYN, ones_complement_checksum, parse_ipv4
from synipopt.probe import classify, summarize


def _tcp_packet(src, dst, sport, dport, flags, seq=0, ack=0):
    """Build one IPv4 + TCP packet straight from struct, independent of the
    module under test."""
    segment = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(segment))
    tcp_checksum = ones_complement_checksum(pseudo + segment)
    segment = struct.pack(
        "!HHLLBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, tcp_checksum, 0
    )
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 7, 0, 64, 6, 0, src_b, dst_b)
    checksum = ones_complement_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + segment


def test_classify_synack():
    packet = _tcp_packet("192.0.2.20", "192.0.2.10", 443, 40000, SYN | ACK)
    assert classify(parse_ipv4(packet), 40000, 443) == "syn-ack"


def test_classify_rst():
    packet = _tcp_packet("192.0.2.20", "192.0.2.10", 443, 40000, RST | ACK)
    assert classify(parse_ipv4(packet), 40000, 443) == "rst"


def test_classify_skips_other_flows():
    packet = _tcp_packet("192.0.2.20", "192.0.2.10", 22, 40000, SYN | ACK)
    assert classify(parse_ipv4(packet), 40000, 443) == "other-flow"


def test_classify_icmp():
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 28, 1, 0, 64, 1, 0,
        socket.inet_aton("192.0.2.20"), socket.inet_aton("192.0.2.10"),
    )
    packet = header + b"\x03\x03\x00\x00\x00\x00\x00\x00"
    assert classify(parse_ipv4(packet), 40000, 443) == "icmp"


def test_summarize_counts():
    from synipopt.probe import AttemptResult

    results = [
        AttemptResult(0, 1, 40000, 443, "reply", "rst", {}),
        AttemptResult(1, 2, 40000, 443, "reply", "rst", {}),
        AttemptResult(2, 3, 40000, 443, "timeout"),
    ]
    assert summarize(results) == {"attempts": 3, "kinds": {"rst": 2, "timeout": 1}}


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "synipopt", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_dry_run_needs_no_privileges():
    result = _run_cli("--dry-run", "--target", "192.0.2.10")
    assert result.returncode == 0, result.stderr
    assert "dry run: 64 bytes" in result.stdout
    assert "nothing was sent" in result.stdout


def test_cli_refuses_public_target_without_flag():
    result = _run_cli("--target", "8.8.8.8", "--retries", "1")
    assert result.returncode == 2
    assert "refusing" in result.stderr


def test_cli_analyze_hex_flags_rst_as_not_synack():
    packet = _tcp_packet("192.0.2.20", "192.0.2.10", 443, 40000, RST | ACK)
    result = _run_cli("--analyze-hex", packet.hex())
    assert result.returncode == 0, result.stderr
    assert "classified: not a SYN-ACK" in result.stdout


def test_cli_analyze_hex_flags_synack():
    packet = _tcp_packet("192.0.2.20", "192.0.2.10", 443, 40000, SYN | ACK)
    result = _run_cli("--analyze-hex", packet.hex())
    assert result.returncode == 0, result.stderr
    assert "classified: SYN-ACK" in result.stdout

