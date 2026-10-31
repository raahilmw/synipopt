"""Raw socket send and receive for the crafted SYN.

Needs CAP_NET_RAW or root because the tool writes its own IPv4 header.
"""

from __future__ import annotations

import json
import random
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .packet import IPPROTO_ICMP, IPPROTO_TCP, PacketView, SynSpec, build_syn, parse_ipv4


@dataclass
class AttemptResult:
    attempt: int
    seq_sent: int
    sport: int
    dport: int
    status: str
    reply_kind: Optional[str] = None
    reply: Optional[dict] = None

    def as_log_record(self, target: str, src_ip: str) -> dict:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "src": src_ip,
            "sport": self.sport,
            "dport": self.dport,
            "attempt": self.attempt,
            "seq_sent": self.seq_sent,
            "status": self.status,
            "reply_kind": self.reply_kind,
        }
        if self.reply is not None:
            record["reply"] = self.reply
        return record


def classify(view: PacketView, expected_sport: int, expected_dport: int) -> str:
    """Name what the raw socket received, from the parsed header fields."""
    if view.protocol != IPPROTO_TCP or view.tcp is None:
        if view.protocol == IPPROTO_ICMP:
            return "icmp"
        return f"proto-{view.protocol}"
    tcp = view.tcp
    if tcp.sport != expected_dport or tcp.dport != expected_sport:
        return "other-flow"
    if tcp.syn and tcp.ack_flag:
        return "syn-ack"
    if tcp.rst:
        return "rst"
    return "other-tcp"


def view_to_dict(view: PacketView) -> dict:
    tcp = view.tcp
    payload = {
        "src_ip": view.src_ip,
        "dst_ip": view.dst_ip,
        "ip_header_len": view.header_len,
        "ip_options_len": len(view.ip_options),
        "ip_options_hex": view.ip_options.hex(),
        "ip_checksum_ok": view.header_checksum_ok,
        "ttl": view.ttl,
        "tcp": None,
        "tcp_error": view.tcp_error,
    }
    if tcp is not None:
        payload["tcp"] = {
            "sport": tcp.sport,
            "dport": tcp.dport,
            "flags": f"0x{tcp.flags:02x}",
            "seq": tcp.seq,
            "ack": tcp.ack,
            "data_offset": tcp.data_offset,
            "window": tcp.window,
            "payload_len": len(tcp.payload),
        }
    return payload


def probe(
    target: str,
    src_ip: str,
    sport: int,
    dport: int,
    options: bytes,
    retries: int = 3,
    timeout: float = 1.0,
    log_path: Optional[str] = None,
    ip_id: Optional[int] = None,
) -> list[AttemptResult]:
    """Fire `retries` SYNs and record the first matching answer per attempt.

    Each attempt reuses the same 4-tuple with a new sequence number. That is
    the retransmit shape described in CVE-2026-98432's fix commit.
    """
    results: list[AttemptResult] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, IPPROTO_TCP)
    except PermissionError as exc:
        raise RuntimeError(
            "raw sockets need CAP_NET_RAW or root; run under sudo or grant the capability"
        ) from exc
    # Without IP_HDRINCL the kernel builds its own IPv4 header and treats the
    # crafted packet as TCP payload. That mistake is exactly what the original
    # script made: its "SYN" went out as 84 bytes of payload with the real
    # header fields read from the wrong offsets.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.settimeout(timeout)
    try:
        for attempt in range(retries):
            seq = random.randrange(0x100000000)
            spec = SynSpec(
                src_ip=src_ip,
                dst_ip=target,
                sport=sport,
                dport=dport,
                seq=seq,
                options=options,
                ip_id=ip_id,
            )
            sock.sendto(build_syn(spec), (target, 0))

            result = AttemptResult(
                attempt=attempt,
                seq_sent=seq,
                sport=sport,
                dport=dport,
                status="timeout",
            )
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, peer = sock.recvfrom(65535)
                except socket.timeout:
                    break
                try:
                    view = parse_ipv4(data)
                except ValueError:
                    continue
                if view.src_ip != target:
                    continue
                kind = classify(view, sport, dport)
                if kind == "other-flow":
                    continue
                result.status = "reply"
                result.reply_kind = kind
                result.reply = view_to_dict(view)
                result.reply["peer"] = peer[0]
                break

            results.append(result)
            if log_path:
                with open(log_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(result.as_log_record(target, src_ip)) + "\n")
            time.sleep(random.uniform(0.05, 0.15))
    finally:
        sock.close()
    return results


def summarize(results: list[AttemptResult]) -> dict:
    kinds: dict[str, int] = {}
    for result in results:
        key = result.reply_kind if result.status == "reply" else "timeout"
        kinds[key] = kinds.get(key, 0) + 1
    return {"attempts": len(results), "kinds": kinds}


def detect_source_ip(target: str) -> str:
    """Pick the local address the kernel would use to reach `target`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target, 9))
        return sock.getsockname()[0]
    finally:
        sock.close()
