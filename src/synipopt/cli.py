"""Command line interface for synipopt."""

from __future__ import annotations

import argparse
import random
import sys

from . import __version__
from .packet import (
    SynSpec,
    build_syn,
    hexdump,
    looks_like_lab_target,
    parse_ipv4,
)
from .probe import detect_source_ip, probe, summarize

DEFAULT_OPTIONS_HEX = "01" * 24  # 24 NOP bytes, raises IHL to 11


def _parse_hex_blob(value: str) -> bytes:
    cleaned = "".join(value.split()).replace(":", "")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SystemExit(f"invalid hex: {exc}")


def _print_view(view) -> None:
    indent = "  "
    print(
        f"{indent}IPv{view.version} {view.src_ip} -> {view.dst_ip} "
        f"proto={view.protocol} ttl={view.ttl}"
    )
    print(
        f"{indent}header {view.header_len} bytes, total_len {view.total_len}, "
        f"ip checksum ok={view.header_checksum_ok}"
    )
    print(f"{indent}ip options {len(view.ip_options)} bytes: {view.ip_options.hex() or '(none)'}")
    if view.tcp is not None:
        tcp = view.tcp
        print(
            f"{indent}tcp {tcp.sport} -> {tcp.dport} flags=0x{tcp.flags:02x} "
            f"seq={tcp.seq} ack={tcp.ack} data_offset={tcp.data_offset} "
            f"payload={len(tcp.payload)}B"
        )
    elif view.tcp_error:
        print(f"{indent}tcp: {view.tcp_error}")


def _summary_line(results, label: str) -> None:
    stats = summarize(results)
    kinds = ", ".join(f"{kind}={count}" for kind, count in sorted(stats["kinds"].items()))
    print(f"  {label}: {stats['attempts']} attempts, {kinds or 'no replies'}")


def _verdict(with_options, baseline) -> None:
    opt_kinds = summarize(with_options)["kinds"]
    base_kinds = summarize(baseline)["kinds"]
    answered = lambda kinds: sum(count for kind, count in kinds.items() if kind != "timeout")
    opt_answered = answered(opt_kinds)
    base_answered = answered(base_kinds)
    if opt_answered == 0 and base_answered > 0:
        print("  reading: option-carrying SYNs went unanswered while plain SYNs were")
        print("  answered. That is consistent with an ip hdrlength filter, the")
        print("  RHSB-2026-016 mitigation, or any other rule that drops IP options.")
    elif opt_answered > 0:
        print("  reading: at least one option-carrying SYN was answered, so no")
        print("  hdrlength filter is visible on this path.")
    else:
        print("  reading: neither packet got an answer. Check the route, the")
        print("  listener, and whether the source address reaches the target.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="synipopt",
        description="Single-target IPv4 SYN probe with IP options (CVE-2026-98432 research).",
    )
    ap.add_argument("--version", action="version", version=f"synipopt {__version__}")
    ap.add_argument("--target", help="single IPv4 address to probe")
    ap.add_argument("--src-ip", help="source address for crafted packets (default: kernel choice)")
    ap.add_argument("--sport", type=int, help="source port (default: random)")
    ap.add_argument("--dport", type=int, default=443, help="destination port (default 443)")
    ap.add_argument(
        "--options-hex",
        default=DEFAULT_OPTIONS_HEX,
        help="IP option bytes, multiple of 4 up to 40 (default 24 NOP bytes)",
    )
    ap.add_argument("--retries", type=int, default=3, help="SYNs per run (default 3)")
    ap.add_argument("--timeout", type=float, default=1.0, help="seconds waited per SYN")
    ap.add_argument("--log", help="append results to this JSONL file")
    ap.add_argument(
        "--compare",
        action="store_true",
        help="also fire a baseline SYN without IP options and compare answers",
    )
    ap.add_argument(
        "--allow-public",
        action="store_true",
        help="permit targets outside lab ranges (authorized testing only)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="build the packet, print it, parse it back, send nothing",
    )
    ap.add_argument("--analyze-hex", metavar="HEX", help="parse a captured packet from hex")

    args = ap.parse_args(argv)

    if args.analyze_hex is not None:
        data = _parse_hex_blob(args.analyze_hex)
        print(hexdump(data))
        print()
        try:
            view = parse_ipv4(data)
        except ValueError as exc:
            print(f"parse error: {exc}")
            return 1
        _print_view(view)
        tcp = view.tcp
        is_synack = bool(tcp is not None and tcp.syn and tcp.ack_flag)
        print(f"  classified: {'SYN-ACK' if is_synack else 'not a SYN-ACK'}")
        return 0

    if not args.target:
        ap.error("--target is required unless --analyze-hex is used")

    options = _parse_hex_blob(args.options_hex)
    if len(options) % 4 or len(options) > 40:
        ap.error("--options-hex must decode to a multiple of 4 bytes, at most 40")
    sport = args.sport or random.randrange(20000, 61000)
    if sport == args.dport:
        ap.error("source and destination ports must differ")

    if args.dry_run:
        spec = SynSpec(
            src_ip=args.src_ip or "192.0.2.10",
            dst_ip=args.target,
            sport=sport,
            dport=args.dport,
            seq=0x12349678,
            options=options,
            ttl=64,
            ip_id=0x1234,
        )
        packet = build_syn(spec)
        print(f"dry run: {len(packet)} bytes, IHL {(packet[0] & 0x0F) * 4}")
        print(hexdump(packet))
        print()
        _print_view(parse_ipv4(packet))
        print("  nothing was sent")
        return 0

    if not looks_like_lab_target(args.target) and not args.allow_public:
        print(
            f"refusing {args.target}: not a lab address.\n"
            "synipopt probes one host per run and assumes you control it.\n"
            "For an authorized external test, pass --allow-public. See README Safety.",
            file=sys.stderr,
        )
        return 2

    src_ip = args.src_ip or detect_source_ip(args.target)
    print(
        f"target {args.target}:{args.dport} from {src_ip}, "
        f"{args.retries} SYN(s), options {len(options)}B"
    )

    total = 0
    try:
        results = probe(
            args.target,
            src_ip,
            sport,
            args.dport,
            options,
            retries=args.retries,
            timeout=args.timeout,
            log_path=args.log,
        )
        total += len(results)
        _summary_line(results, "options SYN ")
        if args.compare:
            baseline_sport = sport + 1 if sport + 1 != args.dport else sport + 2
            baseline = probe(
                args.target,
                src_ip,
                baseline_sport,
                args.dport,
                b"",
                retries=args.retries,
                timeout=args.timeout,
                log_path=args.log,
            )
            total += len(baseline)
            _summary_line(baseline, "baseline SYN")
            _verdict(results, baseline)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {total} records" + (f" to {args.log}" if args.log else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
