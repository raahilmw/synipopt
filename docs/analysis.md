# CVE-2026-98432, and the packet that fooled its own tool

This document explains the vulnerability, the packet this repo builds, and what the original auto-script actually did. Numbers and quotes come from the mainline fix commit and the Red Hat bulletin linked at the bottom.

## The vulnerability

CVE-2026-98432 is a use-after-free in the Linux kernel's IPv4 TCP handshake path, rated CVSS 3.1 9.8 by the Linux CNA and Critical by Red Hat. An unauthenticated remote sender can reach the bug with a TCP connection request that carries IPv4 options. Precise timing is required. No privileges and no user interaction are involved on the target.

The ownership problem, from the fix commit:

> tcp_v4_syn_recv_sock() transfers ownership of ireq->ireq_opt to the child socket (newinet->inet_opt) without copying it. Another cpu can concurrently process a retransmitted SYN for the same request socket, and send a SYNACK from tcp_check_req(). tcp_v4_send_synack() and inet_csk_route_req() read ireq->ireq_opt under rcu_read_lock() only, and ip_build_and_send_pkt() and ip_options_build() then read opt->optlen twice.

Sequence that ends in the UAF:

1. A SYN with IP options lands. The listener stores the parsed options as `ireq->ireq_opt` on the request socket.
2. The kernel completes the handshake and `tcp_v4_syn_recv_sock()` moves the pointer to the child socket. No copy is made. Two sockets now view the same option buffer, and only one of them owns it.
3. A retransmitted SYN for the same request socket is processed on another CPU. `tcp_check_req()` calls `tcp_v4_send_synack()`, which reads `ireq->ireq_opt` under `rcu_read_lock()` and nothing stronger.
4. Meanwhile the child socket is torn down. `inet_sock_destruct()` calls plain `kfree()` on `inet_opt`, and with the pointer freed the SYN-ACK path continues into `ip_options_build()`, which reads `opt->optlen` a second time. That read can hit released memory.

Two kernel commits made this reachable: request sockets are processed without the listener lock (079096f103fa, "tcp/dccp: install syn_recv requests into ehash table"), and a retransmitted SYN can be handled concurrently for the same request socket. A second path exists through request socket migration (`net.ipv4.tcp_migrate_req=1` or a BPF `SK_REUSEPORT_SELECT_OR_MIGRATE` program): `inet_reqsk_clone()` clones a request socket, and clone and original share `ireq_opt` until `reqsk_migrate_reset()` clears the old pointer, so a thread still holding a reference can read freed options.

## The patch

Commit `e3f33b0a1d89d738e2b913dab519226eaf76e15b`, "ipv4: free inet_opt and ireq_opt after an RCU grace period", by Eric Dumazet, merged by Jakub Kicinski on 2026-10-05. Two files, two lines:

    net/ipv4/af_inet.c   inet_sock_destruct():        kfree -> kfree_rcu
    net/ipv4/tcp_ipv4.c  tcp_v4_reqsk_destructor():   kfree -> kfree_rcu

RCU readers already guard the SYN-ACK path, and other paths that replace `inet_opt` (`do_ip_setsockopt()`, `cipso_v4_sock_setattr()`) already used `kfree_rcu()`. The patch makes the two destructors match. The commit message also notes that IPv6 is not affected by the first issue because `tcp_v6_syn_recv_sock()` duplicates the options, while the CALIPSO `ipv6_opt` migration case is handled in a separate patch.

The fix is small because the bug is a deallocation contract violation, not a logic error. The reader was allowed to run under RCU, and the writer deallocated immediately.

## The echo on the wire

Extending IHL is one thing; getting the kernel to keep the option block is another. Linux compiles the SYN's option bytes, and a block made only of NOP padding compiles to nothing, so the SYN-ACK goes back with a 20-byte IP header. An option that carries payload survives and comes back in the reply. Measured against a listening socket on a test container, three probes with the same code path:

| SYN options | SYN-ACK IP header | echoed options | reply |
|---|---|---|---|
| 24 NOP bytes | 20 bytes, IHL 5 | none | SYN-ACK |
| Record Route, 12 bytes | 32 bytes, IHL 8 | 12 bytes | SYN-ACK |
| none | 20 bytes, IHL 5 | none | SYN-ACK |

That table explains why the send-recv loop has to parse `IHL * 4` and why `ip_options_len` is the field to watch in the JSONL. It also says something about the original script: its 24-NOP craft asks for an 11-word header, but by the time the SYN-ACK path reads `ireq->ireq_opt`, the compiled block is empty. The wire path it claimed to exercise would have needed options with payload, like record route or timestamp.

## The mitigation, and what this tool measures

Red Hat's bulletin offers an nftables rule that drops inbound IPv4 TCP packets with IP options:

    table inet cve_2026_98432 {
        chain input {
            type filter hook input priority -310; policy accept;
            ip protocol tcp ip hdrlength > 5 counter drop
        }
    }

`ip hdrlength > 5` means the IPv4 header is longer than five 32-bit words, which happens exactly when IP options are present. TCP options live in the TCP header and are untouched. Red Hat is explicit that this reduces exposure and does not replace patching.

That rule gives a lab measurement a clear signal. Send one SYN with 24 bytes of NOP filler and one plain SYN to the same listening port. If the filtered host answers the plain SYN and ignores the option-carrying one, an hdrlength drop is in the path. `synipopt --compare` automates that pair and prints the reading, including the case where both go unanswered and the case where both are answered.

## The original auto-script, audited

`cve_2026_98432_auto.zip` advertised two stages.

Stage one, auto-dorking: query Shodan with version-range dorks for Linux hosts, save IPs to `targets.txt`. Without an API key it wrote `192.168.56.101`, a VirtualBox host-only address, and continued. With a key it queried Shodan's host search and fed every public IP into stage two. A lab tool has no use for that stage, and a repository that ships it accumulates abuse reports.

Stage two, the exploiter: build a SYN with IHL 11 (44-byte IP header, 24 NOP option bytes), fire it, retransmit with the same 4-tuple and a new sequence number, then read the raw socket and look for a SYN-ACK.

The stimulus is mechanically sensible. The vulnerable path reads `ireq->ireq_opt` when building the SYN-ACK, and a SYN with options is exactly what populates that pointer. The retransmit is the concurrency the fix commit describes. What was broken is the response handling.

### The parser

`parse_synack()` did not parse. It scanned every offset from 20 to the end of the packet for a byte pair that looked like a valid TCP data offset plus SYN and ACK flag bits:

```python
for off in range(20, len(data) - 20):
    doff = (data[off+12] >> 4) * 4
    fl = data[off+13]
    if doff >= 20 and doff <= 60 and (fl & 0x12) == 0x12:
        tcp_off = off
        break
```

Random and repetitive payloads satisfy that test often. The script's own shipped log proves the outcome. Race 0 reports:

| field the old parser printed | value | where the bytes actually are |
|---|---|---|
| `tcp_start_offset` | 55 | inside the 0x01 option filler |
| `reply_sport` | 257 (0x0101) | two NOP bytes at offset 55 |
| `reply_dport` | 257 (0x0101) | two more NOP bytes |
| `tcp_seq` | 16843009 (0x01010101) | four NOP bytes at offsets 59..62 |
| `tcp_ack` | 27017217 (0x019c4001) | one filler byte plus the first TCP bytes |
| `tcp_flags` | 0x56 | byte at offset 68, inside the real TCP sequence field |

The packet itself, 84 bytes, dissects cleanly:

    offset 0..19   outer IPv4 header: 45 00 00 54, proto 6, src=dst=127.0.0.1
    offset 20..63  the crafted 64-byte SYN as payload: starts 0x4b (v4, IHL 11),
                   total_len 64, ends with its own 20-byte TCP header (9c40 -> 01bb)
    offset 64..83  rest of the payload, never looked at by the old code

A correct parse starts at `IHL * 4`. The outer header declares IHL 5, so the TCP header begins at offset 20, and its flags byte is 0x00. No SYN, no ACK. The bytes at offset 20 are another IPv4 header (`0x4b`), which is the part that should have been on the wire.

The outer header is not a loopback artifact. It is the kernel's own header, built because the script never set `IP_HDRINCL`. Without that socket option, a raw socket treats the buffer as payload: Linux prepends an IPv4 header and sends everything else as data. The trace below comes from reproducing the same mistake on a Linux host, with an nftables trace rule and `nft monitor trace`:

    trace id ea2f9f8e ip filter OUTPUT packet: oif "docker0" ... ip length 84
      tcp sport 19200 tcp dport 64 tcp flags == 0x11 tcp window 1

nftables parses the TCP header at offset 20, which is our buffer's start. sport 0x4b00 is 19200 and dport 0x0040 is 64: the version/IHL byte and the total-length field of the crafted header, read as ports. The kernel's real TCP header never existed, so the remote stack saw a segment with nonsense ports (19200 -> 64) and answered it with a reset, if anything. Nothing the script built was ever transmitted as designed.

With `IP_HDRINCL` set, the same code path works. The probe in this repo was run against a listening socket on a lab container and received a SYN-ACK whose echoed options came back as `ip_options_len: 24`, which is the wire behavior the craft is supposed to produce.

Consequences: every `[RACE n] recv` line in the log is the script reading its own payload bytes. The log contains no target response at all, no UAF evidence, and no basis for the "auto-exploiter" label. A SYN-ACK alone would not prove memory corruption either; the tool had no oracle for the race.

### What the original did well

The packet builder was close to usable: correct version/IHL nibble, correct total length, correct pseudo-header checksum over the TCP segment. The capture loop also recorded JSONL with timestamps and raw hex, which is what makes this audit possible today. The rewrite keeps that logging discipline.

## What synipopt changes

- No dorking stage, no Shodan, no target lists. One address per run, guarded to lab ranges by default.
- The parser reads IHL from the version/IHL nibble, then parses the TCP header at `IHL * 4`. No byte scanning.
- Replies are matched by swapped ports and classified as `syn-ack`, `rst`, `other-tcp`, `icmp`, or `other-flow`, so a stray packet cannot masquerade as a handshake.
- Checksums are computed and verified. `parse_ipv4` reports `ip_checksum_ok`, and a mismatched header is visible instead of silently parsed.
- The old log packet is a regression fixture. `tests/test_packet.py::test_original_log_packet_is_not_a_synack` pins the exact offsets and values that fooled the old code.
- `--compare` turns the tool into a mitigation check: one SYN with options, one without, and an honest reading of the pair.
- `--dry-run` and `--analyze-hex` work without root, so the packet logic can be reviewed and tested anywhere.

## Limits

A wire probe cannot prove the UAF. The SYN-ACK echo shows that a host processes IPv4 options in the handshake path, which is the precondition, not the bug. Showing the race needs a kernel built with KASAN or similar instrumentation, a listener that accepts the connection, and retransmit timing inside the window the fix commit describes. Even then, the signal is a kernel splat, not a packet.

Two practical notes. Sending many option-carrying SYNs at a host creates request socket churn, so keep attempt counts small, especially outside your own lab. And a filtered target tells you only that IP options were dropped somewhere between you and the socket, not which rule did it.

## References

- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-98432
- Fix commit: https://git.kernel.org/linus/e3f33b0a1d89d738e2b913dab519226eaf76e15b
- Red Hat bulletin RHSB-2026-016: https://access.redhat.com/security/vulnerabilities/RHSB-2026-016
- BleepingComputer: https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/
- The Hacker News: https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html
