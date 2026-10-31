# synipopt

A single-target probe for CVE-2026-98432, the Linux kernel IPv4 TCP use-after-free patched in October 2026.

It builds an IPv4 SYN that carries IP options (24 NOP bytes by default, which raises IHL to 11), sends it to one host, and reads the answer by header offset instead of pattern matching. The packet logic also runs offline: a dry run prints and re-parses the crafted packet, the hex analyzer parses captured traffic, and the test suite needs neither root nor a network.

## What this is not

There is no target list handling, no Shodan integration, and no batch mode. One address per run, and the CLI refuses anything outside lab ranges unless you pass `--allow-public`. The tool assumes you own the target or have written permission to test it.

## Install

    python3 -m pip install -e ".[test]"

Python 3.9 or newer. Standard library only.

## Quick start

Dry run, no privileges, no packet sent:

    synipopt --dry-run --target 192.0.2.10

Parse the packet from the original script's log, the one it reported as a SYN-ACK:

    synipopt --analyze-hex "$(cat docs/fixtures/original-log-packet.hex)"

Probe a lab VM and compare option-carrying SYNs against plain SYNs:

    sudo synipopt --target 192.168.56.101 --dport 443 --retries 3 --compare --log probe.jsonl

## The packet

Default craft, 64 bytes on the wire:

- IP header: 44 bytes (IHL 11), 24 bytes of `0x01` NOP filler
- TCP header: 20 bytes, SYN flag, checksum over the IPv4 pseudo header
- Total length field: 64

A SYN carrying options is what puts `ireq->ireq_opt` on the request socket. The kernel compiles the option block, and pure NOP filler compiles down to an empty block, so a SYN-ACK to the default craft comes back without IP options. Options that carry payload, record route for example, are echoed. Measured during development against a listening socket:

| SYN options | SYN-ACK IP header | echoed options |
|---|---|---|
| 24 NOP bytes | 20 bytes (IHL 5) | none |
| Record Route, 12 bytes | 32 bytes (IHL 8) | 12 bytes |
| none | 20 bytes (IHL 5) | none |

Both facts matter for lab work: the reply's header length tells you whether the stack kept the option block, and a correct parser starts the TCP header at `IHL * 4`, not at offset 20.

## What the original script got wrong

The circulating script behind this repo (`cve_2026_98432_auto.zip`) shipped its own run log. Every "successful" SYN-ACK in that log has `reply_sport=257` and `tcp_seq=16843009`. Those are the NOP filler bytes: 0x0101 is 257 and 0x01010101 is 16843009. The parser scanned for flag bits anywhere in the packet and landed at offset 55, inside the option padding. A correct parse of that 84-byte packet finds IHL 5, protocol TCP, and a TCP segment whose flags byte is 0x00, no SYN and no ACK.

The payload is the script's own crafted SYN (`0x4b` at offset 20). The outer header belongs to the kernel: the script never set `IP_HDRINCL`, so Linux built its own IPv4 header and took the crafted packet as payload. Nothing it built was ever transmitted as a packet. Two failures stacked: the packet never left as designed, and the parser read filler bytes as the reply.

The dork stage was inert without a key. It read `--shodan-key` or `SHODAN_KEY`; with neither, it wrote `192.168.56.101` (a VirtualBox host-only default) to `targets.txt` and carried on. With a key it would query Shodan for public hosts and fire at them, which no lab tool needs and which gets repos removed.

synipopt keeps the single-packet wire idea, removes the targeting stage, replaces the heuristic parser with header-offset parsing, and turns the old log values into a regression test in `tests/test_packet.py`.

## CVE facts

CVE-2026-98432, Linux kernel IPv4 networking, use-after-free, CVSS 3.1 9.8 from the Linux CNA. Red Hat rates it Critical (RHSB-2026-016) and lists RHEL 8, 9, 10, and OpenShift among the affected products.

The race, as described in the fix commit: `tcp_v4_syn_recv_sock()` transfers `ireq->ireq_opt` to the child socket (`newinet->inet_opt`) without copying. Another CPU can process a retransmitted SYN for the same request socket and send a SYN-ACK from `tcp_check_req()`. `tcp_v4_send_synack()` and `inet_csk_route_req()` read `ireq->ireq_opt` under `rcu_read_lock()` only, and `ip_build_and_send_pkt()` and `ip_options_build()` then read `opt->optlen` twice. Because request sockets are processed without the listener lock (commit 079096f103fa), the child can be freed while the SYN-ACK is still being built. Child sockets lack `SOCK_RCU_FREE`, and `inet_sock_destruct()` freed `inet_opt` with a plain `kfree()`, so `ip_options_build()` could read released memory.

The mainline fix is commit `e3f33b0a1d89d738e2b913dab519226eaf76e15b`, "ipv4: free inet_opt and ireq_opt after an RCU grace period" (Eric Dumazet, merged 2026-10-05). It swaps `kfree()` for `kfree_rcu()` in `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()`. The same commit notes a second path through request socket migration (`net.ipv4.tcp_migrate_req=1` or a BPF reuseport program), where `inet_reqsk_clone()` shares `ireq_opt` between the old request socket and its clone.

Red Hat's temporary mitigation drops inbound IPv4 TCP packets that carry IP options:

    table inet cve_2026_98432 {
        chain input {
            type filter hook input priority -310; policy accept;
            ip protocol tcp ip hdrlength > 5 counter drop
        }
    }

`--compare` tests for exactly that filter: option-carrying SYNs go unanswered while plain SYNs get a reply.

Sources:

- https://www.cve.org/CVERecord?id=CVE-2026-98432
- https://git.kernel.org/linus/e3f33b0a1d89d738e2b913dab519226eaf76e15b
- https://access.redhat.com/security/vulnerabilities/RHSB-2026-016
- https://www.bleepingcomputer.com/news/security/critical-linux-kernel-flaw-allows-remote-root-attacks-on-mptcp-servers/
- https://thehackernews.com/2026/10/linux-kernel-tcp-flaw-with-98-cvss.html

## Lab sketch

Wire probes cannot prove memory corruption. What they can show: whether a host answers SYNs that carry IP options, whether the SYN-ACK echoes those options, and whether an hdrlength filter sits in the path.

1. Boot a VM whose kernel predates the vendor fix for CVE-2026-98432. Check `uname -r` against your distribution's advisory.
2. On the VM, watch for option-carrying packets: `tcpdump -ni eth0 'tcp and (ip[0] & 0x0f) > 5'`
3. From the lab host: `sudo synipopt --target VM_IP --dport 22 --retries 5 --compare --log run.jsonl`
4. Read the JSONL: `reply_kind` classifies the answer and the `tcp` block carries the parsed header. `ip_options_len` shows the echo, which appears for option blocks with payload (record route, timestamp); pure NOP filler compiles away and comes back as a 20-byte header.
5. For memory-safety signals, build the test kernel with KASAN and watch `dmesg`. The wire only shows packet handling.

## Safety

Test hosts you own or are authorized to test. The default guard refuses addresses outside RFC 1918, loopback, link-local, CGNAT, and the documentation ranges. `--allow-public` exists for authorized engagements on hosts you control. Firing crafted SYNs at third parties is not what this tool is for.

## Tests

    python3 -m pytest -q

The suite covers checksum properties, build and parse roundtrips, option length limits, reply classification (SYN-ACK, RST, ICMP, wrong flow), the CLI guard and dry run, and the original log packet as a regression fixture. CI runs Python 3.10 and 3.12.

## Provenance

Derived from a circulating auto-exploiter script that combined Shodan dorking with a raw SYN race probe. This rewrite keeps the wire-level idea, removes the mass-targeting stage, and replaces the heuristic parser with header-offset parsing. The original run log values are preserved as a test fixture.

Docs follow the antislop and humanizer writing rules.

## License

MIT, see LICENSE.
