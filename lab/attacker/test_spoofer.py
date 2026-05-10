"""Unit tests for spoofer packet construction.

Run from lab/attacker/ with:
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt pytest
    pytest test_spoofer.py -v
"""
from scapy.all import IP, UDP, DNS

import spoofer


def test_build_spoofed_response_has_correct_5tuple():
    pkt = spoofer.build_spoofed_response(
        src_ip="192.168.56.99",
        dst_ip="192.168.56.20",
        dst_port=33333,
        txid=0x4242,
        qname="www.target.lab",
        spoof_ip="192.168.56.10",
    )
    assert pkt[IP].src == "192.168.56.99"
    assert pkt[IP].dst == "192.168.56.20"
    assert pkt[UDP].sport == 53
    assert pkt[UDP].dport == 33333
    assert pkt[DNS].id == 0x4242
    assert pkt[DNS].qr == 1
    assert pkt[DNS].aa == 1
    assert pkt[DNS].qd.qname == b"www.target.lab."
    assert pkt[DNS].an.rdata == "192.168.56.10"
    assert pkt[DNS].an.ttl == 86400


def test_build_trigger_query_targets_resolver():
    pkt = spoofer.build_trigger_query(
        resolver_ip="192.168.56.20",
        qname="www.target.lab",
    )
    assert pkt[IP].dst == "192.168.56.20"
    assert pkt[UDP].dport == 53
    assert pkt[DNS].qr == 0
    assert pkt[DNS].qd.qname == b"www.target.lab."
