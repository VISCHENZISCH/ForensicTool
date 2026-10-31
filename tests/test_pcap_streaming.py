"""PCAP : lecture en flux équivalente à la lecture en mémoire, DNS forgé sans blocage."""

from __future__ import annotations

import time

import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402


def _capture(path, extra=()):
    packets = [
        Ether()
        / IP(src="8.8.8.8", dst="10.0.0.5")
        / UDP(sport=53, dport=33333)
        / DNS(qr=1, qd=DNSQR(qname="g00gle-update.com"), an=[DNSRR(rrname="g00gle-update.com", rdata="203.0.113.9")]),
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(sport=40000, dport=80, flags="S", seq=1),
        Ether()
        / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=40000, dport=80, flags="PA", seq=2)
        / Raw(
            b"POST /login HTTP/1.1\r\nHost: g00gle-update.com\r\nUser-Agent: curl/8.0\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 27\r\n\r\nusername=admin&password=x1"
        ),
        *extra,
    ]
    for n, p in enumerate(packets):
        p.time = 1_700_000_000 + n
    wrpcap(str(path), packets)
    return str(path)


def test_streamed_analysis_matches_in_memory(tmp_path, monkeypatch):
    from forensic_analyzer.analyzers.pcap import analyzer as pcap

    path = _capture(tmp_path / "c.pcap")
    in_memory = pcap.PCAPAnalyzer().analyze(path)
    monkeypatch.setattr(pcap, "IN_MEMORY_BYTES", 0)
    streamed = pcap.PCAPAnalyzer().analyze(path)
    assert "Lecture" in streamed.metadata and "Lecture" not in in_memory.metadata
    assert {k: v for k, v in streamed.metadata.items() if k != "Lecture"} == in_memory.metadata
    assert str(streamed.extra) == str(in_memory.extra)


def test_forged_dns_answer_count_does_not_stall(tmp_path):
    from scapy.all import rdpcap

    from forensic_analyzer.analyzers.pcap.dns_mapping import extract_dns_mappings

    forged = (
        Ether()
        / IP(src="8.8.8.8", dst="10.0.0.5")
        / UDP(sport=53, dport=1)
        / Raw(b"\x12\x34\x81\x80\x00\x01\xff\xff\x00\x00\x00\x00" + b"\x01a\x00\x00\x01\x00\x01")
    )  # ancount = 65535
    path = _capture(tmp_path / "f.pcap", [forged] * 200)
    packets = rdpcap(path)
    start = time.perf_counter()
    result = extract_dns_mappings(packets)
    assert time.perf_counter() - start < 5  # 200 paquets : plusieurs minutes avant correction
    assert result["mappings"] == {"203.0.113.9": ["g00gle-update.com"]}
