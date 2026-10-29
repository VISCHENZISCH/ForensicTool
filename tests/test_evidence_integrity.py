"""Tests des hashes, de l'entropie et du matching IOC hors-ligne."""
from __future__ import annotations

import hashlib

from forensic_analyzer.analyzers.malware import ioc_matcher
from forensic_analyzer.analyzers.malware.entropy import StreamingEntropy, calculate_entropy
from forensic_analyzer.analyzers.malware.analyzer import MalwareAnalyzer
from forensic_analyzer.analyzers.stego.analyzer import _check_stego_signatures
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils import network


def test_finding_injects_hashes(tmp_path):
    content = b"evidence content"
    f = tmp_path / "sample.bin"
    f.write_bytes(content)

    finding = FindingModel(type="test", file=str(f))

    assert finding.metadata["SHA-256"] == hashlib.sha256(content).hexdigest()
    assert finding.metadata["MD5"] == hashlib.md5(content).hexdigest()


def test_entropy_bounds():
    assert calculate_entropy(b"") == 0.0
    assert calculate_entropy(b"A" * 1000) == 0.0
    assert calculate_entropy(bytes(range(256)) * 4) == 8.0


def test_streaming_entropy_matches_one_shot():
    data = bytes(range(256)) * 3 + b"A" * 5000 + b"\x00" * 777
    stream = StreamingEntropy()
    for i in range(0, len(data), 1000):
        stream.update(data[i:i + 1000])
    assert abs(stream.value() - calculate_entropy(data)) < 1e-12


def test_stego_signature_found_across_chunk_boundary(tmp_path):
    f = tmp_path / "img.png"
    # La signature chevauche la frontière des blocs de 1 Mo
    f.write_bytes(b"\x00" * (1024 * 1024 - 4) + b"OutGuess" + b"\x00" * 16)
    assert _check_stego_signatures(str(f)) == ["OutGuess"]


def test_virustotal_skipped_when_offline(monkeypatch):
    monkeypatch.setattr(network, "_online", False)
    monkeypatch.setenv("VT_API_KEY", "dummy")
    assert "hors-ligne" in MalwareAnalyzer()._virustotal_lookup("a" * 64)


def test_local_ioc_match():
    sha = next(iter(ioc_matcher.KNOWN_IOCS["sha256"]))
    menaces = ioc_matcher.match_iocs(md5="", sha256=sha)
    assert any("Lumma" in m for m in menaces)


def test_no_network_call_when_offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("aucune requête réseau ne doit partir en mode hors-ligne")

    monkeypatch.setattr(network, "_online", False)
    monkeypatch.setattr(ioc_matcher.urllib.request, "urlopen", forbidden)
    assert ioc_matcher.match_iocs(md5="0" * 32, sha256="0" * 64) == []


def test_online_lookup_requires_auth_key(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("pas de requête sans clé API")

    monkeypatch.setattr(network, "_online", True)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.setattr(ioc_matcher.urllib.request, "urlopen", forbidden)
    assert ioc_matcher.match_iocs(md5="0" * 32, sha256="0" * 64) == []


def test_online_lookup_uses_verified_tls(monkeypatch):
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b'{"query_status": "ok", "data": [{"signature": "AgentTesla", "tags": ["exe"]}]}'

    def fake_urlopen(req, **kwargs):
        captured["kwargs"] = kwargs
        captured["headers"] = dict(req.header_items())
        return FakeResponse()

    monkeypatch.setattr(network, "_online", True)
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "test-key")
    monkeypatch.setattr(ioc_matcher.urllib.request, "urlopen", fake_urlopen)

    menaces = ioc_matcher.match_iocs(md5="0" * 32, sha256="a" * 64)

    assert menaces == ["CLOUD INTEL (MalwareBazaar): Famille 'AgentTesla' | Tags: exe"]
    assert "context" not in captured["kwargs"]  # contexte TLS par défaut = vérifié
    assert captured["headers"].get("Auth-key") == "test-key"

