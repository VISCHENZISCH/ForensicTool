"""Tests de validation des corrections apportées d'après les faiblesses du TP."""
import gzip

import pytest

from forensic_analyzer.core.pipeline import run_pipeline
from forensic_analyzer.core.scanner import default_registry
from forensic_analyzer.analyzers.linux import LinuxArtifactsAnalyzer
from forensic_analyzer.analyzers.log_analyzer import LogAnalyzer
from forensic_analyzer.analyzers.webshell import WebshellAnalyzer
from forensic_analyzer.analyzers.nmap import NmapAnalyzer
from forensic_analyzer.analyzers.pcap.credentials import extract_credentials
from forensic_analyzer.analyzers.pcap.streams import rebuild_tcp_streams


def test_log_analyzer_parses_web_access(tmp_path):
    """Vérifie l'analyse de logs d'accès web Nginx/Apache."""
    log_file = tmp_path / "nginx-access.log"
    log_content = (
        '203.0.113.42 - - [12/Oct/2026:13:55:36 +0200] "GET /wp-login.php HTTP/1.1" 200 1450 "-" "Mozilla/5.0"\n'
        '203.0.113.42 - - [12/Oct/2026:13:55:40 +0200] "POST /wp-login.php HTTP/1.1" 302 0 "-" "Mozilla/5.0"\n'
        '203.0.113.42 - - [12/Oct/2026:13:56:00 +0200] "GET /wp-content/plugins/vuln/x.php?cmd=id HTTP/1.1" 200 45 "-" "curl/7.88"\n'
        '203.0.113.42 - - [12/Oct/2026:13:56:10 +0200] "GET /index.php?id=1%27%20UNION%20SELECT%20null,null-- HTTP/1.1" 500 200 "-" "sqlmap/1.7"\n'
    )
    log_file.write_text(log_content)

    analyzer = LogAnalyzer()
    assert analyzer.can_handle(str(log_file))
    res = analyzer.analyze(str(log_file))

    assert res is not None
    assert res.type == "log_analysis"
    assert "203.0.113.42" in res.metadata.get("Top IP sources", "")
    assert "[ALERTE] Attaques web détectées" in res.metadata
    assert "[ALERTE] Accès Webshell" in res.metadata
    assert "[ALERTE] Scanners automatisés" in res.metadata
    assert len(res.extra.get("timeline_events", [])) >= 2


def test_log_analyzer_parses_gzipped_access_log(tmp_path):
    """Vérifie la décompression transparente et l'analyse de journaux gzippés (ex: access.log.1.gz)."""
    log_file = tmp_path / "access.log.1.gz"
    log_content = '203.0.113.42 - - [12/Oct/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 500 "-" "Mozilla/5.0"\n'
    with gzip.open(log_file, "wt", encoding="utf-8") as f:
        f.write(log_content)

    analyzer = LogAnalyzer()
    assert analyzer.can_handle(str(log_file))
    res = analyzer.analyze(str(log_file))
    assert res is not None
    assert "203.0.113.42" in res.metadata.get("Top IP sources", "")


def test_log_analyzer_parses_syslog_and_auth(tmp_path):
    """Vérifie l'analyse de syslog et auth.log avec détection SSH et SUDO."""
    syslog_file = tmp_path / "syslog"
    content = (
        'Oct 12 10:14:02 srv sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 54321 ssh2\n'
        'Oct 12 10:14:05 srv sshd[1235]: Failed password for root from 203.0.113.42 port 54322 ssh2\n'
        'Oct 12 10:15:00 srv sshd[1240]: Accepted password for deploy from 203.0.113.42 port 54330 ssh2\n'
        'Oct 12 10:16:00 srv sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash\n'
    )
    syslog_file.write_text(content)

    analyzer = LogAnalyzer()
    assert analyzer.can_handle(str(syslog_file))
    res = analyzer.analyze(str(syslog_file))
    assert res is not None
    assert res.metadata["Échecs d'authentification"] == "2"
    assert res.metadata["Succès d'authentification"] == "1"
    assert res.metadata["Commandes SUDO"] == "1"
    assert "203.0.113.42" in res.metadata.get("[ALERTE] Top IPs brute-force (SSH)", "")


def test_log_analyzer_parses_wp_debug(tmp_path):
    """Vérifie l'analyse de wp-debug.log et l'identification des fichiers PHP fautifs."""
    debug_file = tmp_path / "wp-debug.log"
    content = (
        '[12-Oct-2026 13:56:01 UTC] PHP Fatal error:  Uncaught Error: Call to undefined function eval_post() in /var/www/html/wp-content/plugins/vuln/x.php:12\n'
        '[12-Oct-2026 13:56:02 UTC] PHP Warning:  Cannot modify header information in /var/www/html/wp-includes/pluggable.php on line 1234\n'
    )
    debug_file.write_text(content)

    analyzer = LogAnalyzer()
    assert analyzer.can_handle(str(debug_file))
    res = analyzer.analyze(str(debug_file))
    assert res is not None
    assert res.metadata["Erreurs fatales PHP"] == "1"
    assert "x.php" in res.metadata["Fichiers PHP impliqués"]


def test_webshell_analyzer_detects_php_backdoor(tmp_path):
    """Vérifie la détection d'un webshell PHP (x.php)."""
    php_file = tmp_path / "x.php"
    php_file.write_text('<?php if(isset($_POST["cmd"])){ eval(base64_decode($_POST["cmd"])); } ?>')

    analyzer = WebshellAnalyzer()
    assert analyzer.can_handle(str(php_file))
    res = analyzer.analyze(str(php_file))
    assert res is not None
    assert res.type == "webshell_analysis"
    assert "WEBSHELL DÉTECTÉ" in res.metadata["[ALERTE] Verdict"]
    assert "Exécution de code arbitraire" in res.metadata["[ALERTE] Fonctions d'exécution"]
    assert "Décodage Base64" in res.metadata["Obfuscation / Encodages"]


def test_nmap_analyzer_parses_xml(tmp_path):
    """Vérifie l'analyse de nmap-perimeter.xml."""
    xml_file = tmp_path / "nmap-perimeter.xml"
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -p 22,80,445 203.0.113.42" start="1790000000">
<host>
    <status state="up"/>
    <address addr="203.0.113.42" addrtype="ipv4"/>
    <hostnames><hostname name="target.lab" type="user"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.22"/></port>
        <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" product="Samba"/></port>
    </ports>
</host>
</nmaprun>
"""
    xml_file.write_text(xml_content)

    analyzer = NmapAnalyzer()
    assert analyzer.can_handle(str(xml_file))
    res = analyzer.analyze(str(xml_file))
    assert res is not None
    assert res.metadata["Hôtes actifs découverts"] == "1"
    assert res.metadata["Total ports ouverts"] == "3"
    assert "203.0.113.42" in res.extra["iocs"]["ips"]


def test_linux_analyzer_handles_bash_history_and_cron(tmp_path):
    """Vérifie la prise en charge de .bash_history et de cron.d/updater."""
    bh_file = tmp_path / ".bash_history"
    bh_file.write_text(
        "#1790000000\n"
        "smbclient //192.168.1.100/share -U user%password123\n"
        "mysql -u root -pSecretPass -e 'SHOW DATABASES;'\n"
        "rm -rf /var/log/nginx/*\n"
    )

    analyzer = LinuxArtifactsAnalyzer()
    assert analyzer.can_handle(str(bh_file))
    res = analyzer.analyze(str(bh_file))
    assert res is not None
    assert int(res.metadata["Commandes suspectes"]) >= 3

    # Test cron file
    cron_dir = tmp_path / "cron.d"
    cron_dir.mkdir()
    updater_file = cron_dir / "updater"
    updater_file.write_text("* * * * * root /tmp/.x/kworkerd\n")

    assert analyzer.can_handle(str(updater_file))
    res_cron = analyzer.analyze(str(updater_file))
    assert res_cron is not None
    assert res_cron.metadata["Type"] == "crontab / cron.d"
    assert res_cron.metadata["Entrées cron"] == "1"


def test_pcap_credentials_extracts_post_form():
    """Vérifie l'extraction des identifiants dans les requêtes POST HTTP."""
    data = (
        b"POST /wp-login.php HTTP/1.1\r\n"
        b"Host: target.lab\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        b"log=admin&pwd=SuperPassword123%21&wp-submit=Log+In"
    )
    streams = {"203.0.113.42:54321 <-> 10.0.0.5:80": data}
    creds = extract_credentials(streams)
    assert len(creds) == 1
    assert creds[0]["protocol"] == "HTTP Form (POST)"
    assert creds[0]["username"] == "admin"
    assert creds[0]["password"] == "SuperPassword123!"


def test_pcap_rebuild_streams_separates_syn_sessions():
    """Vérifie que des connexions successives partageant le même quadruplet sont scindées en sessions distinctes."""
    scapy = pytest.importorskip("scapy.all")
    pkt1_syn = scapy.IP(src="203.0.113.42", dst="10.0.0.5") / scapy.TCP(sport=50000, dport=80, flags="S", seq=100)
    pkt1_data = scapy.IP(src="203.0.113.42", dst="10.0.0.5") / scapy.TCP(sport=50000, dport=80, flags="A", seq=101) / scapy.Raw(load=b"POST /wp-login.php (req 1)")

    pkt2_syn = scapy.IP(src="203.0.113.42", dst="10.0.0.5") / scapy.TCP(sport=50000, dport=80, flags="S", seq=200)
    pkt2_data = scapy.IP(src="203.0.113.42", dst="10.0.0.5") / scapy.TCP(sport=50000, dport=80, flags="A", seq=201) / scapy.Raw(load=b"POST /wp-login.php (req 2)")

    streams = rebuild_tcp_streams([pkt1_syn, pkt1_data, pkt2_syn, pkt2_data])
    assert len(streams) == 2
    keys = list(streams.keys())
    assert any("#2" in k for k in keys)


def test_pipeline_warning_on_unsupported_files(tmp_path):
    """Vérifie que les fichiers non gérés (ex: CONSTAT.md) sont tracés dans skipped_files et avertis."""
    notes = tmp_path / "CONSTAT.md"
    notes.write_text("# Mes notes d'investigation")

    reg = default_registry()
    report = run_pipeline([str(notes)], reg)

    assert str(notes) in report.skipped_files
    assert report.total == 0
