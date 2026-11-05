"""Scénario ransomware sur partage de fichiers : audit clé=valeur, sauvegardes, manifeste, faux positifs."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile

import pytest

AUDIT = """\
2026-11-04T09:14:02Z ACCESS user=nadia.k host=ws-07 share=Finance path=/reports/summary.xlsx action=open result=allow
2026-11-04T09:14:11Z ACCESS user=nadia.k host=ws-07 share=Finance path=/reports/summary.xlsx action=rename result=allow new_name=summary.xlsx.locked
2026-11-04T09:14:12Z ACCESS user=nadia.k host=ws-07 share=Finance path=/reports/budget.xlsx action=rename result=allow new_name=budget.xlsx.locked
2026-11-04T09:15:32Z ACCESS user=nadia.k host=ws-07 share=Finance path=/reports/* action=rename result=allow count=179
2026-11-04T09:18:00Z SYSTEM host=files-01 action=share-disabled reason=manual-containment
2026-11-04T09:21:14Z ACCESS user=nadia.k host=ws-07 share=Backup path=/snapshots/preincident action=read result=deny
2026-11-04T09:24:10Z RESPONSE actor=soc-01 action=account-disabled user=nadia.k result=success
"""
CLEAN = {
    "summary.xlsx": b"FICTITIOUS SUMMARY\n",
    "budget.xlsx": b"FICTITIOUS BUDGET\nApproved: yes\n",
    "vendors.csv": b"vendor,status\nalpha,active\n",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


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


@pytest.fixture
def report(case):
    from forensic_analyzer.core.scanner import auto_scan, default_registry

    manifest = "".join(f"{_sha(CLEAN[n])}  reports/{n}\n" for n in ("summary.xlsx", "budget.xlsx"))
    with tarfile.open(case / "tp.tar.gz", "w:gz") as tar:
        for folder in ("./backups", "./backups/clean", "./data"):
            info = tarfile.TarInfo(folder)
            info.type = tarfile.DIRTYPE
            tar.addfile(info)
        for name, data in CLEAN.items():
            _add(tar, f"./backups/clean/reports/{name}", data)
            _add(tar, f"./backups/daily/reports/{name}.locked", b"LOCKED-BY-SIMULATION\n\n")
        _add(tar, "./data/access.log", AUDIT.encode())
        _add(tar, "./data/backup.sha256", manifest.encode())
        _add(tar, "./data/share-inventory.csv", b"share,criticality,rto_hours\nFinance,critical,4\nHR,high,8\n")
        _add(tar, "./data/ticket.md", b"# Ticket INC-17\nFichiers illisibles\n")
        _add(tar, "./scripts/wipe.sh", b"#!/bin/sh\nvssadmin delete shadows /all\n")
    return auto_scan(str(case), default_registry())


def _only(report, kind):
    found = [f for f in report.findings if f.type == kind]
    assert len(found) == 1, kind
    return found[0]


def test_audit_log_is_not_mistaken_for_a_web_log(report):
    log = _only(report, "log_analysis")
    assert log.extra["log_type"] == "file_audit" and log.severity == "critique"
    assert "Total requêtes" not in log.metadata
    alert = log.metadata["[ALERTE] Renommage de masse par nadia.k"]
    assert "181 fichiers" in alert and "ws-07" in alert and "Finance" in alert and ".locked" in alert
    assert "[ALERTE] Accès refusé 09:21:14" in log.metadata
    assert "account-disabled" in log.metadata["Actions de confinement"]
    assert log.extra["mitre"][0]["id"] == "T1486"
    assert [e["event_type"] for e in log.extra["timeline_events"]][:2] == ["first_access", "rename"]


def test_impact_links_marked_files_log_copies_and_manifest(report):
    impact = _only(report, "ransomware_impact")
    meta = impact.metadata
    assert impact.severity == "critique"
    assert "3 fichier(s) marqué(s) .locked" in meta["[ALERTE] Verdict"]
    assert "backups/daily/reports : 3/3" in meta["Dossiers touchés"]
    assert "pas un chiffrement réel" in meta["Nature du contenu"]
    assert meta["Journal et fichiers"].startswith("2/3")
    assert "vendors.csv.locked" in meta["Sans ligne nominative"] and "/reports/* (179)" in meta["Sans ligne nominative"]
    assert meta["Copies attestées par manifeste"] == "2/3 dans backups/clean/reports"
    assert "vendors.csv" in meta["[ATTENTION] Copies non attestées"]
    assert "criticality=critical" in meta["Enjeu (inventaires)"] and "HR" not in meta["Enjeu (inventaires)"]
    assert any("178 autres" in r for r in impact.incomplete)


def test_manifest_root_is_found_among_the_evidence(report):
    integrity = _only(report, "evidence_integrity")
    assert integrity.extra["all_ok"] and integrity.severity == "info"
    assert integrity.metadata["Racine retrouvée"].startswith("backups/clean ")
    assert integrity.extra["uncovered"] == ["backups/clean/reports/vendors.csv"]
    assert "ABSENT" not in str(integrity.metadata)


def test_every_extracted_file_is_accounted_for(report):
    triage = _only(report, "text_triage")
    assert report.skipped_files == []
    assert "Ticket INC-17" in triage.metadata["Documents (1)"]
    assert "colonnes share, criticality, rto_hours" in triage.metadata["Tableaux (2)"]
    assert triage.severity == "moyen" and "vssadmin" in triage.metadata["[ATTENTION] Script wipe.sh"]
    assert triage.incomplete  # une lecture n'est pas une analyse dédiée : le rapport le dit


def test_archive_directories_are_not_reported_as_refused(report):
    assert "écartée" not in report.scan_notes[0]


def test_conclusion_tells_the_incident(report, capsys):
    from forensic_analyzer.output import ui

    ui.render_conclusion(report)
    out = capsys.readouterr().out
    for expected in ("Incident", "Premier accès de nadia.k", "account-disabled", "Source de restauration", "Limite"):
        assert expected in out, expected
    assert "Fichiers non analysés" not in out


def test_homonym_without_matching_hash_is_not_an_alteration(tmp_path):
    from forensic_analyzer.analyzers.integrity.analyzer import integrity_finding
    from forensic_analyzer.core.integrity import locate_in_evidence, verify_manifest

    (tmp_path / "data").mkdir()
    (tmp_path / "autre" / "reports").mkdir(parents=True)
    other = tmp_path / "autre" / "reports" / "a.txt"
    other.write_text("sans rapport")
    manifest = tmp_path / "data" / "m.sha256"
    manifest.write_text(f"{'0' * 64}  reports/a.txt\n")

    res = verify_manifest(str(manifest), confined=True)
    assert locate_in_evidence(res, [str(other), str(manifest)]) is False
    finding = integrity_finding(str(manifest), res)
    assert res["results"][0]["status"] == "ABSENT" and finding.severity == "info"
    assert str(other) in str(finding.metadata)  # signalé comme piste, non vérifié


def test_alteration_is_detected_once_the_root_is_proven(tmp_path):
    from forensic_analyzer.core.integrity import locate_in_evidence, verify_manifest

    (tmp_path / "data").mkdir()
    reports = tmp_path / "snap" / "reports"
    reports.mkdir(parents=True)
    (reports / "ok.txt").write_bytes(b"ok")
    (reports / "ko.txt").write_bytes(b"modifie")
    manifest = tmp_path / "data" / "m.sha256"
    manifest.write_text(f"{_sha(b'ok')}  reports/ok.txt\n{_sha(b'original')}  reports/ko.txt\n")

    res = verify_manifest(str(manifest), confined=True)
    assert locate_in_evidence(res, [str(reports / "ok.txt"), str(reports / "ko.txt"), str(manifest)])
    assert {r["file"]: r["status"] for r in res["results"]} == {"reports/ok.txt": "OK", "reports/ko.txt": "DIFFÉRENT"}
    assert not res["all_ok"]


def test_plain_text_office_extension_is_not_a_macro(tmp_path):
    pytest.importorskip("oletools")
    from forensic_analyzer.analyzers.office import OfficeAnalyzer

    fake = tmp_path / "budget.xlsx"
    fake.write_text("FICTITIOUS BUDGET\nApproved: yes\n")
    finding = OfficeAnalyzer().analyze(str(fake))
    assert finding.severity == "faible" and finding.metadata["Format"] == "texte brut"
    assert "Macros" not in finding.metadata and "aucune macro" in finding.metadata["Raisons"]

    script = tmp_path / "facture.doc"
    script.write_text('Sub AutoOpen()\nShell "cmd /c calc"\nEnd Sub\n')
    finding = OfficeAnalyzer().analyze(str(script))
    assert finding.severity == "moyen" and "déguisé" in finding.metadata["Raisons"]


def test_log_format_is_judged_on_content(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer import LogAnalyzer
    from forensic_analyzer.analyzers.log_analyzer.parsers import detect_log_type

    other = tmp_path / "access.log"
    other.write_text("ceci n'est pas un journal web\nencore une ligne\n")
    assert detect_log_type(str(other)) == "unknown"
    assert LogAnalyzer().analyze(str(other)) is None  # plus de « 0 requête »

    web = tmp_path / "access_web.log"
    web.write_text('203.0.113.9 - - [25/Oct/2026:07:21:00 +0000] "GET / HTTP/1.1" 200 12 "-" "curl"\nligne illisible\n')
    assert detect_log_type(str(web)) == "web_access"
    assert LogAnalyzer().analyze(str(web)).incomplete == ["1 ligne(s) sur 2 au format non reconnu"]

    empty = tmp_path / "nginx-access.log"
    empty.write_text("")
    assert detect_log_type(str(empty)) == "web_access"


def test_corrupt_gzip_does_not_stop_the_scan(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer.parsers import detect_log_type

    corrupt = tmp_path / "x.log.gz"
    corrupt.write_bytes(gzip.compress(b"contenu " * 500)[:-12] + b"\xff" * 12)
    assert detect_log_type(str(corrupt)) in ("unknown", "web_access")


def test_few_renames_stay_below_the_mass_threshold(tmp_path):
    from forensic_analyzer.analyzers.log_analyzer import LogAnalyzer

    log = tmp_path / "audit.log"
    log.write_text("2026-11-04T09:14:11Z ACCESS user=a host=b path=/x action=rename result=allow new_name=y\n" * 3)
    finding = LogAnalyzer().analyze(str(log))
    assert finding.extra["details"]["mass_renames"] == [] and finding.severity == "info"


def test_ordinary_files_do_not_raise_a_ransomware_verdict(tmp_path):
    from forensic_analyzer.core.ransomware import assess_ransomware

    locks = [tmp_path / f"p{i}" / "poetry.lock" for i in range(5)]
    for lock in locks:
        lock.parent.mkdir()
        lock.write_text("x")
    assert assess_ransomware([str(p) for p in locks], [], {}) == (None, set())

    metas = [tmp_path / f"i{i}.png.meta" for i in range(5)]
    for meta in metas:
        meta.write_text("guid")
    impact, _ = assess_ransomware([str(p) for p in metas], [], {})
    assert impact.severity == "moyen" and "[ALERTE] Verdict" not in impact.metadata and impact.extra["mitre"] == []


def test_multiline_values_keep_their_lines(capsys):
    from forensic_analyzer.output import ui

    ui.kv("Clé", "première\nseconde")
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 and "première" in lines[0] and "seconde" in lines[1]
