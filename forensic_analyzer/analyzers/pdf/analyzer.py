"""Analyseur pour fichiers PDF : métadonnées, révisions et analyse de menace."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .parser import format_pdf_date, read_metadata
from .threats import analyze_pdf

log = get_logger("pdf")

_DATE_KEYS = ("CreationDate", "ModDate")
_MAX_JS_SHOWN = 20_000
_SEVERITY = {"Critique": "critique", "Élevé": "élevé", "Moyen": "moyen", "Faible": "faible"}   # Indéterminé : None


class PDFAnalyzer(BaseAnalyzer):
    """Analyseur de fichiers PDF."""
    name = "pdf"
    supported_extensions = ('.pdf',)

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path):
            return None

        log.debug(f"Analyse PDF sur {path}...")
        metadata, reader, error = read_metadata(path)
        try:
            t = analyze_pdf(path, reader)
        except (OSError, MemoryError) as exc:
            log.warning("↳ PDF non analysé (%s)", exc)
            metadata["[ATTENTION] Non analysé"] = f"{exc} : aucune conclusion sur la menace"
            return FindingModel(type="pdf_analysis", file=os.path.abspath(path), metadata=metadata,
                                incomplete=[f"analyse de menace impossible : {exc}"])

        if not reader:   # pypdf absent ou en échec : /Info lu dans la structure brute
            metadata = {**t.info, **metadata}
        if error:        # l'analyse de menace a son propre découpage : seule la lecture pypdf a échoué
            log.warning("↳ %s", error)
            metadata["[ATTENTION] Structure"] = f"{error} ; métadonnées lues dans la structure brute"
        if "Chiffrement" not in metadata and t.encrypted:
            metadata["Chiffrement"] = "Chiffré (détecté dans la structure)"
        for key in _DATE_KEYS:
            if key in metadata:
                metadata[key] = format_pdf_date(metadata[key])
        if t.revisions > 1 or t.redefined:
            metadata["Révisions"] = (f"{t.revisions} (mises à jour incrémentales), "
                                     f"{t.redefined} objet(s) redéfini(s) : document modifié après création")
        if t.linearized:
            metadata["Linéarisation"] = "OUI (Fast Web View)"
        for key, value in t.xmp.items():
            metadata[f"XMP {key}"] = value
        if t.partial:
            metadata["[ATTENTION] Non analysé"] = "\n".join(dict.fromkeys(t.partial))

        if t.score >= 50:
            metadata["[ALERTE] Verdict"] = "PDF malveillant probable : " + t.reasons[0][1]
        metadata["Score de menace"] = f"{t.score}/100 ({t.level})" + (" — analyse partielle" if t.partial else "")
        if t.reasons:
            metadata["Justification du score"] = "\n".join(f"+{p} {text}" for p, text in t.reasons)
        if t.scripts:
            metadata["PDF Actions"] = "\n".join(
                f"JavaScript {'exécuté sans clic (Critique)' if s.auto else 'présent'} : {s.trigger}, obj {s.obj}"
                for s in t.scripts)
        if t.launches:
            metadata["Lancement de programme"] = "\n".join(f"{x} (Critique)" for x in t.launches)
        if t.other_actions or t.auto_external:
            metadata["Actions externes"] = "\n".join(dict.fromkeys(t.auto_external + t.other_actions))
        if t.embedded:
            metadata["Fichiers Embarqués"] = ", ".join(t.embedded) + " (à extraire et analyser)"
        if t.shellcode:
            metadata["Shellcode"] = f"DÉTECTÉ (heap spray encodé) : {', '.join(t.shellcode)} (CRITIQUE)"
        if t.obfuscated_names:
            metadata["Noms obfusqués"] = ", ".join(t.obfuscated_names) + " écrits en #xx (technique d'évasion)"
        if t.high_entropy:
            metadata["Streams Obfusqués"] = (f"obj {', '.join(map(str, t.high_entropy))} : encore aléatoire(s) "
                                             "après décodage (chiffré ou packé)")
        if t.tags:
            metadata["Tags PDF Suspects"] = ", ".join(t.tags)
        if t.urls:
            metadata["URLs intégrées"] = "\n".join(t.urls)
        if t.text_urls:
            metadata["URLs dans le texte"] = "\n".join(t.text_urls)
        if t.scripts:
            js = "\n\n".join(f"// obj {s.obj} — {s.trigger}\n{s.code or '(illisible)'}" for s in t.scripts)
            metadata["JS Code Extrait"] = js if len(js) <= _MAX_JS_SHOWN else \
                js[:_MAX_JS_SHOWN] + f"\n… ({len(js)} caractères au total, code complet dans le JSON)"

        extra = {"pdf_threat": {"score": t.score, "level": t.level, "partial": t.partial,
                                "reasons": [{"points": p, "reason": text} for p, text in t.reasons]}}
        if t.urls:
            extra["pdf_urls"] = t.urls
        if t.scripts:
            extra["pdf_javascript"] = [s.code for s in t.scripts]
            extra["pdf_scripts"] = [{"obj": s.obj, "trigger": s.trigger, "auto": s.auto, "code": s.code}
                                    for s in t.scripts]
        return FindingModel(type="pdf_analysis", file=os.path.abspath(path), metadata=metadata, extra=extra,
                            severity=_SEVERITY.get(t.level), incomplete=list(dict.fromkeys(t.partial)))
