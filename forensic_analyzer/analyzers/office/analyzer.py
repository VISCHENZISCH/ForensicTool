"""Documents Office (OLE2 .doc/.xls/.ppt, OOXML .docx/.xlsm...) : macros, DDE, relations externes.

Premier vecteur d'infection en entreprise. Trois mécanismes sont cherchés :
- macros VBA ou Excel 4.0 (XLM), auto-exécutées ou non, et le VBA stomping (code source
  effacé ou différent du p-code réellement exécuté) ;
- champs DDE qui lancent une commande sans macro ;
- relations externes chargées à l'ouverture (modèle distant T1221, objet OLE, chemin UNC qui
  fait fuiter le hash NTLM T1187), elles aussi sans macro.
Un document chiffré est signalé comme non analysé, jamais comme sain.
"""
from __future__ import annotations

import os
import re
import zipfile

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("office")

try:
    from oletools import crypto, msodde
    from oletools.olevba import VBA_Parser
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

_OFFICE_EXT = (".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm", ".xls", ".xlt", ".xlsx", ".xlsm", ".xltm",
               ".xlsb", ".xlam", ".ppt", ".pps", ".pptx", ".pptm", ".ppsm", ".potm")
_RELATIONSHIP = re.compile(rb"<Relationship\b[^>]*>")
_ATTRIBUTE = re.compile(rb'(\w+)="([^"]*)"')
# Relations externes chargées sans action de l'utilisateur ; les hyperliens, eux, demandent un clic
_LOADED_AT_OPEN = {"attachedTemplate": "modèle distant (T1221)", "oleObject": "objet OLE externe",
                   "frame": "cadre externe", "subDocument": "sous-document externe"}
_MAX_RELS_BYTES = 4 * 1024 * 1024
_MAX_CODE_SHOWN = 20_000
_LEVELS = ("info", "faible", "moyen", "élevé", "critique")
# Mots-clés olevba qui exécutent ou téléchargent : seuls eux rendent une macro auto-exécutée critique
_ACTIVE = ("shell", "wscript", "powershell", "createobject", "getobject", "urldownloadtofile", "xmlhttp",
           "winhttp", "adodb.stream", "callbyname", "createprocess", "virtualalloc", "rtlmovememory",
           "mshta", "rundll32", "regsvr32", "exec", "run")


class OfficeAnalyzer(BaseAnalyzer):
    """Macros, DDE et relations externes des documents Office."""
    name = "office"
    supported_extensions = (".ole", ".ooxml") + _OFFICE_EXT   # .ole / .ooxml : signatures (utils/magic.py)

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path):
            return None
        if not HAS_OLETOOLS:
            return FindingModel(type="office_analysis", file=os.path.abspath(path),
                                metadata={"[ATTENTION] Non analysé": "oletools absent (pip install oletools)"},
                                incomplete=["oletools absent : macros non analysées"])
        office_named = path.lower().endswith(_OFFICE_EXT)
        meta: dict[str, str] = {}
        reasons: list[tuple[str, str]] = []      # (sévérité, raison)
        incomplete: list[str] = []
        extra: dict = {"office": {}}

        if _encrypted(path):
            incomplete.append("document chiffré par mot de passe : macros et contenu non analysés")
        else:
            self._macros(path, meta, reasons, incomplete, extra["office"])
            self._dde(path, meta, reasons, extra["office"])
        self._external_relations(path, meta, reasons, extra["office"])

        if not (reasons or incomplete or office_named):
            return None   # OLE2 sans rapport avec Office (MSI, Thumbs.db...) et sans macro
        severity = max((s for s, _ in reasons), key=_LEVELS.index, default="info")
        head = {"Format": _format(path)}
        if reasons and severity in ("élevé", "critique"):
            head["[ALERTE] Verdict"] = f"Document Office malveillant probable : {reasons[0][1]}"
        head["Sévérité"] = severity.capitalize()
        if reasons:
            head["Raisons"] = "\n".join(f"[{s}] {r}" for s, r in sorted(reasons, key=lambda x: -_LEVELS.index(x[0])))
        if incomplete:
            head["[ATTENTION] Non analysé"] = "\n".join(incomplete)
        urls = extra["office"].get("urls", [])
        if urls:
            extra["office_urls"] = urls
        return FindingModel(type="office_analysis", file=os.path.abspath(path), metadata={**head, **meta},
                            extra=extra, severity=severity, incomplete=incomplete)

    @staticmethod
    def _macros(path: str, meta: dict, reasons: list, incomplete: list, out: dict) -> None:
        try:
            parser = VBA_Parser(path)
        except Exception as exc:   # oletools lève des types variés sur un fichier corrompu
            incomplete.append(f"structure illisible par olevba ({type(exc).__name__} : {exc})")
            return
        try:
            if not parser.detect_vba_macros():
                return
            modules = [(vba_name, code) for _f, _s, vba_name, code in parser.extract_macros()
                       if code and code.strip()]
            keywords = [{"type": k, "keyword": w, "description": d} for k, w, d in parser.analyze_macros()]
            stomped = _safe(parser.detect_vba_stomping)
        finally:
            parser.close()

        xlm = [m for m in modules if "XLM" in m[0] or m[0].lower().startswith("xlm")]
        auto = sorted({k["keyword"] for k in keywords if k["type"] == "AutoExec"})
        suspicious = sorted({k["keyword"] for k in keywords if k["type"] == "Suspicious"})
        iocs = sorted({k["keyword"] for k in keywords if k["type"] == "IOC"})
        obfuscated = sum(k["type"] in ("Hex String", "Base64 String", "Dridex string", "VBA string") for k in keywords)

        meta["Macros"] = f"{len(modules)} module(s) : {', '.join(n for n, _ in modules[:8])}"
        if auto:
            meta["Auto-exécution"] = ", ".join(auto)
        if suspicious:
            meta["Mots-clés suspects"] = ", ".join(suspicious)
        if iocs:
            meta["IOC des macros"] = "\n".join(iocs)
        if obfuscated:
            meta["Chaînes obfusquées"] = f"{obfuscated} (hexadécimal, base64, concaténations)"
        if stomped:
            meta["VBA stomping"] = "DÉTECTÉ : le code source diffère du p-code réellement exécuté (CRITIQUE)"
        code = "\n\n".join(f"' ── {name}\n{text}" for name, text in modules)
        meta["Code des macros"] = code if len(code) <= _MAX_CODE_SHOWN else \
            code[:_MAX_CODE_SHOWN] + f"\n… ({len(code)} caractères au total, code complet dans le JSON)"

        if stomped:
            reasons.append(("critique", "VBA stomping : le code exécuté n'est pas celui affiché"))
        active = [k for k in suspicious if k.lower() in _ACTIVE or k.lower().startswith(("wscript", "shell"))]
        if auto and active:
            reasons.append(("critique", f"macro auto-exécutée ({auto[0]}) qui appelle {', '.join(active[:4])}"))
        elif auto:
            reasons.append(("élevé", f"macro auto-exécutée ({', '.join(auto[:3])})"))
        elif xlm:
            reasons.append(("élevé", "macros Excel 4.0 (XLM), rarement légitimes"))
        else:
            reasons.append(("moyen", f"{len(modules)} macro(s) VBA, déclenchées par l'utilisateur"))
        out.update(macros=[{"module": n, "code": c} for n, c in modules], keywords=keywords,
                   urls=[i for i in iocs if re.match(r"(?i)https?://", i)])

    @staticmethod
    def _dde(path: str, meta: dict, reasons: list, out: dict) -> None:
        links = _safe(lambda: msodde.process_file(path, msodde.FIELD_FILTER_BLACKLIST))
        if not links or not str(links).strip():
            return
        links = str(links).strip()
        meta["Champs DDE"] = links
        command = re.search(r"(?i)\b(cmd|powershell|mshta|wscript|cscript|rundll32|regsvr32)\b", links)
        reasons.append(("critique" if command else "élevé",
                        f"champ DDE{' qui lance ' + command.group(1) if command else ''} (exécution sans macro)"))
        out["dde"] = links

    @staticmethod
    def _external_relations(path: str, meta: dict, reasons: list, out: dict) -> None:
        if not zipfile.is_zipfile(path):
            return
        found = []
        try:
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if not info.filename.endswith(".rels") or info.file_size > _MAX_RELS_BYTES:
                        continue
                    for rel in _RELATIONSHIP.findall(z.read(info)):
                        attrs = {k.decode(): v.decode("utf-8", "replace") for k, v in _ATTRIBUTE.findall(rel)}
                        kind = attrs.get("Type", "").rsplit("/", 1)[-1]
                        if attrs.get("TargetMode") == "External" and kind in _LOADED_AT_OPEN:
                            found.append((kind, attrs.get("Target", ""), info.filename))
        except (zipfile.BadZipFile, OSError, KeyError) as exc:
            log.debug("Relations illisibles dans %s : %s", path, exc)
            return
        if not found:
            return
        meta["Relations externes"] = "\n".join(f"{_LOADED_AT_OPEN[k]} : {t} ({src})" for k, t, src in found)
        for kind, target, _src in found:
            unc = target.startswith("\\\\") or target.lower().startswith("file://")
            reasons.append(("élevé", f"{_LOADED_AT_OPEN[kind]} chargé à l'ouverture : {target}"
                                     + (" (chemin UNC : fuite du hash NTLM, T1187)" if unc else "")))
        out.setdefault("urls", []).extend(t for _k, t, _s in found if re.match(r"(?i)https?://", t))
        out["external"] = [{"type": k, "target": t, "part": s} for k, t, s in found]


def _safe(call):
    try:
        return call()
    except Exception as exc:   # détection secondaire : son échec ne doit pas masquer le reste
        log.debug("oletools : %s", exc)
        return None


def _encrypted(path: str) -> bool:
    return bool(_safe(lambda: crypto.is_encrypted(path)))


def _format(path: str) -> str:
    if zipfile.is_zipfile(path):
        return "OOXML (Office 2007+)"
    with open(path, "rb") as fh:
        return "OLE2 (Office 97-2003)" if fh.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" else "inconnu"
