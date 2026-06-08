"""Analyzer YARA - scan de fichiers avec des regles YARA custom."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("yara")

class DummyYaraSyntaxError(Exception):
    pass

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    class yara:
        SyntaxError = DummyYaraSyntaxError
        @staticmethod
        def compile(*args, **kwargs):
            return None


def compile_rules(rules_path: str) -> object | None:
    """Compile les regles YARA depuis un fichier ou un dossier."""
    if not HAS_YARA:
        log.error("yara-python requis - pip install yara-python")
        return None
    try:
        if os.path.isfile(rules_path):
            return yara.compile(filepath=rules_path)
        elif os.path.isdir(rules_path):
            rule_files = {}
            for fname in os.listdir(rules_path):
                if fname.endswith(('.yar', '.yara')):
                    namespace = os.path.splitext(fname)[0]
                    rule_files[namespace] = os.path.join(rules_path, fname)
            if rule_files:
                return yara.compile(filepaths=rule_files)
        return None
    except yara.SyntaxError as exc:
        log.error("Erreur syntaxe YARA : %s", exc)
        return None
    except Exception as exc:
        log.error("Erreur compilation YARA : %s", exc)
        return None


def scan_file(compiled_rules, file_path: str, timeout: int = 60) -> list[dict]:
    """Scanne un fichier avec des regles YARA compilees."""
    try:
        matches = compiled_rules.match(file_path, timeout=timeout)
        results = []
        for match in matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
                "strings": [],
            }
            for s in match.strings:
                for instance in s.instances:
                    match_info["strings"].append({
                        "offset": instance.offset,
                        "identifier": s.identifier,
                        "data": instance.matched_data[:64].hex(),
                    })
            results.append(match_info)
        return results
    except Exception as exc:
        log.error("Erreur scan YARA '%s' : %s", os.path.basename(file_path), exc)
        return []


def scan_data(compiled_rules, data: bytes, timeout: int = 60) -> list[dict]:
    """Scanne des donnees brutes avec des regles YARA compilees."""
    try:
        matches = compiled_rules.match(data=data, timeout=timeout)
        results = []
        for match in matches:
            match_info = {
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta) if match.meta else {},
            }
            results.append(match_info)
        return results
    except Exception as exc:
        log.error("Erreur scan YARA data : %s", exc)
        return []


class YARAAnalyzer(BaseAnalyzer):
    """Scanne des fichiers avec des regles YARA."""
    name = "yara"
    supported_extensions = ()

    def __init__(self, rules_path: str | None = None) -> None:
        self._rules_path = rules_path
        self._compiled = None

    def can_handle(self, path: str) -> bool:
        return False  # Active uniquement via CLI --yara

    def set_rules(self, rules_path: str) -> bool:
        """Charge et compile les regles YARA."""
        self._rules_path = rules_path
        self._compiled = compile_rules(rules_path)
        return self._compiled is not None

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_YARA:
            log.error("yara-python requis - pip install yara-python")
            return None

        if not self._compiled and self._rules_path:
            self._compiled = compile_rules(self._rules_path)

        if not self._compiled:
            log.error("Aucune regle YARA chargee")
            return None

        try:
            if os.path.isfile(path):
                matches = scan_file(self._compiled, path)
            elif os.path.isdir(path):
                matches = []
                for root, dirs, files in os.walk(path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            file_matches = scan_file(self._compiled, fpath)
                            for m in file_matches:
                                m["file"] = fpath
                            matches.extend(file_matches)
                        except Exception:
                            continue
            else:
                return None

            meta: dict = {
                "Regles YARA": self._rules_path or "N/A",
                "Fichier/Dossier scanne": path,
                "Total matches": str(len(matches)),
            }

            rules_matched = set()
            for m in matches:
                rules_matched.add(m["rule"])

            meta["Regles declenchees"] = str(len(rules_matched))

            for i, m in enumerate(matches[:15]):
                tags_str = f" [{', '.join(m['tags'])}]" if m.get('tags') else ""
                meta[f"Match #{i+1}"] = f"{m['rule']}{tags_str}"

            return FindingModel(
                type="yara",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "matches": matches[:200],
                    "rules_path": self._rules_path,
                    "unique_rules": list(rules_matched),
                },
            )
        except Exception as exc:
            log.error("Erreur YARA '%s' : %s", path, exc)
            return None
