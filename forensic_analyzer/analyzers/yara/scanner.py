"""Logique avancée de scan YARA avec Result Pattern."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Generic, TypeVar

from forensic_analyzer.utils.logger import get_logger

log = get_logger("yara")

T = TypeVar('T')
E = TypeVar('E')

@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T
    ok: bool = True

@dataclass(frozen=True)
class Err(Generic[E]):
    error: E
    ok: bool = False

Result = Ok[T] | Err[E]

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
        def compile(*args, **kwargs): return None

class YaraScanner:
    """Scanner YARA avec encapsulation ."""
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self._compiled = self._compile_rules()

    def _compile_rules(self) -> object | None:
        if not HAS_YARA: return None
        try:
            if os.path.isfile(self.rules_path):
                return yara.compile(filepath=self.rules_path)
            elif os.path.isdir(self.rules_path):
                rule_files = {
                    os.path.splitext(f)[0]: os.path.join(self.rules_path, f)
                    for f in os.listdir(self.rules_path) if f.endswith(('.yar', '.yara'))
                }
                return yara.compile(filepaths=rule_files) if rule_files else None
            return None
        except yara.SyntaxError as exc:
            log.error("Erreur syntaxe YARA : %s", exc)
            return None
        except Exception as exc:
            log.error("Erreur compilation YARA : %s", exc)
            return None

    @property
    def is_ready(self) -> bool:
        return self._compiled is not None

    def scan_file(self, file_path: str, timeout: int = 60) -> Result[list[dict], str]:
        if not self.is_ready:
            return Err("Aucune règle compilée prête.")
        try:
            matches = self._compiled.match(file_path, timeout=timeout)
            results = []
            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": list(match.tags),
                    "meta": dict(match.meta) if match.meta else {},
                    "strings": [],
                    "file": file_path
                }
                for s in match.strings:
                    for instance in s.instances:
                        match_info["strings"].append({
                            "offset": instance.offset,
                            "identifier": s.identifier,
                            "data": instance.matched_data[:64].hex(),
                        })
                results.append(match_info)
            return Ok(results)
        except Exception as exc:
            return Err(f"Erreur d'analyse du fichier : {exc}")
