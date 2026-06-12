"""Analyseur pour scan YARA."""
from __future__ import annotations

import os

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

from .scanner import YaraScanner, HAS_YARA

log = get_logger("yara")

class YARAAnalyzer(BaseAnalyzer):
    """Scanne des fichiers avec des règles YARA."""
    name = "yara"
    supported_extensions = ()

    def __init__(self, rules_path: str | None = None) -> None:
        self._rules_path = rules_path
        self._scanner = None

    def can_handle(self, path: str) -> bool:
        return False  # Active uniquement via CLI --yara

    def set_rules(self, rules_path: str) -> bool:
        self._rules_path = rules_path
        self._scanner = YaraScanner(rules_path)
        return self._scanner.is_ready

    def analyze(self, path: str) -> FindingModel | None:
        if not HAS_YARA:
            log.error("yara-python requis - pip install yara-python")
            return None

        if not self._scanner and self._rules_path:
            self.set_rules(self._rules_path)

        if not self._scanner or not self._scanner.is_ready:
            log.error("Aucune règle YARA chargée")
            return None

        matches = []
        if os.path.isfile(path):
            res = self._scanner.scan_file(path)
            if res.ok: matches.extend(res.value)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    res = self._scanner.scan_file(fpath)
                    if res.ok: matches.extend(res.value)
        else:
            return None

        meta: dict = {
            "Règles YARA": self._rules_path or "N/A",
            "Fichier/Dossier scanné": path,
            "Total matches": str(len(matches)),
        }

        rules_matched = {m["rule"] for m in matches}
        meta["Règles déclenchées"] = str(len(rules_matched))

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
