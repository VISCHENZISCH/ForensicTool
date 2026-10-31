"""Analyzer de scripts et webshells (PHP, scripts malveillants)."""
from __future__ import annotations

import os
import re
from typing import Any

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("webshell")

# Fonctions d'exécution de code ou commandes système
_DANGEROUS_EXEC = [
    (re.compile(r'\b(?:eval|assert|passthru|shell_exec|system|exec|popen|proc_open|pcntl_exec)\s*\(', re.IGNORECASE), "Exécution de code arbitraire"),
    (re.compile(r'\bcreate_function\s*\(', re.IGNORECASE), "create_function dépréciée / injection"),
    (re.compile(r'\$\w+\s*\(\s*\$_(?:GET|POST|COOKIE|REQUEST)', re.IGNORECASE), "Appel de fonction variable directe depuis entrée HTTP"),
]

# Obfuscation et encodages suspects
_OBFUSCATION = [
    (re.compile(r'\bbase64_decode\s*\(', re.IGNORECASE), "Décodage Base64"),
    (re.compile(r'\bgzinflate\s*\(', re.IGNORECASE), "Décompression Gzip/Inflate"),
    (re.compile(r'\bstr_rot13\s*\(', re.IGNORECASE), "Chiffrement ROT13"),
    (re.compile(r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', re.IGNORECASE), "Chaînes hexadécimales obfusquées"),
    (re.compile(r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(', re.IGNORECASE), "Concaténation dynamique chr()"),
]

# Vecteurs d'accès / backdoors
_INPUT_VECTORS = [
    (re.compile(r'\$_(?:POST|GET|COOKIE|REQUEST|SERVER)\s*\[', re.IGNORECASE), "Lecture d'entrées utilisateur HTTP"),
    (re.compile(r'\bfile_put_contents\s*\(', re.IGNORECASE), "Écriture de fichier sur disque"),
    (re.compile(r'\bmove_uploaded_file\s*\(', re.IGNORECASE), "Upload de fichier"),
]

# Signatures connues de webshells
_WEBSHELL_SIGNATURES = [
    (re.compile(r'c99shell|r57shell|b374k|WSO\s+version|FilesMan|Weevely|China\s+Chopper', re.IGNORECASE), "Signature de webshell public connu"),
    (re.compile(r'\b(?:cmd|shell|backdoor|rootkit)\b', re.IGNORECASE), "Mots-clés de contrôle à distance"),
]


class WebshellAnalyzer(BaseAnalyzer):
    """Détection et analyse de webshells PHP et scripts malveillants."""
    name = "webshell"
    supported_extensions = (".php", ".phtml", ".php5", ".php7", ".phps")

    def can_handle(self, path: str) -> bool:
        if not os.path.isfile(path):
            return False
        basename = os.path.basename(path).lower()
        if basename.endswith(self.supported_extensions):
            return True
        # Détection PHP sans extension ou shebang
        try:
            with open(path, "rb") as f:
                head = f.read(256)
                # "<?xml" n'est pas du PHP : seules les balises <?php, <?= et <? suivies d'un blanc comptent
                if re.search(rb"<\?(?:php\b|=|\s)", head):
                    return True
        except Exception:
            pass
        return False

    def analyze(self, path: str) -> FindingModel | None:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            file_size = len(content)
            findings_exec: list[str] = []
            findings_obfuscation: list[str] = []
            findings_inputs: list[str] = []
            signatures_hit: list[str] = []

            for pattern, desc in _DANGEROUS_EXEC:
                if pattern.search(content):
                    findings_exec.append(desc)

            for pattern, desc in _OBFUSCATION:
                if pattern.search(content):
                    findings_obfuscation.append(desc)

            for pattern, desc in _INPUT_VECTORS:
                if pattern.search(content):
                    findings_inputs.append(desc)

            for pattern, desc in _WEBSHELL_SIGNATURES:
                if pattern.search(content):
                    signatures_hit.append(desc)

            # Évaluation du score de dangerosité
            is_webshell = bool(findings_exec and findings_inputs) or bool(signatures_hit) or (bool(findings_exec) and bool(findings_obfuscation))

            meta: dict[str, Any] = {
                "Taille": f"{file_size:,} octets",
                "Langage": "PHP",
            }

            if is_webshell:
                meta["[ALERTE] Verdict"] = "WEBSHELL DÉTECTÉ — Script de porte dérobée (Backdoor)"
            else:
                meta["Verdict"] = "Script PHP sans indicateur évident de webshell"

            if findings_exec:
                meta["[ALERTE] Fonctions d'exécution"] = ", ".join(findings_exec)
            if findings_obfuscation:
                meta["Obfuscation / Encodages"] = ", ".join(findings_obfuscation)
            if findings_inputs:
                meta["Vecteurs d'entrée"] = ", ".join(findings_inputs)
            if signatures_hit:
                meta["[ALERTE] Signatures reconnues"] = ", ".join(signatures_hit)

            severity = "critique" if is_webshell else ("élevé" if findings_exec else ("moyen" if findings_obfuscation else "info"))
            return FindingModel(
                type="webshell_analysis",
                file=os.path.abspath(path),
                metadata=meta,
                extra={
                    "is_webshell": is_webshell,
                    "execution_functions": findings_exec,
                    "obfuscation": findings_obfuscation,
                    "inputs": findings_inputs,
                    "signatures": signatures_hit,
                },
                severity=severity,
            )
        except Exception as exc:
            log.error("Erreur lors de l'analyse du webshell '%s' : %s", path, exc)
            return None
