import math
import os
from typing import Any

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.pe")

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count > 0:
            p = float(count) / length
            entropy -= p * math.log2(p)
    return entropy


class PEAnalyzer(BaseAnalyzer):
    """
    Analyse statique d'exécutables (Triage Malware).
    Extrait l'entropie, l'Imphash, les sections suspectes et les timestamps.
    """

    def supports(self, filepath: str) -> bool:
        if not os.path.isfile(filepath):
            return False
        try:
            with open(filepath, "rb") as f:
                return f.read(2) == b"MZ"
        except Exception:
            return False

    def analyze(self, filepath: str) -> FindingModel | None:
        if not self.supports(filepath):
            return None

        logger.info(f"Analyse statique PE (Malware Triage) sur {filepath}...")
        
        metadata: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        
        # 1. Calcul Entropie Global (toujours dispo)
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            entropy = calculate_entropy(data)
            metadata["Entropie globale"] = f"{entropy:.2f} (Suspicion packé: {'OUI' if entropy > 7.2 else 'NON'})"
        except Exception as e:
            logger.error(f"[PE] Erreur lecture entropie : {e}")
            return None

        # 2. Analyse avancée avec pefile
        if HAS_PEFILE:
            try:
                pe = pefile.PE(filepath)
                
                # Architecture
                arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
                metadata["Architecture"] = arch
                
                # Compilation Timestamp
                timestamp = pe.FILE_HEADER.TimeDateStamp
                import datetime
                dt = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
                metadata["Date Compilation"] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                
                # Imphash
                metadata["Imphash"] = pe.get_imphash()
                
                # Sections suspectes
                sections = []
                for section in pe.sections:
                    sec_name = section.Name.decode('utf-8', 'ignore').rstrip('\x00')
                    sec_ent = section.get_entropy()
                    suspicious = " (CRITIQUE)" if sec_ent > 7.5 else ""
                    sections.append({
                        "Nom": sec_name,
                        "Entropie": f"{sec_ent:.2f}{suspicious}",
                        "Taille Virtuelle": section.Misc_VirtualSize
                    })
                extra["sections_pe"] = sections
                
                # Imports
                imports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else "Unknown"
                        imports.append(dll_name)
                extra["dll_imports"] = imports
                
            except Exception as e:
                logger.error(f"[PE] Parsing pefile échoué : {e}")
        else:
            logger.warning("Bibliothèque 'pefile' manquante. Imphash et Headers ignorés. pip install pefile")

        return FindingModel(
            type="pe_analysis",
            file=filepath,
            metadata=metadata,
            extra=extra
        )
