import os
import struct
from typing import Any

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.winexec")

class WindowsExecutionAnalyzer(BaseAnalyzer):
    """
    Analyse statique des artefacts d'exécution Windows (Prefetch, LNK).
    """

    def supports(self, filepath: str) -> bool:
        if not os.path.isfile(filepath):
            return False
            
        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".pf":
            return True
        if ext == ".lnk":
            return True
            
        # Magic bytes check for LNK
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
                if header == b"\x4c\x00\x00\x00":
                    return True
                # Prefetch Win10 signature SCCA
                if header in (b"SCCA", b"MAM\x04"):
                    return True
        except Exception:
            pass
            
        return False

    def analyze(self, filepath: str) -> FindingModel | None:
        if not self.supports(filepath):
            return None

        fname = os.path.basename(filepath)
        ext = os.path.splitext(filepath)[1].lower()
        
        metadata: dict[str, Any] = {}
        extra: dict[str, Any] = {}

        logger.info(f"Analyse d'artefact d'exécution Windows sur {filepath}...")

        try:
            with open(filepath, "rb") as f:
                header = f.read(8)

            if ext == ".pf" or header.startswith(b"SCCA") or header.startswith(b"MAM\x04"):
                artifact_type = "prefetch"
                metadata["Format"] = "Windows Prefetch (.pf)"
                # Basic parsing placeholder
                # Without pyscca or similar, parsing full Win10 compressed prefetch is complex.
                # Let's provide basic metadata.
                metadata["Nom supposé"] = fname.split('-')[0] + ".exe" if '-' in fname else fname
                extra["warning"] = "Le parsing profond des fichiers Prefetch nécessite la bibliothèque pyscca ou libyal."
                
            elif ext == ".lnk" or header.startswith(b"\x4c\x00\x00\x00"):
                artifact_type = "lnk_shortcut"
                metadata["Format"] = "Windows Shortcut (.lnk)"
                
                # Très basique parsing de LNK
                with open(filepath, "rb") as f:
                    data = f.read(100)
                    if len(data) >= 0x4C:
                        flags = struct.unpack("<I", data[0x14:0x18])[0]
                        metadata["Link Flags (Hex)"] = hex(flags)
                        
                        # Timestamps Windows FILETIME (100-nanoseconds since 1601)
                        # We won't convert them entirely here to save space, but they exist at 0x1C, 0x24, 0x2C
                        metadata["A un Target IDList"] = "OUI" if (flags & 0x01) else "NON"
                        metadata["A un Relative Path"] = "OUI" if (flags & 0x40) else "NON"
                        metadata["A des arguments"] = "OUI" if (flags & 0x20) else "NON"

        except Exception as e:
            logger.error(f"[WinExec] Erreur lors de l'analyse : {e}")
            return None

        return FindingModel(
            type=artifact_type,
            file=filepath,
            metadata=metadata,
            extra=extra
        )
