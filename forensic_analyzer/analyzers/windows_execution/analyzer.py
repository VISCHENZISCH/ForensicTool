import os
import re
from typing import Any
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.winexec")

try:
    import pyscca
    HAS_SCCA = True
except ImportError:
    HAS_SCCA = False

try:
    import LnkParse3
    HAS_LNK = True
except ImportError:
    HAS_LNK = False

class WindowsExecutionAnalyzer(BaseAnalyzer):
    """
    Analyse statique des artefacts d'exécution Windows (Prefetch, LNK).
    """
    name = "winexec"
    supported_extensions = ('.pf', '.lnk')

    def analyze(self, filepath: str) -> FindingModel | None:
        if not self.can_handle(filepath):
            return None

        fname = os.path.basename(filepath)
        ext = os.path.splitext(filepath)[1].lower()
        
        metadata: dict[str, Any] = {}
        extra: dict[str, Any] = {}

        logger.info(f"Analyse Artefact Windows : {fname}...")

        try:
            with open(filepath, "rb") as f:
                data = f.read()

            # Extraction heuristique de chaînes (ASCII et Unicode)
            ascii_strings = re.findall(rb"[\x20-\x7E]{5,}", data)
            unicode_strings = re.findall(rb"(?:[\x20-\x7E]\x00){5,}", data)
            
            all_strings = [s.decode('ascii', 'ignore') for s in ascii_strings]
            all_strings.extend([s.decode('utf-16le', 'ignore') for s in unicode_strings])
            
            text_content = " ".join(all_strings)

            if ext == ".pf":
                artifact_type = "prefetch"
                metadata["Format"] = "Windows Prefetch (.pf)"
                metadata["Exécutable Source"] = fname.split('-')[0] + ".exe" if '-' in fname else fname
                
                if HAS_SCCA:
                    try:
                        scca_file = pyscca.file()
                        scca_file.open(filepath)
                        metadata["Exécutions"] = str(scca_file.run_count)
                        if scca_file.get_number_of_run_times() > 0:
                            # Usually returns a datetime-like object or needs parsing
                            metadata["Dernière Exécution"] = "Extraite (voir pyscca object)"
                        filenames = []
                        for i in range(scca_file.number_of_filenames):
                            filenames.append(scca_file.get_filename(i))
                        extra["chemins_touches"] = filenames
                    except Exception as e:
                        logger.debug(f"Erreur pyscca: {e}")
                        
                if "chemins_touches" not in extra:
                    # Fallback heuristique
                    paths = re.findall(r'[A-Za-z]:\\[\w\\\.\-\ ]+\.\w+', text_content)
                    if paths:
                        extra["chemins_touches"] = list(set(paths))
                        
                if "chemins_touches" in extra:
                    metadata["Fichiers Référencés"] = f"{len(extra['chemins_touches'])} chemins extraits"

            elif ext == ".lnk":
                artifact_type = "lnk_shortcut"
                metadata["Format"] = "Windows Shortcut (.lnk)"
                
                if HAS_LNK:
                    try:
                        with open(filepath, 'rb') as f_lnk:
                            lnk = LnkParse3.lnk_file(f_lnk)
                            lnk_json = lnk.get_json()
                            link_info = lnk_json.get("link_info", {})
                            data_strings = lnk_json.get("data", {})
                            
                            metadata["Chemin Original"] = link_info.get("local_base_path", "N/A")
                            if data_strings.get("command_line_arguments"):
                                metadata["Arguments"] = data_strings.get("command_line_arguments")
                            if data_strings.get("working_directory"):
                                metadata["Dossier Travail"] = data_strings.get("working_directory")
                            
                            header = lnk_json.get("header", {})
                            if header.get("creation_time"):
                                metadata["Date Création (LNK)"] = header.get("creation_time")
                            if header.get("write_time"):
                                metadata["Date Modification (LNK)"] = header.get("write_time")
                                
                            extra["lnk_data"] = lnk_json
                    except Exception as e:
                        logger.debug(f"Erreur LnkParse3: {e}")
                
                # Recherche d'arguments suspects
                suspect_cmds = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "certutil", "bitsadmin"]
                found_cmds = [cmd for cmd in suspect_cmds if cmd.lower() in text_content.lower()]
                
                if found_cmds:
                    metadata["Exécutables Suspects"] = ", ".join(found_cmds)
                    
                if "-windowstyle hidden" in text_content.lower() or "-w hidden" in text_content.lower() or "-ep bypass" in text_content.lower():
                    metadata["Furtivité"] = "Exécution cachée détectée (Hidden Window / Bypass)"
                    
                if "http://" in text_content.lower() or "https://" in text_content.lower():
                    metadata["Téléchargement"] = "URL distante détectée dans le raccourci"

        except Exception as e:
            logger.error(f"[WinExec] Erreur d'analyse sur l'artefact Windows {fname}: {e}")
            return None

        if not metadata:
            metadata["Statut"] = "Aucun indicateur de compromission trouvé"

        return FindingModel(
            type=artifact_type,
            file=filepath,
            metadata=metadata,
            extra=extra
        )
