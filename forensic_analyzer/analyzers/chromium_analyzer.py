import os
import sqlite3
from typing import Any

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.chromium")

class ChromiumAnalyzer(BaseAnalyzer):
    """
    Analyse approfondie des bases SQLite basées sur Chromium 
    (Chrome, Edge, Brave, Vivaldi).
    Extrait l'historique de téléchargement, les logins et les web data.
    """

    def supports(self, filepath: str) -> bool:
        if not os.path.isfile(filepath):
            return False
        
        fname = os.path.basename(filepath).lower()
        if fname in ("history", "web data", "login data"):
            return True
        return False

    def analyze(self, filepath: str) -> FindingModel | None:
        if not self.supports(filepath):
            return None

        fname = os.path.basename(filepath).lower()
        logger.info(f"Analyse base Chromium ({fname}) sur {filepath}...")
        
        metadata: dict[str, Any] = {"Base cible": fname}
        extra: dict[str, Any] = {}

        try:
            conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
            cursor = conn.cursor()

            if fname == "history":
                # Historique des téléchargements
                cursor.execute("SELECT target_path, start_time, total_bytes, danger_type FROM downloads LIMIT 500")
                downloads = []
                for row in cursor.fetchall():
                    downloads.append({
                        "fichier": row[0],
                        "timestamp_webkit": row[1],
                        "taille_octets": row[2],
                        "danger_type": row[3]
                    })
                metadata["Téléchargements trouvés"] = len(downloads)
                extra["chromium_downloads"] = downloads

                # Historique web
                cursor.execute("SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 500")
                urls = [{"url": r[0], "titre": r[1], "visites": r[2]} for r in cursor.fetchall()]
                metadata["URLs indexées"] = len(urls)
                extra["chromium_urls"] = urls

            elif fname == "login data":
                # Identifiants (Login Data)
                cursor.execute("SELECT origin_url, username_value FROM logins LIMIT 500")
                logins = [{"url": r[0], "utilisateur": r[1]} for r in cursor.fetchall()]
                metadata["Identifiants stockés"] = len(logins)
                extra["chromium_logins"] = logins

            elif fname == "web data":
                # Autofill
                cursor.execute("SELECT name, value, count FROM autofill LIMIT 500")
                autofill = [{"champ": r[0], "valeur": r[1], "utilisation": r[2]} for r in cursor.fetchall()]
                metadata["Champs autofill"] = len(autofill)
                extra["chromium_autofill"] = autofill

            conn.close()

        except sqlite3.OperationalError as e:
            logger.warning(f"Base de données verrouillée ou invalide : {e}")
            return None
        except sqlite3.Error as e:
            logger.error(f"[Chromium] Erreur SQLite : {e}")
            return None

        return FindingModel(
            type="chromium_artifacts",
            file=filepath,
            metadata=metadata,
            extra=extra
        )
