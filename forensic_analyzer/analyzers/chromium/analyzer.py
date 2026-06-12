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
        if fname in ("history", "web data", "login data", "cookies", "bookmarks", "preferences", "secure preferences"):
            return True
        if fname in ("last session", "last tabs", "current session", "current tabs"):
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
            if fname in ("bookmarks", "preferences", "secure preferences"):
                import json
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    
                if fname == "bookmarks":
                    metadata["Type"] = "JSON Bookmarks"
                    metadata["Favoris (Alerte)"] = "Extraction JSON réussie"
                    # Extraction basique pour l'exemple
                    extra["bookmarks_raw"] = data
                else:
                    # Preferences -> Extensions
                    exts = data.get("extensions", {}).get("settings", {})
                    metadata["Extensions Installées"] = str(len(exts))
                    extra["chromium_extensions"] = list(exts.keys())
                    
            elif "session" in fname or "tabs" in fname:
                metadata["Type"] = "SNSS Session File"
                metadata["Reconstruction Session"] = "Onglets/Historique de session (Format binaire propriétaire)"
                # On peut juste lire les chaines ASCII
                with open(filepath, "rb") as f:
                    content = f.read()
                    import re
                    urls = re.findall(rb'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
                    urls = list(set([u.decode('ascii', 'ignore') for u in urls]))
                    metadata["URLs de la Session"] = str(len(urls))
                    extra["session_urls"] = urls
                    
            else:
                conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
                cursor = conn.cursor()

                if fname == "history":
                    try:
                        cursor.execute("SELECT target_path, datetime((start_time/1000000)-11644473600, 'unixepoch'), total_bytes, danger_type FROM downloads LIMIT 500")
                        downloads = [{"fichier": r[0], "date": r[1], "taille": r[2], "danger": r[3]} for r in cursor.fetchall()]
                        metadata["Téléchargements"] = len(downloads)
                        extra["chromium_downloads"] = downloads
                    except Exception: pass

                    try:
                        cursor.execute("SELECT url, title, visit_count, datetime((last_visit_time/1000000)-11644473600, 'unixepoch') FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
                        urls = [{"url": r[0], "titre": r[1], "visites": r[2], "date": r[3]} for r in cursor.fetchall()]
                        metadata["URLs visitées"] = len(urls)
                        extra["chromium_urls"] = urls
                    except Exception: pass
                    
                    try:
                        cursor.execute("SELECT term, datetime((u.last_visit_time/1000000)-11644473600, 'unixepoch') FROM keyword_search_terms k JOIN urls u ON k.url_id = u.id")
                        searches = [{"terme": r[0], "date": r[1]} for r in cursor.fetchall()]
                        metadata["Termes de recherche"] = len(searches)
                        extra["chromium_searches"] = searches
                    except Exception: pass

                elif fname == "cookies":
                    try:
                        cursor.execute("SELECT host_key, name, value, path, is_secure, is_httponly, datetime((expires_utc/1000000)-11644473600, 'unixepoch') FROM cookies")
                        cookies = [{"host": r[0], "name": r[1], "valeur": r[2], "secure": r[4], "httponly": r[5], "expire": r[6]} for r in cursor.fetchall()]
                        metadata["Cookies (SQLite)"] = len(cookies)
                        extra["chromium_cookies"] = cookies
                    except Exception: pass

                elif fname == "login data":
                    try:
                        cursor.execute("SELECT origin_url, username_value, password_value FROM logins LIMIT 500")
                        logins = []
                        for r in cursor.fetchall():
                            has_pass = "Oui (Chiffré DPAPI/OS Crypt)" if r[2] else "Non"
                            logins.append({"url": r[0], "utilisateur": r[1], "mot_de_passe": has_pass})
                        metadata["Identifiants (Logins)"] = len(logins)
                        extra["chromium_logins"] = logins
                    except Exception: pass

                elif fname == "web data":
                    try:
                        cursor.execute("SELECT name, value, count FROM autofill LIMIT 500")
                        autofill = [{"champ": r[0], "valeur": r[1], "utilisation": r[2]} for r in cursor.fetchall()]
                        metadata["Champs autofill"] = len(autofill)
                        extra["chromium_autofill"] = autofill
                    except Exception: pass
                    
                    try:
                        cursor.execute("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
                        cc = [{"nom": r[0], "expire": f"{r[1]}/{r[2]}", "chiffre": "Oui (DPAPI)" if r[3] else "Non"} for r in cursor.fetchall()]
                        if cc:
                            metadata["Cartes Bancaires"] = f"{len(cc)} trouvée(s) (Chiffré)"
                            extra["chromium_creditcards"] = cc
                    except Exception: pass

                conn.close()

        except sqlite3.OperationalError as e:
            logger.warning(f"Base de données verrouillée ou invalide : {e}")
            return None
        except sqlite3.Error as e:
            logger.error(f"[Chromium] Erreur SQLite : {e}")
            return None
        except Exception as e:
            logger.error(f"[Chromium] Erreur parsing : {e}")
            return None

        return FindingModel(
            type="chromium_artifacts",
            file=filepath,
            metadata=metadata,
            extra=extra
        )
