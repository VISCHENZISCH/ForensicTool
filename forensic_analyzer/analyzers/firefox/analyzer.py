"""Analyzers Firefox — historique et cookies depuis les bases SQLite."""
from __future__ import annotations

import os
import sqlite3

from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("firefox")

_HISTORY_SQL = """
    SELECT p.url, p.title, p.visit_count, 
           datetime(h.visit_date / 1000000, 'unixepoch') as visit_time, 
           h.visit_type
    FROM   moz_places p
    JOIN   moz_historyvisits h ON p.id = h.place_id
    ORDER  BY h.visit_date DESC
    LIMIT  2000
"""

_INPUT_HISTORY_SQL = "SELECT input, use_count FROM moz_inputhistory ORDER BY use_count DESC"

_BOOKMARKS_SQL = """
    SELECT b.title, p.url, datetime(b.dateAdded / 1000000, 'unixepoch')
    FROM moz_bookmarks b
    JOIN moz_places p ON b.fk = p.id
    WHERE p.url IS NOT NULL
"""

_DOWNLOADS_SQL = """
    SELECT p.url, a.content, datetime(a.dateAdded / 1000000, 'unixepoch')
    FROM moz_annos a
    JOIN moz_places p ON a.place_id = p.id
    JOIN moz_anno_attributes n ON a.anno_attribute_id = n.id
    WHERE n.name = 'downloads/destinationFileURI'
"""

_COOKIES_SQL = """
    SELECT name, value, host, path, 
           datetime(expiry, 'unixepoch') as expiry_date, 
           datetime(lastAccessed / 1000000, 'unixepoch') as last_accessed, 
           isSecure, isHttpOnly, sameSite
    FROM moz_cookies
"""

def _connect_ro(db_path: str) -> sqlite3.Connection:
    """Ouvre la base en lecture seule pour éviter tout risque de corruption."""
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

class FirefoxHistoryAnalyzer(BaseAnalyzer):
    """Extraction et Analyse de la base places.sqlite de Firefox."""
    name = "firefox_places"
    supported_extensions = ('.sqlite',)

    def can_handle(self, path: str) -> bool:
        return os.path.basename(path).lower() == "places.sqlite"

    def analyze(self, path: str) -> FindingModel | None:
        try:
            conn = _connect_ro(path)
            
            # 1. Historique & Visites
            try:
                hist_rows = conn.execute(_HISTORY_SQL).fetchall()
            except: hist_rows = []
            
            # 2. Input History (Recherches)
            try:
                input_rows = conn.execute(_INPUT_HISTORY_SQL).fetchall()
            except: input_rows = []
            
            # 3. Bookmarks
            try:
                book_rows = conn.execute(_BOOKMARKS_SQL).fetchall()
            except: book_rows = []
            
            # 4. Téléchargements
            try:
                down_rows = conn.execute(_DOWNLOADS_SQL).fetchall()
            except: down_rows = []
            
            conn.close()
            
            # Traitement des données et détection de suspects
            import re
            suspicious_patterns = re.compile(r'(\.onion\b|pastebin\.com|mega\.nz|anonfiles|gofile\.io|t\.me|protonmail|hackforums)', re.IGNORECASE)
            
            suspects = set()
            entries = []
            for r in hist_rows:
                url, title, count, date, vtype = r
                entries.append({"url": url, "title": title, "count": count, "date": date, "type": vtype})
                if url and suspicious_patterns.search(url):
                    suspects.add(url)
                    
            inputs = [{"input": r[0], "count": r[1]} for r in input_rows]
            bookmarks = [{"title": r[0], "url": r[1], "date": r[2]} for r in book_rows]
            downloads = [{"url": r[0], "dest": r[1], "date": r[2]} for r in down_rows]
            
            metadata = {
                "Visites (moz_historyvisits)": str(len(entries)),
                "Mots-Clés (moz_inputhistory)": str(len(inputs)),
                "Favoris (Bookmarks)": str(len(bookmarks)),
                "Téléchargements": str(len(downloads))
            }
            
            if suspects:
                metadata["Sites Suspects (Darkweb/Paste)"] = " | ".join(list(suspects)[:5]) + ("..." if len(suspects)>5 else "")
                
            return FindingModel(
                type="firefox_places",
                file=os.path.abspath(path),
                metadata=metadata,
                extra={
                    "history": entries,
                    "inputs": inputs,
                    "bookmarks": bookmarks,
                    "downloads": downloads,
                    "suspects": list(suspects)
                }
            )
        except Exception as exc:
            log.error("Erreur Firefox DB '%s' : %s", os.path.basename(path), exc)
            return None


class FirefoxCookiesAnalyzer(BaseAnalyzer):
    """Extrait les cookies depuis cookies.sqlite."""
    name = "firefox_cookies"
    supported_extensions = ('.sqlite',)

    def can_handle(self, path: str) -> bool:
        return os.path.basename(path).lower() == "cookies.sqlite"

    def analyze(self, path: str) -> FindingModel | None:
        try:
            conn = _connect_ro(path)
            try:
                rows = conn.execute(_COOKIES_SQL).fetchall()
            except: rows = []
            conn.close()
            
            import re
            import base64
            from collections import defaultdict
            
            b64_pat = re.compile(r'^(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
            tracking_pat = re.compile(r'^(_ga|_gid|_fbp|_pk_.*|fr|tr|uid|IDE|GPS|PREF|VISITOR_INFO.*)$', re.IGNORECASE)
            
            domains = defaultdict(list)
            tracking_cookies = 0
            b64_decoded = 0
            secure_count = 0
            
            for r in rows:
                name, val, host, c_path, expiry, last_acc, is_sec, is_http, s_site = r
                
                # Check base64
                decoded_val = None
                if b64_pat.match(val):
                    try:
                        dec = base64.b64decode(val).decode('utf-8', 'ignore')
                        if len(dec) > 5 and re.match(r'^[\x20-\x7E\r\n\t]+$', dec):
                            decoded_val = dec
                            b64_decoded += 1
                    except: pass
                
                # Tracking
                is_tracking = bool(tracking_pat.match(name))
                if is_tracking: tracking_cookies += 1
                
                if is_sec: secure_count += 1
                
                cookie_obj = {
                    "name": name,
                    "value": val,
                    "path": c_path,
                    "expiry": expiry,
                    "last_accessed": last_acc,
                    "flags": {
                        "isSecure": bool(is_sec),
                        "isHttpOnly": bool(is_http),
                        "sameSite": s_site
                    },
                    "is_tracking": is_tracking,
                    "decoded_value": decoded_val
                }
                domains[host].append(cookie_obj)
            
            metadata = {
                "Total Cookies": str(len(rows)),
                "Domaines Uniques": str(len(domains)),
                "Cookies de Tracking": str(tracking_cookies),
                "Cookies Sécurisés (HTTPS)": str(secure_count),
                "Valeurs Base64 Décodées": str(b64_decoded)
            }
            
            return FindingModel(
                type="firefox_cookies",
                file=os.path.abspath(path),
                metadata=metadata,
                extra={"domains": dict(domains)}
            )
        except Exception as exc:
            log.error("Erreur Cookies Firefox '%s' : %s", os.path.basename(path), exc)
            return None
