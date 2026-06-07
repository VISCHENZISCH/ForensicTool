"""Analyzers Firefox — historique et cookies depuis les bases SQLite."""
from __future__ import annotations
import os
import sqlite3
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("firefox")

_HISTORY_SQL = """
    SELECT url, datetime(last_visit_date / 1000000, 'unixepoch')
    FROM   moz_places
    JOIN   moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
    WHERE  visit_count > 0
    ORDER  BY last_visit_date DESC
    LIMIT  500
"""
_COOKIES_SQL = "SELECT name, value, host FROM moz_cookies"


def _connect_ro(db_path: str) -> sqlite3.Connection:
    """Ouvre la base en lecture seule pour éviter tout risque de corruption."""
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


class FirefoxHistoryAnalyzer(BaseAnalyzer):
    """Extrait l'historique de navigation depuis places.sqlite."""
    name = "firefox_history"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False  # Activé uniquement via --fh

    def analyze(self, path: str) -> FindingModel | None:
        try:
            conn   = _connect_ro(path)
            rows   = conn.execute(_HISTORY_SQL).fetchall()
            conn.close()
            entries = [{"url": r[0], "date": r[1]} for r in rows]
            return FindingModel(
                type="firefox_history",
                file=os.path.abspath(path),
                metadata={"total_entrées": len(entries)},
                extra={"entries": entries},
            )
        except Exception as exc:
            log.error("Erreur Historique Firefox '%s' : %s", os.path.basename(path), exc)
            return None


class FirefoxCookiesAnalyzer(BaseAnalyzer):
    """Extrait les cookies depuis cookies.sqlite."""
    name = "firefox_cookies"
    supported_extensions = ()

    def can_handle(self, path: str) -> bool:
        return False  # Activé uniquement via --fc

    def analyze(self, path: str) -> FindingModel | None:
        try:
            conn   = _connect_ro(path)
            rows   = conn.execute(_COOKIES_SQL).fetchall()
            conn.close()
            entries = [{"name": r[0], "value": r[1], "host": r[2]} for r in rows]
            return FindingModel(
                type="firefox_cookies",
                file=os.path.abspath(path),
                metadata={"total_cookies": len(entries)},
                extra={"entries": entries},
            )
        except Exception as exc:
            log.error("Erreur Cookies Firefox '%s' : %s", os.path.basename(path), exc)
            return None
