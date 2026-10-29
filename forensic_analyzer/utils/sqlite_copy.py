"""Lecture d'une base SQLite de preuve sans jamais toucher au dossier des preuves.

Même en `mode=ro`, SQLite crée le fichier `-shm` à côté d'une base WAL, et une URI
construite avec le chemin brut est détournée par un `?` ou un `#` dans un nom de dossier
(`profil?mode=rwc#/places.sqlite` ouvre et crée `profil`). La base et ses journaux sont
donc copiés dans un dossier temporaire privé, et c'est la copie qui est ouverte.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
import weakref


class _CopyConnection(sqlite3.Connection):
    """Connexion dont la fermeture supprime la copie temporaire."""

    def close(self) -> None:
        super().close()
        self._cleanup()


def connect_copy(db_path: str) -> sqlite3.Connection:
    workdir = tempfile.mkdtemp(prefix="fa-sqlite-")
    copy = os.path.join(workdir, "db.sqlite")
    try:
        shutil.copyfile(db_path, copy)
        # Le WAL et le journal contiennent des transactions pas encore reportées dans la base
        for suffix in ("-wal", "-journal"):
            if os.path.isfile(db_path + suffix):
                shutil.copyfile(db_path + suffix, copy + suffix)
        conn = sqlite3.connect(copy, factory=_CopyConnection)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    conn._cleanup = weakref.finalize(conn, shutil.rmtree, workdir, True)
    return conn
