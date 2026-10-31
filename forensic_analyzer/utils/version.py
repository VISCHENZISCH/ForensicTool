"""Identité de l'outil inscrite dans chaque rapport : version et commit exacts.

Le commit est lu dans .git sans lancer git : un dépôt git présent parmi les preuves ne doit
jamais faire exécuter quoi que ce soit (voir core/updater.py).
"""
from __future__ import annotations

import os
from functools import lru_cache

from forensic_analyzer import __version__

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@lru_cache(maxsize=1)
def git_commit() -> str | None:
    """Commit court de l'outil, ou None hors dépôt git (installation par pip)."""
    git_dir = os.path.join(_REPO, ".git")
    try:
        with open(os.path.join(git_dir, "HEAD"), encoding="utf-8") as fh:
            head = fh.read().strip()
        if not head.startswith("ref: "):
            return head[:7] or None          # HEAD détachée
        ref = head[5:]
        ref_file = os.path.join(git_dir, *ref.split("/"))
        if os.path.isfile(ref_file):
            with open(ref_file, encoding="utf-8") as fh:
                return fh.read().strip()[:7] or None
        with open(os.path.join(git_dir, "packed-refs"), encoding="utf-8") as fh:
            for line in fh:
                sha, _, name = line.strip().partition(" ")
                if name == ref:
                    return sha[:7]
    except OSError:
        pass
    return None


def tool_identity() -> str:
    commit = git_commit()
    return f"Forensic Analyzer {__version__}" + (f" (commit {commit})" if commit else "")
