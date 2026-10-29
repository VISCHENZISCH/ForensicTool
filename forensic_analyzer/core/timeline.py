"""Chronologie consolidée : fusion des événements concordants et niveau de confiance.

Deux événements de sources différentes, proches dans le temps et partageant un élément
significatif (unité, utilisateur, terminal, fichier, IP...), décrivent le même fait.
Confiance : « élevée » = au moins deux sources concordantes, « moyenne » = une seule source,
« faible » = horodatage peu fiable (ex : date de modification d'un fichier).
"""
from __future__ import annotations

import datetime
import re
import unicodedata

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.@/-]*[a-z0-9]")
# Mots trop génériques pour prouver que deux événements décrivent le même fait
_STOPWORDS = {
    "session", "opened", "closed", "user", "for", "by", "the", "sur", "via", "depuis", "de", "du", "des",
    "started", "stopped", "starting", "stopping", "service", "service_start", "service_stop", "system",
    "login", "logon", "authentification", "demarrage", "systemd", "pam_unix", "uid", "unit", "unite",
    "creation", "modification", "activation", "execution", "dev", "on", "to", "and", "et", "le", "la",
}
LOW_RELIABILITY = {"unit_modified"}


def _fold(text: str) -> str:
    """Minuscules sans accents : « Création » et « creation » donnent le même jeton."""
    return "".join(c for c in unicodedata.normalize("NFD", text.lower()) if unicodedata.category(c) != "Mn")  # mtime d'un fichier : falsifiable (timestomping)


def parse_ts(ts: str) -> datetime.datetime | None:
    """ISO 8601 → datetime UTC (un horodatage sans fuseau est supposé UTC)."""
    if not ts:
        return None
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _tokens(event: dict) -> set[str]:
    text = _fold(f"{event.get('description', '')} {event.get('details', '')}")
    tokens = set()
    for tok in _TOKEN.findall(text):
        tok = re.sub(r"\.(service|timer|socket)$", "", tok).removeprefix("/dev/")
        # Un chemin ou un nom composé partage aussi ses parties (/usr/.../sysupdate, systemd-sysupdate)
        variants = {tok, tok.rsplit("/", 1)[-1], *tok.rsplit("/", 1)[-1].split("-")}
        tokens.update(v for v in variants if v not in _STOPWORDS and not v.isdigit() and len(v) > 2)
    return tokens


def consolidate(events: list[dict], window: float = 2.0) -> list[dict]:
    """
    Regroupe les événements concordants en faits datés, triés chronologiquement.

    Chaque fait : timestamp, description, sources, confiance et événements d'origine.
    """
    timed = []
    for e in events:
        dt = parse_ts(e.get("timestamp", ""))
        if dt:
            timed.append((dt, _tokens(e), e))
    timed.sort(key=lambda t: t[0])

    # Regroupement ancre sur le premier événement de chaque fait (pas de fusion de proche en proche)
    clusters: list[list[tuple]] = []
    for item in timed:
        dt, tokens, event = item
        best, best_overlap = None, 0
        for cluster in reversed(clusters):
            if (dt - cluster[0][0]).total_seconds() > window:
                break
            if any(m[2].get("source") == event.get("source") for m in cluster):
                continue  # une seule observation par source dans un fait
            overlap = len(tokens & set().union(*(m[1] for m in cluster)))
            if overlap > best_overlap:
                best, best_overlap = cluster, overlap
        if best is not None:
            best.append(item)
        else:
            clusters.append([item])

    facts = []
    for members in clusters:
        sources = sorted({m[2].get("source", "") for m in members})
        if len(sources) >= 2:
            confidence = "élevée"
        elif all(m[2].get("event_type") in LOW_RELIABILITY for m in members):
            confidence = "faible"
        else:
            confidence = "moyenne"
        main = members[0][2]  # premier observateur du fait
        facts.append({
            "timestamp": members[0][0].isoformat(),
            "description": main.get("description", ""),
            "sources": sources,
            "confidence": confidence,
            "events": [m[2] for m in members],
        })
    facts.sort(key=lambda f: f["timestamp"])
    return facts
