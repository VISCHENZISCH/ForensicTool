"""Évaluation d'incident dérivée des constats : verdict, matrice ATT&CK, impact, actions et pistes.

Rien n'est inventé : chaque phrase produite ici découle d'un champ des constats (gravité, alertes,
techniques MITRE, indicateurs, limites) et renvoie aux constats qui la justifient. Les modèles
suivis : NIST SP 800-61 (endiguement, éradication, rétablissement), SANS Incident Handler's
Handbook, RFC 3227 (ordre de volatilité) et la matrice MITRE ATT&CK Enterprise (ordre des tactiques).
Les vues sont génériques : une nouvelle détection ou technique est exploitée sans code dédié.
"""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field

from forensic_analyzer.core import iocs as ioc_mod
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import SEVERITIES, FindingModel, ReportModel

# Vues transverses : elles agrègent les autres constats, on ne les compte pas deux fois
TRANSVERSE = {"timeline", "correlation", "evidence_integrity"}
HIGH = ("critique", "élevé")
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Tactiques ATT&CK Enterprise dans l'ordre de la chaîne d'attaque, avec les libellés qu'emploient
# core/mitre.py et les modules (français ou anglais, sans accents ni casse)
TACTICS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("TA0043", "Reconnaissance", ("reconnaissance",)),
    ("TA0042", "Développement de ressources", ("developpement de ressources", "ressources", "resource development")),
    ("TA0001", "Accès initial", ("acces initial", "acces", "initial access")),
    ("TA0002", "Exécution", ("execution",)),
    ("TA0003", "Persistance", ("persistance", "persistence")),
    ("TA0004", "Élévation de privilèges", ("elevation", "elevation de privileges", "escalade", "privilege escalation")),
    ("TA0005", "Évasion des défenses", ("evasion", "evasion des defenses", "furtivite", "defense evasion", "stealth")),
    ("TA0006", "Accès aux identifiants", ("acces aux identifiants", "identifiants", "credential access")),
    ("TA0007", "Découverte", ("decouverte", "discovery")),
    ("TA0008", "Mouvement latéral", ("mouvement lateral", "deplacement lateral", "lateral movement")),
    ("TA0009", "Collecte", ("collecte", "collection")),
    ("TA0011", "Commande et contrôle", ("commande et controle", "c2", "command and control")),
    ("TA0010", "Exfiltration", ("exfiltration",)),
    ("TA0040", "Impact", ("impact",)),
)
OTHER_TACTIC = ("", "Non classée")
_ALIASES = {alias: tid for tid, _, aliases in TACTICS for alias in aliases}
_TACTIC_NAME = {tid: name for tid, name, _ in TACTICS}

# Modules qui examinent un hôte : une gravité élevée y signale un hôte compromis
_HOST_TYPES = {
    "memory",
    "disk",
    "evtx",
    "registry",
    "prefetch",
    "lnk_shortcut",
    "linux_artifacts",
    "log_analysis",
    "elf_analysis",
    "malware_analysis",
    "pe_analysis",
    "webshell_analysis",
    "ransomware_impact",
    "yara",
}
_HOST_LOG_TYPES = {"evtx", "log_analysis", "linux_artifacts"}
_NETWORK_TYPES = {"pcap", "ids_alerts"}
MAX_REFS = 5  # constats cités par piste : la liste complète est dans les constats détaillés


def fold(text: str) -> str:
    """Minuscules sans accents, pour comparer des libellés libres."""
    return "".join(c for c in unicodedata.normalize("NFD", str(text).lower()) if unicodedata.category(c) != "Mn")


def tactic_ids(label: str) -> list[str]:
    """« Évasion / Élévation » -> ['TA0005', 'TA0004'] ; un libellé inconnu -> []."""
    return [_ALIASES[part] for part in (fold(p).strip() for p in re.split(r"[/,;]", label or "")) if part in _ALIASES]


def techniques_of(finding: FindingModel) -> dict[str, dict]:
    """Techniques d'un constat, qu'elles soient en dicts (contrat describe), en ID ou en texte."""
    found: dict[str, dict] = {}
    for item in (finding.extra or {}).get("mitre", []) or []:
        if isinstance(item, dict) and item.get("id"):
            found[str(item["id"])] = {"id": str(item["id"]), "name": item.get("name", ""), "tactic": item.get("tactic", "")}
        elif isinstance(item, str):
            found.setdefault(item, {"id": item, "name": "", "tactic": ""})
    text = finding.metadata.get("MITRE ATT&CK")
    if isinstance(text, str):
        for tid in _TECHNIQUE_ID.findall(text):
            found.setdefault(tid, {"id": tid, "name": "", "tactic": ""})
    for tid, entry in found.items():  # le référentiel complète ce que le module n'a pas renseigné
        name, tactic = mitre.TECHNIQUES.get(tid, (entry["name"] or "Technique non référencée", entry["tactic"]))
        entry["name"] = entry["name"] or name
        entry["tactic"] = entry["tactic"] or tactic
    return found


def severity_rank(severity: str | None) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else -1


def module_label(finding_type: str) -> str:
    from forensic_analyzer.output.ui import MODULE_NAMES  # import tardif : ui importe le terminal

    return MODULE_NAMES.get(finding_type, finding_type.replace("_", " ").capitalize())


# ── Matrice ATT&CK ───────────────────────────────────────────────────────────


@dataclass
class TechniqueHit:
    id: str
    name: str
    findings: list[int] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    severity: str | None = None


def attack_matrix(findings: list[FindingModel]) -> list[tuple[str, str, list[TechniqueHit]]]:
    """(id de tactique, libellé, techniques observées) pour chaque tactique, dans l'ordre de la chaîne."""
    hits: dict[tuple[str, str], TechniqueHit] = {}
    for i, f in enumerate(findings):
        if f.type in TRANSVERSE:
            continue
        for tid, t in techniques_of(f).items():
            for tactic in tactic_ids(t["tactic"]) or [OTHER_TACTIC[0]]:
                hit = hits.setdefault((tactic, tid), TechniqueHit(tid, t["name"]))
                hit.findings.append(i)
                hit.sources.add(f.type)
                if severity_rank(f.severity) > severity_rank(hit.severity):
                    hit.severity = f.severity
    columns = [*((tid, name) for tid, name, _ in TACTICS), OTHER_TACTIC]
    matrix = []
    for tactic, name in columns:
        cells = sorted((h for (ta, _), h in hits.items() if ta == tactic), key=lambda h: (-len(h.findings), h.id))
        if cells or tactic:  # « Non classée » n'apparaît que si elle sert
            matrix.append((tactic, name, cells))
    return matrix


# ── Contexte commun aux vues ─────────────────────────────────────────────────


@dataclass
class Context:
    report: ReportModel
    graded: list[int]  # constats critique / élevé (hors vues transverses)
    medium: list[int]
    tactics: dict[str, list[int]]  # tactique observée -> constats
    types: set[str]
    shared: list[ioc_mod.IOC]
    iocs: list[ioc_mod.IOC]
    strong_facts: list[dict]
    period: tuple[str, str] | None
    altered: bool
    limits: int

    def refs(self, *types: str, high_only: bool = True) -> list[int]:
        pool = self.graded if high_only else range(len(self.report.findings))
        return [i for i in pool if self.report.findings[i].type in types]


def build_context(report: ReportModel, found: list[ioc_mod.IOC] | None = None) -> Context:
    findings = report.findings
    real = [(i, f) for i, f in enumerate(findings) if f.type not in TRANSVERSE]
    tactics: dict[str, list[int]] = {}
    for tactic, _, cells in attack_matrix(findings):
        refs = sorted({i for h in cells for i in h.findings})
        if refs:
            tactics[tactic] = refs
    if found is None:
        found = ioc_mod.collect([f for f in findings if f.type != "timeline"])
    timeline = next((f for f in findings if f.type == "timeline"), None)
    facts = list((timeline.extra.get("facts") or []) if timeline else [])
    stamps = sorted(str(fact.get("timestamp")) for fact in facts if fact.get("timestamp"))
    return Context(
        report=report,
        graded=[i for i, f in real if f.severity in HIGH],
        medium=[i for i, f in real if f.severity == "moyen"],
        tactics=tactics,
        types={f.type for _, f in real},
        shared=[i for i in found if len(i.sources) > 1],
        iocs=found,
        strong_facts=[fact for fact in facts if fact.get("confidence") == "élevée"],
        period=(stamps[0], stamps[-1]) if stamps else None,
        altered=any(r.changed_during_analysis for r in report.evidence)
        or any(f.type == "evidence_integrity" and f.severity == "critique" for f in findings),
        limits=len(report.analysis_errors) + len(report.skipped_files) + sum(len(f.incomplete) for f in findings),
    )


# ── Synthèse direction ───────────────────────────────────────────────────────


@dataclass
class Verdict:
    level: str  # alteree, confirmee, probable, suspecte, aucune
    title: str
    sentence: str
    confidence: str  # élevée, moyenne, faible
    rationale: str
    severity: str | None


def _confidence(ctx: Context) -> tuple[str, str]:
    """Confiance du verdict : corroboration entre sources indépendantes, sinon une seule source."""
    modules = {ctx.report.findings[i].type for i in ctx.graded}
    reasons = []
    if ctx.shared:
        reasons.append(f"{len(ctx.shared)} indicateur(s) vu(s) par plusieurs sources")
    if ctx.strong_facts:
        reasons.append(f"{len(ctx.strong_facts)} fait(s) daté(s) confirmé(s) par au moins deux sources")
    if len(modules) > 1:
        reasons.append(f"alertes de {len(modules)} modules distincts")
    if reasons:
        return "élevée", "Corroboration : " + ", ".join(reasons) + "."
    if ctx.graded:
        return "moyenne", "Une seule source étaye la menace : à confirmer par une seconde source."
    if ctx.limits:
        return "faible", f"{ctx.limits} limite(s) d'analyse : l'absence de détection ne prouve pas l'absence d'activité."
    return "moyenne", "Aucune alerte des modules exécutés ; seuls les artefacts fournis sont couverts."


def verdict(report: ReportModel, ctx: Context | None = None) -> Verdict:
    ctx = ctx or build_context(report)
    findings = report.findings
    top = max((findings[i].severity for i in ctx.graded + ctx.medium), key=severity_rank, default=None)
    confidence, rationale = _confidence(ctx)
    tactics = [_TACTIC_NAME[t] for t, _, _ in TACTICS if t in ctx.tactics]
    period = f" Activité datée du {utc(ctx.period[0])} au {utc(ctx.period[1])}." if ctx.period else ""
    behaviours = f" Tactiques observées : {', '.join(tactics)}." if tactics else ""
    if ctx.altered:
        return Verdict(
            "alteree",
            "Preuve altérée",
            "L'intégrité d'au moins une preuve n'est pas garantie : ses conclusions ne sont pas opposables.",
            "faible",
            "Empreinte SHA-256 différente de celle prise à la collecte (voir Périmètre).",
            "critique",
        )
    if ctx.graded:
        crit = sum(findings[i].severity == "critique" for i in ctx.graded)
        names = ", ".join(sorted({module_label(findings[i].type) for i in ctx.graded})[:4])
        level, title = (
            ("confirmee", "Compromission confirmée") if confidence == "élevée" else ("probable", "Compromission probable")
        )
        sentence = f"{crit} constat(s) critique(s) et {len(ctx.graded) - crit} de gravité élevée ({names})." + behaviours + period
        return Verdict(level, title, sentence, confidence, rationale, top)
    if ctx.medium:
        sentence = f"{len(ctx.medium)} constat(s) de gravité moyenne, sans menace élevée à ce stade." + behaviours + period
        return Verdict("suspecte", "Activité suspecte à qualifier", sentence, "faible", rationale, top)
    return Verdict(
        "aucune",
        "Aucune compromission mise en évidence",
        "Les modules exécutés n'ont relevé aucune menace sur les preuves fournies.",
        confidence,
        rationale,
        top,
    )


def utc(timestamp: str) -> str:
    return str(timestamp)[:19].replace("T", " ") + " UTC"


# ── Signaux : impact, actions immédiates, prochaines étapes ──────────────────


@dataclass
class Signal:
    key: str
    test: Callable[[Context], list[int] | bool]
    impact: str = ""
    action: str = ""  # action immédiate (endiguement)
    steps: tuple[tuple[int, str], ...] = ()  # (priorité 1 à 3, piste d'enquête)
    reason: str = ""


def _alert_mentions(ctx: Context, *words: str) -> list[int]:
    """Constats dont une alerte (clé ou valeur) cite l'un des mots : signal générique, multi-modules."""
    hits = []
    for i, f in enumerate(ctx.report.findings):
        if f.type in TRANSVERSE:
            continue
        text = fold(" ".join(f"{k} {v}" for k, v in f.metadata.items() if str(k).startswith("[ALERTE]")))
        if text and re.search(r"\b(?:" + "|".join(map(re.escape, words)) + ")", text):
            hits.append(i)
    return hits


def _extra_has(ctx: Context, key: str) -> list[int]:
    """Constats dont les données détaillées contiennent une liste ou un dict non vide sous `key`."""
    return [i for i, f in enumerate(ctx.report.findings) if _deep_has(f.extra or {}, key, 0)]


_MAX_DEPTH = 2


def _deep_has(data: dict, key: str, depth: int) -> bool:
    value = data.get(key)
    if value and isinstance(value, (list, dict)):
        return True
    return depth < _MAX_DEPTH and any(isinstance(v, dict) and _deep_has(v, key, depth + 1) for v in data.values())


def _tactic(*ids: str) -> Callable[[Context], list[int]]:
    return lambda ctx: sorted({i for t in ids for i in ctx.tactics.get(t, [])})


def _any(*tests: Callable[[Context], list[int] | bool]) -> Callable[[Context], list[int]]:
    def run(ctx: Context) -> list[int]:
        out: set[int] = set()
        for test in tests:
            res = test(ctx)
            out.update(res if isinstance(res, list) else [])
        return sorted(out)

    return run


def _host_compromised(ctx: Context) -> list[int]:
    return [i for i in ctx.graded if ctx.report.findings[i].type in _HOST_TYPES]


def _external_iocs(ctx: Context) -> list[int]:
    kinds = {"ipv4", "domain", "url"}
    return sorted({i for ioc in ctx.shared if ioc.kind in kinds for i in _finding_refs(ctx, ioc)})


def _finding_refs(ctx: Context, ioc: ioc_mod.IOC) -> list[int]:
    sources = ioc.sources
    return [i for i, f in enumerate(ctx.report.findings) if f.type in sources][:MAX_REFS]


SIGNALS: tuple[Signal, ...] = (
    Signal(
        "integrite",
        lambda c: c.altered,
        action="Geler les preuves et réacquérir une copie depuis le support d'origine.",
        steps=((1, "Réacquérir la preuve altérée et consigner l'écart dans la chaîne de possession."),),
        reason="empreinte SHA-256 différente après analyse",
    ),
    Signal(
        "rancongiciel",
        _any(_tactic("TA0040"), lambda c: c.refs("ransomware_impact")),
        impact="Chiffrement ou destruction de données : disponibilité du système d'information atteinte.",
        action="Isoler du réseau les hôtes touchés sans les éteindre ; déconnecter les sauvegardes.",
        steps=((1, "Délimiter le périmètre chiffré et vérifier l'intégrité des sauvegardes avant toute restauration."),),
        reason="technique d'impact ou chiffrement de masse observé",
    ),
    Signal(
        "exfiltration",
        _any(_tactic("TA0010"), lambda c: _extra_has(c, "exfiltration"), lambda c: _alert_mentions(c, "exfiltr")),
        impact="Exfiltration de données : confidentialité atteinte.",
        action="Bloquer les destinations d'exfiltration identifiées (pare-feu, proxy).",
        steps=(
            (
                1,
                "Qualifier les données sorties (volume, nature, données personnelles) et évaluer l'obligation "
                "de notification (RGPD art. 33 : 72 h).",
            ),
        ),
        reason="exfiltration observée",
    ),
    Signal(
        "identifiants",
        _any(
            _tactic("TA0006"),
            lambda c: _extra_has(c, "credentials"),
            lambda c: _alert_mentions(c, "identifiant", "mot de passe", "credential", "brute-force", "brute force"),
        ),
        impact="Identifiants exposés ou compromis : l'attaquant peut revenir par un accès légitime.",
        action="Réinitialiser les identifiants exposés et révoquer sessions, jetons et clés SSH associés.",
        steps=((1, "Rechercher la réutilisation de ces comptes dans les journaux d'authentification de tout le parc."),),
        reason="identifiants volés, en clair ou attaqués",
    ),
    Signal(
        "webshell",
        _any(lambda c: c.refs("webshell_analysis"), lambda c: _alert_mentions(c, "webshell")),
        impact="Exécution de commandes à distance sur le serveur web.",
        action="Retirer le serveur web exposé du réseau et conserver le webshell comme preuve.",
        steps=((1, "Rechercher le vecteur d'intrusion et d'autres webshells (journaux d'accès depuis la première requête)."),),
        reason="webshell détecté ou appelé",
    ),
    Signal(
        "c2",
        _any(_tactic("TA0011"), lambda c: _extra_has(c, "c2_beacons") and _alert_mentions(c, "c2", "balise", "beacon")),
        impact="Canal de commande et contrôle : l'attaquant pilote la machine à distance.",
        action="Bloquer en sortie les adresses et domaines de commande et contrôle (pare-feu, proxy, DNS).",
        steps=((1, "Rechercher ces destinations dans les journaux pare-feu, proxy et DNS de tout le parc."),),
        reason="communication de commande et contrôle",
    ),
    Signal(
        "persistance",
        _tactic("TA0003"),
        impact="Accès persistant de l'attaquant, qui survit au redémarrage.",
        steps=((1, "Inventorier chaque mécanisme de persistance avant nettoyage ; privilégier la réinstallation de l'hôte."),),
        reason="technique de persistance",
    ),
    Signal(
        "lateral",
        _any(_tactic("TA0008"), lambda c: _extra_has(c, "smb_lateral")),
        impact="Propagation vers d'autres machines du réseau.",
        steps=((1, "Étendre le périmètre aux hôtes cibles du mouvement latéral et les acquérir."),),
        reason="mouvement latéral",
    ),
    Signal(
        "privileges",
        _tactic("TA0004"),
        impact="Privilèges élevés obtenus (administrateur ou root).",
        steps=((2, "Auditer les comptes à privilèges, groupes d'administration et règles sudo."),),
        reason="élévation de privilèges",
    ),
    Signal(
        "evasion",
        _tactic("TA0005"),
        steps=(
            (2, "Vérifier les journaux effacés ou les outils de sécurité désactivés ; recouper avec une source externe (SIEM)."),
        ),
        reason="évasion des défenses",
    ),
    Signal(
        "memoire",
        lambda c: [] if "memory" in c.types else _host_compromised(c),
        steps=((1, "Acquérir la mémoire vive des hôtes compromis avant tout redémarrage (ordre de volatilité, RFC 3227)."),),
        reason="hôte compromis sans image mémoire analysée",
    ),
    Signal(
        "journaux-hote",
        lambda c: [] if c.types & _HOST_LOG_TYPES else _host_compromised(c),
        steps=((2, "Collecter les journaux système et d'authentification de l'hôte (EVTX, auth.log, journald)."),),
        reason="aucun journal d'hôte analysé",
    ),
    Signal(
        "journaux-reseau",
        lambda c: [] if c.types & _NETWORK_TYPES else _tactic("TA0011", "TA0010", "TA0008")(c),
        steps=((2, "Collecter les journaux réseau (pare-feu, proxy, DNS, NetFlow) ou une capture couvrant la période."),),
        reason="activité réseau suspectée sans source réseau",
    ),
    Signal(
        "pivot",
        _external_iocs,
        steps=((2, "Pivoter sur les indicateurs corroborés : recherche EDR / SIEM sur l'ensemble du parc."),),
        reason="indicateurs vus par plusieurs sources",
    ),
)


@dataclass
class Step:
    priority: int
    action: str
    reason: str
    refs: list[int]


def _fired(ctx: Context) -> list[tuple[Signal, list[int]]]:
    out = []
    for signal in SIGNALS:
        res = signal.test(ctx)
        if res:
            out.append((signal, res if isinstance(res, list) else []))
    return out


def impacts(ctx: Context) -> list[tuple[str, list[int]]]:
    return [(s.impact, refs[:MAX_REFS]) for s, refs in _fired(ctx) if s.impact]


def immediate_actions(ctx: Context) -> list[tuple[str, list[int]]]:
    return [(s.action, refs[:MAX_REFS]) for s, refs in _fired(ctx) if s.action]


def next_steps(ctx: Context, online: bool = False) -> list[Step]:
    """Pistes d'enquête priorisées (1 = immédiat), chacune justifiée par des constats ou une limite."""
    steps = [Step(p, text, s.reason, refs[:MAX_REFS]) for s, refs in _fired(ctx) for p, text in s.steps]
    report = ctx.report
    timeline = next((f for f in report.findings if f.type == "timeline"), None)
    if timeline and timeline.metadata.get("[ATTENTION] Décalage d'horloge"):
        steps.append(
            Step(
                2, "Documenter le décalage d'horloge et vérifier la synchronisation NTP des sources.", "horloges divergentes", []
            )
        )
    if ctx.limits:
        steps.append(
            Step(
                3,
                f"Traiter les {ctx.limits} limite(s) d'analyse : réanalyser ou collecter autrement les éléments non couverts.",
                "voir Limites de l'analyse",
                [],
            )
        )
    if ctx.iocs and not online:
        steps.append(
            Step(
                3,
                "Enrichir les indicateurs (réputation, renseignement sur la menace) depuis un poste dédié.",
                "analyse hors ligne",
                [],
            )
        )
    steps.append(
        Step(
            3,
            "Conserver preuves et rapport selon la politique de rétention ; consigner chaque transfert.",
            "chaîne de possession",
            [],
        )
    )
    return sorted(steps, key=lambda s: s.priority)


# ── Indicateurs : confiance et fenêtre d'observation ─────────────────────────


@dataclass
class IOCRow:
    kind: str
    value: str
    sources: list[str]
    confidence: str
    first_seen: str
    last_seen: str
    context: str


_TOKEN_SPLIT = re.compile(r"[\s,;()\[\]{}<>\"'|=]+")
_MIN_SOURCES = 2


def _seen_windows(report: ReportModel, values: set[str]) -> dict[str, tuple[str, str]]:
    """Première et dernière apparition de chaque valeur dans la chronologie (une passe, index par jeton)."""
    timeline = next((f for f in report.findings if f.type == "timeline"), None)
    events = (timeline.extra.get("events") or []) if timeline else []
    seen: dict[str, tuple[str, str]] = {}
    for e in events:
        ts = str(e.get("timestamp") or "")
        if not ts:
            continue
        text = " ".join(str(v) for v in e.values() if isinstance(v, str))
        tokens = {t.lower() for t in _TOKEN_SPLIT.split(text) if t}
        tokens |= {os.path.basename(t.rstrip("/")) for t in tokens if "/" in t}
        for tok in tokens & values:
            first, last = seen.get(tok, (ts, ts))
            seen[tok] = (min(first, ts), max(last, ts))
    return seen


def ioc_rows(report: ReportModel, found: list[ioc_mod.IOC]) -> list[IOCRow]:
    """Tableau d'indicateurs exploitable : confiance = corroboration et gravité des constats sources."""
    alerting = {f.type for f in report.findings if f.severity in HIGH and f.type not in TRANSVERSE}
    windows = _seen_windows(report, {i.value.lower() for i in found})
    rows = []
    for i in found:
        if len(i.sources) >= _MIN_SOURCES:
            confidence = "élevée"
        elif i.sources & alerting:
            confidence = "moyenne"
        else:
            confidence = "faible"
        first, last = windows.get(i.value.lower(), ("", ""))
        rows.append(
            IOCRow(
                i.kind,
                i.value,
                sorted(i.sources),
                confidence,
                first,
                last,
                " ; ".join(sorted({o.context for o in i.observations if o.context})),
            )
        )
    rank = {"élevée": 0, "moyenne": 1, "faible": 2}
    return sorted(rows, key=lambda r: (rank[r.confidence], r.kind, r.value))
