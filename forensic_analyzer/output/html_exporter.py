"""Rapport HTML (et base du PDF) au design « documentation » gris, dérivé d'ubuntu-fr.

Contenu imposé, quel que soit le type d'analyse : page de garde avec verdict, synthèse (gravités,
chaîne d'attaque, indicateurs corroborés, alertes par module), périmètre (preuves, empreintes,
intégrité), chronologie consolidée, indicateurs, constats détaillés sans troncature et limites.
Aucune ressource externe : polices embarquées, le rapport s'ouvre hors ligne.
"""
from __future__ import annotations

import base64
import html
import os
from collections import defaultdict
from functools import lru_cache

from forensic_analyzer.core import iocs as ioc_mod
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output.ui import MODULE_NAMES
from forensic_analyzer.utils.exports import export_root, output_path as resolve_output
from forensic_analyzer.utils.logger import get_logger
from forensic_analyzer.utils.network import online_enabled

log = get_logger("html_exporter")

# Vues transverses : rendues dans leurs propres sections, pas parmi les constats
_TRANSVERSE = {"timeline", "correlation", "evidence_integrity"}

_CATEGORIES = [
    ("system", "Système, disque et journaux",
     {"disk", "evtx", "registry", "prefetch", "lnk_shortcut", "log_analysis", "linux_artifacts", "memory"}),
    ("network", "Réseau et web",
     {"pcap", "firefox_history", "firefox_places", "firefox_cookies", "chromium_artifacts", "network_recon", "ids_alerts"}),
    ("malware", "Binaires, scripts et menaces",
     {"pe_analysis", "malware_analysis", "elf_analysis", "webshell_analysis", "yara", "ioc", "carving", "strings"}),
    ("files", "Fichiers et métadonnées", {"pdf", "pdf_analysis", "office_analysis", "image", "gps", "stego", "stego_audio"}),
]
_SECTIONS = [("synthese", "Synthèse"), ("perimetre", "Périmètre et méthode"), ("chronologie", "Chronologie consolidée"),
             ("indicateurs", "Indicateurs de compromission"), ("constats", "Constats détaillés"),
             ("limites", "Limites de l'analyse")]
_MAX_ROWS = 300  # lignes par tableau de données détaillées ; le reste est signalé et figure dans l'export JSON
_PRINT_ROWS = 25  # au-delà, lignes masquées à l'impression (PDF) avec mention du reste
_SYNTH_FACTS = 12  # faits de la chaîne d'attaque repris en synthèse (la chronologie les a tous)
_SYNTH_IOCS = 10
# Données déjà restituées ailleurs (chronologie, graphe) : pas de doublon dans les constats
_SKIP_KEYS = {"events", "facts", "graph", "timeline_events", "timeline"}

_GRAVITES = ("critique", "élevé", "moyen", "faible", "info")
_GRAVITE_LIBELLE = {"critique": "Critique", "élevé": "Élevée", "moyen": "Moyenne", "faible": "Faible", "info": "Info"}
_GRAVITE_CLASSE = {"critique": "critique", "élevé": "eleve", "moyen": "moyen", "faible": "faible", "info": "info"}

# Polices libres (OFL) réduites aux caractères latins : voir output/fonts/OFL-*.txt
_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
_FONTS = (("Inter", 400, "normal", "Inter-Regular"), ("Inter", 400, "italic", "Inter-Italic"),
          ("Inter", 600, "normal", "Inter-SemiBold"), ("Inter", 700, "normal", "Inter-Bold"),
          ("JetBrains Mono", 400, "normal", "JetBrainsMono-Regular"), ("JetBrains Mono", 700, "normal", "JetBrainsMono-Bold"))


@lru_cache(maxsize=1)
def _font_faces() -> str:
    """@font-face en data: URI ; une police absente laisse la place aux polices système."""
    faces = []
    for family, weight, style, name in _FONTS:
        try:
            with open(os.path.join(_FONT_DIR, f"{name}.woff2"), "rb") as fh:
                data = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            continue
        faces.append(f"@font-face {{ font-family:'{family}'; font-weight:{weight}; font-style:{style}; "
                     f"font-display:swap; src:url(data:font/woff2;base64,{data}) format('woff2'); }}")
    return "\n".join(faces)


def get_category(f_type: str) -> str:
    return next((cat for cat, _, types in _CATEGORIES if f_type in types), "other")


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _label(f: FindingModel) -> str:
    return MODULE_NAMES.get(f.type, f.type.replace("_", " ").capitalize())


def _anchor(i: int) -> str:
    return f"constat-{i}"


def _utc(timestamp: str) -> str:
    return timestamp[:19].replace("T", " ") + " UTC"


def _octets(size: int) -> str:
    return f"{size:,}".replace(",", "\u202f")   # espace fine insécable : 1 107 864


def _pill(severity: str | None) -> str:
    if severity not in _GRAVITE_CLASSE:
        return ""
    return f'<span class="gravite g-{_GRAVITE_CLASSE[severity]}">{_GRAVITE_LIBELLE[severity]}</span>'


def _alerts(report: ReportModel) -> list[tuple[int, FindingModel, str, str]]:
    """(index du constat, constat, clé, valeur) de chaque alerte, dans l'ordre des constats."""
    return [(i, f, k, v) for i, f in enumerate(report.findings) for k, v in f.metadata.items()
            if str(k).startswith("[ALERTE]") or "[ALERTE]" in str(v)]


def _kv_table(rows: dict, alert_keys: bool = True) -> str:
    out = []
    for k, v in rows.items():
        alert = alert_keys and (str(k).startswith("[ALERTE]") or "[ALERTE]" in str(v))
        cls = ' class="alerte"' if alert else ""
        out.append(f"<tr{cls}><th scope=\"row\">{_e(k)}</th><td>{_e(v)}</td></tr>")
    return f'<table class="kv">{"".join(out)}</table>' if out else ""


def _table(head: list[str], rows: list[str], cls: str = "") -> str:
    th = "".join(f"<th>{_e(h)}</th>" for h in head)
    return (f'<div class="defile"><table class="{cls}"><thead><tr>{th}</tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table></div>")


def _data_block(key: str, value, depth: int = 0) -> str:
    """Données détaillées d'un constat, rendues quelle que soit leur forme (liste, dictionnaire, texte)."""
    title = key.replace("_", " ").strip().capitalize()
    if value in (None, "", [], {}, ()) or key in _SKIP_KEYS:
        return ""
    if isinstance(value, dict):
        scalars = {k: v for k, v in value.items() if not isinstance(v, (dict, list, tuple, set))}
        nested = {k: v for k, v in value.items() if isinstance(v, (dict, list, tuple, set)) and k not in _SKIP_KEYS}
        body = _kv_table(scalars, alert_keys=False)
        if depth < 2:
            body += "".join(_data_block(k, v, depth + 1) for k, v in nested.items())
        else:
            body += _kv_table({k: v for k, v in nested.items()}, alert_keys=False)
        return f'<h5>{_e(title)}</h5>{body}' if body else ""
    if isinstance(value, (list, tuple, set)):
        items = list(value)
        rest = len(items) - _MAX_ROWS
        items = items[:_MAX_ROWS]
        more = (f'<p class="reste">… {rest} élément(s) de plus, présents dans l\'export JSON.</p>'
                if rest > 0 else "")
        hidden = len(value) - _PRINT_ROWS
        if hidden > 0:
            more += (f'<p class="reste impression">… {hidden} ligne(s) de plus dans le rapport HTML '
                     "et l'export JSON.</p>")

        def cls(n: int) -> str:
            return ' class="surplus"' if n >= _PRINT_ROWS else ""
        if items and all(isinstance(x, dict) for x in items):
            cols = []
            for item in items:
                cols += [c for c in item if c not in cols]
            cols = cols[:10]
            rows = [f"<tr{cls(n)}>" + "".join(f"<td>{_e(item.get(c, ''))}</td>" for c in cols) + "</tr>"
                    for n, item in enumerate(items)]
            table = _table([str(c) for c in cols], rows)
        else:
            table = '<ul class="liste">' + "".join(f"<li{cls(n)}>{_e(x)}</li>" for n, x in enumerate(items)) + "</ul>"
        return f"<h5>{_e(title)} ({len(value)})</h5>{table}{more}"
    return f"<h5>{_e(title)}</h5><p>{_e(value)}</p>"


def _note(kind: str, inner: str) -> str:
    return f'<div class="note {kind}">{inner}</div>'


def _h2(sid: str) -> str:
    return f'<h2 id="{sid}">{_e(dict(_SECTIONS)[sid])}</h2>'


# ── Page de garde ────────────────────────────────────────────────────────────

def _verdict(report: ReportModel) -> tuple[str, str]:
    """(classe de la note, phrase de verdict) à partir des champs severity / incomplete."""
    altered = [f for f in report.findings if f.type == "evidence_integrity" and f.severity == "critique"]
    changed = [r for r in report.evidence if r.changed_during_analysis]
    if altered or changed:
        return "warning", "Preuve altérée : l'intégrité d'au moins une preuve n'est pas garantie (voir Périmètre)."
    for level in ("critique", "élevé"):
        hits = [f for f in report.findings if f.severity == level and f.type != "evidence_integrity"]
        if hits:
            names = ", ".join(f"{_label(f)} ({os.path.basename(f.file)})" for f in hits[:3])
            more = f" et {len(hits) - 3} autre(s)" if len(hits) > 3 else ""
            return "warning", f"Menace de gravité {_GRAVITE_LIBELLE[level].lower()} : {names}{more}."
    if any(f.incomplete for f in report.findings) or report.analysis_errors:
        return "important", "Aucune menace élevée, mais l'analyse est incomplète : voir Limites de l'analyse."
    return "tip", "Aucune menace élevée relevée par les modules exécutés."


def _couverture(report: ReportModel, alerts, found, facts, case: str) -> str:
    counts = {lvl: sum(f.severity == lvl for f in report.findings) for lvl in _GRAVITES}
    top = next((lvl for lvl in _GRAVITES if counts[lvl]), None)
    evidence = len(report.evidence) or sum(1 for f in report.findings if f.type not in _TRANSVERSE)
    shared = sum(len(i.sources) > 1 for i in found)
    cards = [
        ("Gravité maximale", _GRAVITE_LIBELLE.get(top, "Non évaluée"), f"g-{_GRAVITE_CLASSE.get(top, 'info')}"),
        ("Critiques / élevées", f"{counts['critique']} / {counts['élevé']}", ""),
        ("Alertes", str(len(alerts)), ""),
        ("Preuves hachées", str(evidence), ""),
        (f"Indicateurs, dont {shared} corroborés", str(len(found)), ""),
        ("Faits datés", str(len(facts)), ""),
    ]
    tiles = "".join(f'<div class="chiffre {cls}"><span class="valeur">{_e(v)}</span><span class="intitule">{_e(t)}</span></div>'
                    for t, v, cls in cards)
    kind, sentence = _verdict(report)
    return (f'<section class="couverture">'
            f'<p class="surtitre">Rapport d\'investigation numérique</p>'
            f"<h1>{_e(case)}</h1>"
            f'<dl class="meta"><div><dt>Généré le</dt><dd>{_e(_utc(report.timestamp))}</dd></div>'
            f"<div><dt>Outil</dt><dd>{_e(report.tool)}</dd></div>"
            f"<div><dt>Services en ligne</dt><dd>{'activés (--online)' if online_enabled() else 'désactivés'}</dd></div>"
            f"<div><dt>Constats</dt><dd>{sum(1 for f in report.findings if f.type not in _TRANSVERSE)}</dd></div></dl>"
            f'<div class="chiffres">{tiles}</div>'
            + _note(f"{kind} verdict", f"<p><strong>Verdict</strong> : {_e(sentence)}</p>")
            + "</section>")


# ── Sections ─────────────────────────────────────────────────────────────────

def _synthese(report: ReportModel, alerts, found, facts) -> str:
    out = [_h2("synthese")]
    rank = {lvl: n for n, lvl in enumerate(_GRAVITES)}
    graded = sorted(((f.severity, i, f) for i, f in enumerate(report.findings) if f.severity in ("critique", "élevé", "moyen")),
                    key=lambda g: (rank[g[0]], g[1]))
    if graded:
        rows = []
        for sev, i, f in graded:
            reason = next((f"{str(k).replace('[ALERTE]', '').strip()} : {v}" for k, v in f.metadata.items()
                           if str(k).startswith("[ALERTE]")), f.metadata.get("Verdict", ""))
            rows.append(f'<tr><td class="fixe">{_pill(sev)}</td><td><a href="#{_anchor(i)}">{_e(_label(f))}</a></td>'
                        f'<td class="court"><code>{_e(os.path.basename(f.file))}</code></td><td>{_e(str(reason)[:220])}</td></tr>')
        out.append("<h3>Résultats par gravité</h3>" + _table(["Gravité", "Module", "Fichier", "Motif principal"], rows))

    strong = [fact for fact in facts if fact.get("confidence") == "élevée"]
    if strong:
        rows = [f'<tr><td class="fixe">{_e(_utc(str(fact.get("timestamp", ""))))}</td>'
                f'<td>{_e(" + ".join(fact.get("sources", [])))}</td><td>{_e(fact.get("description", ""))}</td></tr>'
                for fact in strong[:_SYNTH_FACTS]]
        more = (f'<p class="reste">{len(strong) - _SYNTH_FACTS} fait(s) de plus dans la '
                f'<a href="#chronologie">chronologie</a>.</p>' if len(strong) > _SYNTH_FACTS else "")
        out.append("<h3>Chaîne d'attaque</h3><p>Faits confirmés par au moins deux sources indépendantes.</p>"
                   + _table(["Date", "Sources", "Fait"], rows) + more)

    corroborated = [i for i in found if len(i.sources) > 1]
    if corroborated:
        rows = [f'<tr><td class="court">{_e(i.kind)}</td><td><code>{_e(i.value)}</code></td>'
                f"<td>{_e(', '.join(sorted(MODULE_NAMES.get(s, s) for s in i.sources)))}</td></tr>"
                for i in corroborated[:_SYNTH_IOCS]]
        out.append("<h3>Indicateurs corroborés</h3>" + _table(["Type", "Valeur", "Vu par"], rows)
                   + ('<p class="reste">Liste complète : <a href="#indicateurs">indicateurs</a>.</p>'
                      if len(corroborated) > _SYNTH_IOCS else ""))

    if alerts:
        groups: dict[int, list[tuple[str, str]]] = defaultdict(list)
        for i, f, k, v in alerts:
            groups[i].append((str(k).replace("[ALERTE]", "").strip(), str(v)))
        rows = []
        for i, items in groups.items():
            f = report.findings[i]
            rows.append(f'<tr class="groupe"><th colspan="2"><a href="#{_anchor(i)}">{_e(_label(f))}</a> - '
                        f"<code>{_e(os.path.basename(f.file))}</code> {_pill(f.severity)}</th></tr>")
            rows += [f"<tr><td><strong>{_e(k)}</strong></td><td>{_e(v)}</td></tr>" for k, v in items]
        out.append(f"<h3>Alertes par module ({len(alerts)})</h3>" + _table(["Alerte", "Détail"], rows, "alertes"))
    else:
        out.append(_note("tip", "<p>Aucune alerte relevée par les modules exécutés.</p>"))

    techniques = sorted({t for f in report.findings for t in (f.extra or {}).get("mitre", []) if isinstance(t, str)})
    corr = next((f for f in report.findings if f.type == "correlation"), None)
    if corr:
        techniques = sorted(set(techniques) | {t for t in corr.extra.get("techniques", []) if isinstance(t, str)})
    if techniques:
        rows = [f"<tr><td><code>{_e(t['id'])}</code></td><td>{_e(t['name'])}</td><td>{_e(t.get('tactic', ''))}</td></tr>"
                for t in mitre.describe(techniques)]
        out.append("<h3>Techniques MITRE ATT&amp;CK</h3>" + _table(["Identifiant", "Technique", "Tactique"], rows))
    return "".join(out)


def _perimetre(report: ReportModel) -> str:
    evidence = [f for f in report.findings if f.type not in _TRANSVERSE and os.path.isabs(f.file or "")]
    modules = sorted({_label(f) for f in evidence})
    method = (f'<dl class="methode">'
              f"<div><dt>Rapport généré</dt><dd>{_e(_utc(report.timestamp))}</dd></div>"
              f"<div><dt>Outil</dt><dd>{_e(report.tool)}</dd></div>"
              f"<div><dt>Services en ligne</dt><dd>{'activés (--online)' if online_enabled() else 'désactivés : aucune donnée envoyée à un tiers'}</dd></div>"
              f"<div><dt>Modules exécutés</dt><dd>{_e(', '.join(modules) or 'aucun')}</dd></div>"
              f"<div><dt>Dossier de sortie</dt><dd><code>{_e(export_root())}</code></dd></div></dl>")
    hashed = {r.file for r in report.evidence}
    # Dossier commun affiché une fois : chaque ligne ne garde que son chemin relatif
    try:
        root = os.path.commonpath([os.path.dirname(r.file) for r in report.evidence]) if report.evidence else ""
    except ValueError:
        root = ""

    # Collecte en une passe : l'horodatage commun est donné une fois, la place va aux empreintes
    stamps = {r.hashed_at[:16] for r in report.evidence}
    one_stamp = len(stamps) == 1

    def where(r) -> str:
        return r.origin or (os.path.relpath(os.path.dirname(r.file), root) if root else os.path.dirname(r.file))
    rows = [f"<tr><td><code>{_e(os.path.basename(r.file))}</code><br><small>{_e(where(r))}</small></td>"
            f'<td class="nombre">{_octets(r.size)}</td><td><code class="empreinte">{_e(r.sha256)}</code><br><code class="md5">{_e(r.md5)}</code></td>'
            + ("" if one_stamp else f'<td class="fixe">{_e(_utc(r.hashed_at))}</td>')
            + f"<td>{'<strong>MODIFIÉE</strong>' if r.changed_during_analysis else 'inchangée'}</td></tr>"
            for r in report.evidence]
    # Preuves analysées hors collecte (analyse ciblée) : empreintes prises par le module
    rows += [f"<tr><td><code>{_e(os.path.basename(f.file))}</code><br><small>{_e(f.file)}</small></td><td>-</td>"
             f"<td><code>{_e(f.metadata.get('SHA-256', '-'))}</code><br><code class=\"md5\">{_e(f.metadata.get('MD5', '-'))}</code></td>"
             + ("" if one_stamp else "<td>-</td>") + "<td>-</td></tr>"
             for f in evidence if f.file not in hashed]
    changed = [r for r in report.evidence if r.changed_during_analysis]
    table = ((_note("warning", f"<p><strong>{len(changed)} preuve(s) modifiée(s) pendant l'analyse</strong>.</p>") if changed else "")
             + ("<p>Empreintes prises à la collecte, avant toute analyse"
                + (f" ({_e(_utc(report.evidence[0].hashed_at))})" if one_stamp else "")
                + f", puis recalculées à la fin. Dossier des preuves : <code>{_e(root)}</code>.</p>" if report.evidence else "")
             + _table(["Preuve", "Octets", "SHA-256 / MD5"] + ([] if one_stamp else ["Hachée le"]) + ["Après analyse"], rows)) if rows \
        else "<p>Aucune preuve fichier.</p>"
    integrity = "".join(
        _note("warning" if f.severity == "critique" else ("important" if f.incomplete else "tip"),
              f"<p><strong>{_e(f.metadata.get('Phase', 'Vérification'))}</strong> : {_e(f.metadata.get('Verdict', ''))}</p>")
        for f in report.findings if f.type == "evidence_integrity")
    return (_h2("perimetre") + method + f"<h3>Empreintes des preuves ({len(rows)})</h3>{table}"
            + (f"<h3>Intégrité des preuves</h3>{integrity}" if integrity else ""))


def _chronologie(report: ReportModel, facts) -> str:
    tl = next((f for f in report.findings if f.type == "timeline"), None)
    if not tl:
        return _h2("chronologie") + "<p>Aucun événement daté.</p>"
    clock = ""
    skew = tl.metadata.get("[ATTENTION] Décalage d'horloge")
    if skew:
        realign = tl.metadata.get("Recalage PCAP")
        clock = _note("info", f"<p><strong>Décalage d'horloge</strong> : {_e(skew)}</p>"
                              + (f"<p>{_e(realign)}</p>" if realign else ""))
    rows = [f'<tr class="confiance-{_e(fact.get("confidence", ""))}"><td class="fixe">{_e(_utc(str(fact.get("timestamp", ""))))}</td>'
            f'<td class="fixe">{_e(fact.get("confidence", ""))}</td><td>{_e(" + ".join(fact.get("sources", [])))}</td>'
            f'<td>{_e(fact.get("description", ""))}</td></tr>'
            for fact in facts]
    return (_h2("chronologie") + clock
            + f"<p>{_e(tl.metadata.get('Total événements', 0))} événement(s), {len(facts)} fait(s) consolidé(s). "
            "Confiance <em>élevée</em> : au moins deux sources concordantes.</p>"
            + _table(["Date", "Confiance", "Sources", "Fait"], rows)
            + "<details><summary>Paramètres de la chronologie</summary>" + _kv_table(tl.metadata) + "</details>")


def _indicateurs(found) -> str:
    if not found:
        return _h2("indicateurs") + "<p>Aucun indicateur extrait.</p>"
    rows = [f'<tr><td class="court">{_e(i.kind)}</td><td><code>{_e(i.value)}</code></td>'
            f"<td>{_e(', '.join(sorted(MODULE_NAMES.get(s, s) for s in i.sources)))}</td>"
            f"<td>{_e(' ; '.join(sorted({o.context for o in i.observations if o.context}))[:400])}</td></tr>"
            for i in found]
    shared = sum(len(i.sources) > 1 for i in found)
    return (_h2("indicateurs")
            + f"<p>{len(found)} indicateur(s), dont <strong>{shared}</strong> vu(s) par plusieurs sources (en tête).</p>"
            + _table(["Type", "Valeur", "Sources", "Contexte"], rows))


def _constats(report: ReportModel, toc: list[tuple[str, str]]) -> str:
    grouped: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(report.findings):
        if f.type != "timeline":
            grouped["transverse" if f.type in _TRANSVERSE else get_category(f.type)].append(i)
    titles = [(cat, title) for cat, title, _ in _CATEGORIES] + [("other", "Autres"), ("transverse", "Corrélation et intégrité")]
    out = [_h2("constats")]
    for cat, title in titles:
        if not grouped.get(cat):
            continue
        out.append(f"<h3>{_e(title)}</h3>")
        for i in grouped[cat]:
            f = report.findings[i]
            name = os.path.basename(f.file) or f.file
            toc.append((_anchor(i), f"{_label(f)} - {name}"))
            details = "".join(_data_block(k, v) for k, v in (f.extra or {}).items())
            out.append(
                f'<div class="constat" id="{_anchor(i)}">'
                f'<div class="constat-tete"><h4>{_e(_label(f))}</h4><code class="nom">{_e(name)}</code>{_pill(f.severity)}</div>'
                f'<p class="chemin">{_e(f.file)}</p>'
                f"{_kv_table(f.metadata)}"
                + (f'<details><summary>Données détaillées</summary>{details}</details>' if details else "")
                + "</div>")
    return "".join(out)


def _limites(report: ReportModel) -> str:
    items = []
    if report.analysis_errors:
        lis = "".join(f"<li><code>{_e(e.module)}</code> sur <code>{_e(e.file)}</code> : {_e(e.error)} - {_e(e.message)}</li>"
                      for e in report.analysis_errors)
        items.append(_note("important", f"<p><strong>{len(report.analysis_errors)} échec(s) d'analyse</strong> : "
                                        f"ces fichiers n'ont pas été analysés par le module indiqué.</p><ul>{lis}</ul>"))
    partial = [(f, reason) for f in report.findings for reason in f.incomplete]
    if partial:
        lis = "".join(f"<li><code>{_e(os.path.basename(f.file))}</code> : {_e(reason)}</li>" for f, reason in partial)
        items.append(_note("important", f"<p><strong>Non analysé ou non vérifié</strong> : aucune conclusion "
                                        f"ne peut être tirée sur ces points.</p><ul>{lis}</ul>"))
    if report.skipped_files:
        files = "".join(f"<li><code>{_e(p)}</code></li>" for p in report.skipped_files)
        items.append(_note("warning", f"<p><strong>{len(report.skipped_files)} fichier(s) non analysé(s)</strong> "
                                      f"(aucun module adapté) :</p><ul>{files}</ul>"))
    if report.scan_notes:
        items.append(_note("info", "<p><strong>Archives</strong> :</p><ul>"
                                   + "".join(f"<li>{_e(n)}</li>" for n in report.scan_notes) + "</ul>"))
    warnings = [(f, k, v) for f in report.findings for k, v in f.metadata.items()
                if k in ("Avertissement", "Enregistrements illisibles") or "illisible" in str(k).lower()]
    if warnings:
        lis = "".join(f"<li><code>{_e(os.path.basename(f.file))}</code> : {_e(k)} : {_e(v)}</li>" for f, k, v in warnings)
        items.append(_note("important", f"<p><strong>Lectures partielles</strong> :</p><ul>{lis}</ul>"))
    if not online_enabled():
        items.append(_note("info", "<p>Analyse <strong>hors ligne</strong> : aucune réputation externe (VirusTotal, "
                                   "MalwareBazaar) ni géocodage n'a été consulté.</p>"))
    items.append(_note("help", "<p>Les constats reflètent les modules exécutés et les preuves fournies ; un artefact "
                               "absent du périmètre n'est pas couvert. L'export JSON contient l'intégralité des données.</p>"))
    return _h2("limites") + "".join(items)


_CSS = """
:root {
  --noir:#0B0B0C; --gris-tres-sombre:#161618; --gris-sombre:#232326; --gris-anthracite:#34343A;
  --gris:#55555C; --gris-moyen:#8B8B93; --gris-clair:#C9C9CF; --gris-tres-clair:#E6E6EA;
  --fond:#EDEDF0; --carte:#FFFFFF; --cellule:#F6F6F8; --entete-kv:#E4E4E9; --code-fond:#E3E3E8; --code-texte:#1D1D21;
  --texte:#16161A; --texte-doux:#55555C; --titres:#1D1D21; --lien:#1B6B62; --filet:#D4D4DA;
  --sarcelle:#1B6B62; --sarcelle-claire:#4FC1B1; --sarcelle-profonde:#1F4E49; --acier:#3F6C96; --ambre:#C98F00; --rose:#A3424C;
  --tip:#CFE8DD; --info:#D9DCF2; --warning:#F2D2D5; --important:#E1E1E6; --help:#DDE9DA; --note-texte:#1D1D21; --note-lien:#7A2E36;
  --pied:#C9C9CF; --pied-texte:#16161A; --etiquette:#D4D4DA; --etiquette-texte:#232326;
  --police:'Inter', 'Segoe UI', system-ui, -apple-system, 'Helvetica Neue', Arial, sans-serif;
  --police-code:'JetBrains Mono', ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace;
  font-size: min(17px, calc(12.5px + .45vw));
}
html { background:var(--gris-sombre); background:linear-gradient(150deg, var(--gris-tres-sombre) -100%, var(--gris-anthracite) 60%, var(--sarcelle-profonde) 150%) fixed;
       font-family:var(--police); color:var(--texte); min-height:100%; font-feature-settings:'kern','liga','calt'; -webkit-font-smoothing:antialiased; }
html.dark { --texte:#E2E2E6; --texte-doux:#A0A0A8; --titres:#F0F0F2; --lien:#6FD3C5; --fond:#151517; --carte:#1D1D20; --cellule:#232327;
  --entete-kv:#2A2A2F; --code-fond:#0E0E10; --code-texte:#E6E6EA; --filet:#33333A;
  --tip:#244A40; --info:#363B66; --warning:#5A2E34; --important:#2E2E34; --help:#36412F; --note-texte:#F2F2F2; --note-lien:#8FE0D4;
  --pied:#232326; --pied-texte:#C9C9CF; --etiquette:#34343A; --etiquette-texte:rgba(255,255,255,.75);
  background:linear-gradient(150deg, var(--noir) 0%, var(--gris-sombre) 60%, var(--noir) 120%) fixed; }
* { box-sizing:border-box; }
body { width:100%; margin:0; }
body, p, td, th, li, dd, dt { font-size:.9rem; line-height:1.55; }
p { margin:.5em 0 .8em; }
code, pre, .fixe, .nombre { font-family:var(--police-code); font-feature-settings:'tnum','zero'; }

header.page { position:sticky; top:0; z-index:5; box-shadow:0 0 8px 2px rgba(0,0,0,.6); }
.topbar { background:var(--noir); height:3.6rem; display:flex; align-items:center; justify-content:space-between; padding:0 1.6rem; }
.logo { color:#fff; font-weight:700; font-size:1.15rem; letter-spacing:-.01em; }
.logo span { color:var(--sarcelle-claire); }
.outils button { background:var(--gris-anthracite); color:rgba(255,255,255,.88); border:0; border-radius:4px; padding:.4rem .8rem;
                 font:inherit; font-size:.78rem; font-weight:600; cursor:pointer; margin-left:.4rem; }
.outils button:hover { background:var(--sarcelle); color:#fff; }
.navbar { background:linear-gradient(150deg, var(--noir) -150%, var(--gris-anthracite) 200%); display:flex; flex-wrap:wrap; counter-reset:nav; }
.navbar a { color:rgba(225,225,230,.85); font-size:.92rem; font-weight:600; height:2.6rem; line-height:2.6rem; padding:0 1rem; }
.navbar a::before { counter-increment:nav; content:counter(nav) ". "; opacity:.55; }
.navbar a:hover { color:#fff; background:var(--gris-anthracite); }
.navbar a.active { color:#fff; background:linear-gradient(170deg, var(--sarcelle), var(--acier)); }

main { background:var(--fond); display:grid; grid-template-areas:'content sidebar'; grid-template-columns:minmax(0, 1fr) 15rem; }
article { grid-area:content; padding:1.6rem 2rem 2.4rem; min-width:0; counter-reset:section; }
#controls { grid-area:sidebar; background:linear-gradient(150deg, var(--gris-sombre), var(--sarcelle) 220%);
            color:rgba(255,255,255,.88); padding:1.4rem 1rem; position:sticky; top:6.2rem; align-self:start;
            max-height:calc(100vh - 6.2rem); overflow:auto; counter-reset:toc; }
html.dark #controls { background:linear-gradient(150deg, var(--gris-tres-sombre), var(--sarcelle) 300%); }
#controls h2 { color:#fff; font-size:.72rem; text-transform:uppercase; letter-spacing:.08em; margin:0 0 .8rem; }
#controls a { color:rgba(255,255,255,.85); display:block; font-size:.8rem; line-height:1.35; padding:.25em .4em; border-radius:3px; }
#controls a.n1 { font-weight:600; margin-top:.35rem; }
#controls a.n1::before { counter-increment:toc; content:counter(toc) ". "; opacity:.6; }
#controls a.n2 { padding-left:1.4em; font-size:.74rem; opacity:.85; }
#controls a:hover { color:#fff; background:rgba(255,255,255,.12); }

h1, h2, h3, h4, h5 { color:var(--titres); line-height:1.25; letter-spacing:-.01em; }
h2 { font-size:1.5rem; font-weight:700; margin:2.6rem 0 1.1rem; padding-bottom:.45rem; border-bottom:2px solid var(--filet); string-set:section content(text); }
h2::before { counter-increment:section; content:counter(section) ". "; color:var(--sarcelle); }
h3 { font-size:1.12rem; font-weight:700; margin:1.9rem 0 .7rem; }
h4 { font-size:1rem; font-weight:700; margin:0; }
h5 { font-size:.82rem; font-weight:600; text-transform:uppercase; letter-spacing:.05em; color:var(--texte-doux); margin:1.1em 0 .4em; }
a { color:var(--lien); text-decoration:none; }
a:hover { text-decoration:underline; }

.couverture { background:var(--carte); border-top:4px solid var(--sarcelle); padding:1.6rem 1.8rem 1.2rem; margin-bottom:.6rem;
              box-shadow:0 1px 2px rgba(0,0,0,.08); }
.surtitre { text-transform:uppercase; letter-spacing:.1em; font-size:.72rem; font-weight:600; color:var(--sarcelle); margin:0; }
.couverture h1 { font-size:2rem; font-weight:700; margin:.2rem 0 1rem; overflow-wrap:anywhere; string-set:affaire content(text); }
dl.meta { display:flex; flex-wrap:wrap; gap:.4rem 2rem; margin:0 0 1.2rem; }
dl.meta dt, dl.methode dt { font-size:.7rem; text-transform:uppercase; letter-spacing:.06em; color:var(--texte-doux); font-weight:600; }
dl.meta dd, dl.methode dd { margin:0; font-weight:600; }
.chiffres { display:flex; flex-wrap:wrap; margin:0 -.3rem .9rem; }
.chiffre { flex:1 1 28%; min-width:9rem; margin:.3rem; background:var(--cellule); border-left:3px solid var(--gris-moyen);
           padding:.55rem .8rem; display:flex; flex-direction:column; }
.chiffre .valeur { font-size:1.35rem; font-weight:700; font-feature-settings:'tnum'; line-height:1.2; }
.chiffre .intitule { font-size:.72rem; color:var(--texte-doux); text-transform:uppercase; letter-spacing:.05em; font-weight:600; }
.chiffre.g-critique { border-color:var(--rose); } .chiffre.g-critique .valeur { color:var(--rose); }
.chiffre.g-eleve { border-color:var(--ambre); } .chiffre.g-moyen { border-color:var(--acier); }
html.dark .chiffre.g-critique .valeur { color:#E58A94; }
.note.verdict { margin:0; }
.note.verdict p { font-size:.95rem; margin:0; }

dl.methode { display:grid; grid-template-columns:minmax(9rem, 14rem) 1fr; gap:.35rem 1rem; background:var(--carte); padding:1rem 1.2rem; margin:0 0 1rem; }
dl.methode div { display:contents; }

code { background:var(--code-fond); color:var(--code-texte); padding:.05em .3em; border-radius:3px; font-size:.84em; overflow-wrap:anywhere; }
code.md5 { color:var(--texte-doux); }
td code.empreinte, td code.md5 { font-size:.74em; word-break:break-all; }
pre { background:var(--code-fond); color:var(--code-texte); padding:.8rem; overflow-x:auto; }
small { color:var(--texte-doux); overflow-wrap:anywhere; }

table { border-collapse:collapse; margin:.4em 0 1em; width:100%; background:var(--carte); }
th { background:var(--gris-sombre); color:rgba(255,255,255,.9); font-weight:600; font-size:.78rem; text-transform:uppercase;
     letter-spacing:.04em; padding:.45rem .7rem; text-align:left; vertical-align:top; }
td { padding:.45rem .7rem; vertical-align:top; text-align:left; overflow-wrap:break-word; border-bottom:1px solid var(--filet); }
tbody tr:nth-child(even) td { background:var(--cellule); }
table.kv th { width:30%; background:var(--entete-kv); color:var(--titres); text-transform:none; letter-spacing:0; font-size:.86rem;
              border-bottom:1px solid var(--filet); }
table.kv td { white-space:pre-line; }
tr.alerte th { background:var(--rose); color:#fff; }
tr.alerte td { font-weight:600; }
table.alertes tr.groupe th { background:var(--entete-kv); color:var(--titres); text-transform:none; letter-spacing:0; font-size:.88rem; padding-top:.6rem; }
table.alertes td:first-child { width:32%; }
tr.confiance-élevée td:nth-child(2) { color:var(--lien); font-weight:700; }
td.fixe, td.court { white-space:nowrap; }
td.court code { overflow-wrap:normal; }
td.nombre { white-space:nowrap; text-align:right; }
.defile { overflow-x:auto; }
.defile > table { min-width:34rem; }   /* petit écran : on fait défiler plutôt que d'écraser les colonnes */

.gravite { display:inline-block; font-family:var(--police); font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.05em;
           padding:.12rem .5rem; border-radius:999px; background:var(--gris-clair); color:var(--gris-sombre); white-space:nowrap; vertical-align:middle; }
.gravite.g-critique { background:var(--rose); color:#fff; }
.gravite.g-eleve { background:var(--ambre); color:#1D1D21; }
.gravite.g-moyen { background:var(--acier); color:#fff; }
.gravite.g-faible { background:#B9C2CC; color:#1D1D21; }

.constat { background:var(--carte); border-left:3px solid var(--filet); padding:1rem 1.2rem .6rem; margin:0 0 1.1rem; box-shadow:0 1px 2px rgba(0,0,0,.06); }
.constat:has(.g-critique) { border-left-color:var(--rose); }
.constat:has(.g-eleve) { border-left-color:var(--ambre); }
.constat-tete { display:flex; flex-wrap:wrap; align-items:center; gap:.4rem .7rem; }
.constat-tete h4 { white-space:nowrap; }
.constat-tete code.nom { font-size:.82rem; }
.constat-tete .gravite { margin-left:auto; }
.chemin { margin:.3rem 0 .7rem; font-family:var(--police-code); font-size:.74rem; color:var(--texte-doux); overflow-wrap:anywhere; }

ul { padding-left:1.2em; }
.note ul, ul.liste { list-style:none; padding-left:1.1em; }
.note ul > li, ul.liste > li { margin:.3em 0; }
.note ul > li::before, ul.liste > li::before { content:'•'; color:var(--sarcelle); position:absolute; margin-left:-1em; }
.note { padding:.85rem 1rem .85rem 3rem; margin:0 0 1rem; color:var(--note-texte); position:relative; border-radius:3px; }
.note p { margin:.2em 0; }
.note a { color:var(--note-lien); }
.note::before { position:absolute; left:.85rem; top:.45rem; font-size:1.6rem; font-weight:700; color:var(--note-texte); opacity:.35; }
.note.tip { background:var(--tip); } .note.tip::before { content:'✓'; }
.note.info { background:var(--info); } .note.info::before { content:'i'; }
.note.warning { background:var(--warning); } .note.warning::before { content:'!'; }
.note.important { background:var(--important); } .note.important::before { content:'‼'; }
.note.help { background:var(--help); } .note.help::before { content:'?'; }
details > summary { cursor:pointer; color:var(--lien); font-weight:600; font-size:.86rem; margin:.5em 0; }
.reste { font-style:italic; color:var(--texte-doux); font-size:.82rem; }
.impression { display:none; }
.tags { background:var(--pied); padding:.6rem 2rem; }
.tags span { display:inline-block; background:var(--etiquette); color:var(--etiquette-texte); font-size:.62rem; font-weight:600;
             text-transform:uppercase; letter-spacing:.04em; border-radius:.6rem; padding:.1rem .6rem; margin:.15rem .2rem; }
footer.page { background:var(--pied); color:var(--pied-texte); padding:.8rem 2rem; font-size:.78rem; }

@media (max-width:1000px) { main { grid-template-areas:'content'; grid-template-columns:minmax(0, 1fr); } #controls { display:none; }
  #controls.ouvert { display:block; position:fixed; right:0; top:6.2rem; z-index:6; width:15rem; } #menu { display:inline-block; } }
@media (min-width:1001px) { #menu { display:none; } }
@media (max-width:607px) { .topbar { height:auto; flex-wrap:wrap; gap:.4rem; padding:.6rem 1rem; }
  .outils button { font-size:.7rem; padding:.3rem .5rem; margin:0 .3rem 0 0; } .navbar a { font-size:.82rem; padding:0 .6rem; }
  .couverture h1 { font-size:1.5rem; } table.kv th { width:38%; }
  article { padding:1rem; } .couverture { padding:1rem; } dl.methode { grid-template-columns:1fr; } }
@media (min-width:608px) and (max-height:800px) { header.page { top:-3.6rem; } }

@page { size:A4; margin:10mm 6mm 10mm;   /* marges réduites : la place va au contenu */
  @top-left { content:string(section); font-family:'Inter', sans-serif; font-size:7.5pt; color:#8B8B93; }
  @top-right { content:string(affaire); font-family:'Inter', sans-serif; font-size:7.5pt; color:#8B8B93; }
  @bottom-left { content:"Forensic Analyzer - rapport d'investigation"; font-family:'Inter', sans-serif; font-size:7.5pt; color:#55555C; }
  @bottom-right { content:"page " counter(page) " / " counter(pages); font-family:'Inter', sans-serif; font-size:7.5pt; color:#55555C; } }
@page :first { @top-left { content:none; } @top-right { content:none; } }
@media print {
  html, html.dark { background:#fff; font-size:9.5pt; }
  body { width:auto; margin:0; }
  header.page { position:static; box-shadow:none; }
  .topbar { height:auto; padding:.5rem 0; background:#fff; }
  .logo { color:#1D1D21; }
  .navbar, .outils, #controls, #menu, .tags { display:none !important; }
  main { display:block; background:#fff; }
  article { padding:0; }
  .couverture { box-shadow:none; padding:1rem 0 0; background:#fff; }
  .chiffre, td, tbody tr:nth-child(even) td { background:#F6F6F8; }
  table, .constat, dl.methode { background:#fff; }
  .constat { box-shadow:none; border:1px solid #D4D4DA; border-left-width:3px; padding:.6rem .8rem .3rem; }
  h2 { break-before:page; } h2#synthese { break-before:auto; } h3, h4, .constat-tete { break-after:avoid; }
  tr { break-inside:avoid; }
  .surplus { display:none !important; }
  .impression { display:block; }
  details > summary { display:none; }
  * { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
"""

_JS = """
(function () {
  var root = document.documentElement;
  try { if (localStorage.getItem('fa-theme') === 'dark' ||
            (!localStorage.getItem('fa-theme') && matchMedia('(prefers-color-scheme: dark)').matches)) root.classList.add('dark'); } catch (e) {}
  document.getElementById('theme').onclick = function () {
    root.classList.toggle('dark');
    try { localStorage.setItem('fa-theme', root.classList.contains('dark') ? 'dark' : 'light'); } catch (e) {}
  };
  document.getElementById('imprimer').onclick = function () { window.print(); };
  document.getElementById('menu').onclick = function () { document.getElementById('controls').classList.toggle('ouvert'); };
  var liens = document.querySelectorAll('.navbar a');
  function actif() {
    var courant = liens[0];
    liens.forEach(function (a) { var s = document.querySelector(a.getAttribute('href'));
      if (s && s.getBoundingClientRect().top < 160) courant = a; });
    liens.forEach(function (a) { a.classList.toggle('active', a === courant); });
  }
  addEventListener('scroll', actif, {passive: true}); actif();
})();
"""

_NAV_LABELS = {"synthese": "Synthèse", "perimetre": "Périmètre", "chronologie": "Chronologie",
               "indicateurs": "Indicateurs", "constats": "Constats", "limites": "Limites"}


def build_interactive_html(report: ReportModel) -> str:
    alerts = _alerts(report)
    found = sorted(ioc_mod.collect([f for f in report.findings if f.type not in ("timeline",)]),
                   key=lambda i: (-len(i.sources), i.kind, i.value))
    timeline = next((f for f in report.findings if f.type == "timeline"), None)
    facts = (timeline.extra.get("facts") or []) if timeline else []
    toc: list[tuple[str, str]] = []
    constats = _constats(report, toc)
    case = os.path.basename(os.path.normpath(export_root())) or "analyse"
    nav = "".join(f'<a href="#{sid}"' + (' class="active"' if n == 0 else "") + f">{_NAV_LABELS[sid]}</a>"
                  for n, (sid, _) in enumerate(_SECTIONS))
    side = "".join(f'<a class="n1" href="#{sid}">{_NAV_LABELS[sid]}</a>' + (
        "".join(f'<a class="n2" href="#{a}">{_e(name)}</a>' for a, name in toc) if sid == "constats" else "")
        for sid, _ in _SECTIONS)
    tags = "".join(f"<span>{_e(t)}</span>" for t in sorted({_label(f) for f in report.findings}))
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport d'investigation - {_e(case)}</title>
<style>{_font_faces()}
{_CSS}</style>
</head>
<body>
<header class="page">
  <div class="topbar">
    <div class="logo">Forensic<span>Analyzer</span></div>
    <div class="outils"><button id="menu" type="button">Sommaire</button><button id="theme" type="button">Thème clair / sombre</button><button id="imprimer" type="button">Imprimer</button></div>
  </div>
  <nav class="navbar">{nav}</nav>
</header>
<main>
  <article>
    {_couverture(report, alerts, found, facts, case)}
    {_synthese(report, alerts, found, facts)}
    {_perimetre(report)}
    {_chronologie(report, facts)}
    {_indicateurs(found)}
    {constats}
    {_limites(report)}
  </article>
  <aside id="controls"><h2>Sommaire</h2>{side}</aside>
</main>
<div class="tags">{tags}</div>
<footer class="page">{_e(report.tool)} · rapport généré le {_e(_utc(report.timestamp))} · © 2026 Félix TOVIGNAN · VISCHENZISCH</footer>
<script>{_JS}</script>
</body>
</html>"""


class HTMLExporter:
    """Rapport HTML hors ligne au design « documentation » (aussi utilisé pour le PDF)."""

    def export(self, report: ReportModel, output_path: str) -> str:
        target_path = resolve_output(output_path)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(build_interactive_html(report))
        log.info("Rapport HTML exporté -> %s", target_path)
        return target_path
