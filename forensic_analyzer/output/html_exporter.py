"""Rapport HTML (et base du PDF) au design « documentation » gris, dérivé d'ubuntu-fr.

Contenu imposé, quel que soit le type d'analyse : synthèse des alertes, périmètre (preuves,
empreintes, intégrité), chronologie consolidée, indicateurs, constats détaillés sans troncature
et limites de l'analyse. Aucune ressource externe : le rapport s'ouvre hors ligne.
"""
from __future__ import annotations

import html
import os
from collections import defaultdict

from forensic_analyzer.core import iocs as ioc_mod
from forensic_analyzer.core import mitre
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output.ui import MODULE_NAMES
from forensic_analyzer.utils.exports import export_root
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
    ("files", "Fichiers et métadonnées", {"pdf", "pdf_analysis", "image", "gps", "stego", "stego_audio"}),
]
_MAX_ROWS = 300  # lignes par tableau de données détaillées ; le reste est signalé et figure dans l'export JSON
_PRINT_ROWS = 25  # au-delà, lignes masquées à l'impression (PDF) avec mention du reste
# Données déjà restituées ailleurs (chronologie, graphe) : pas de doublon dans les constats
_SKIP_KEYS = {"events", "facts", "graph", "timeline_events", "timeline"}


def get_category(f_type: str) -> str:
    return next((cat for cat, _, types in _CATEGORIES if f_type in types), "other")


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _label(f: FindingModel) -> str:
    return MODULE_NAMES.get(f.type, f.type.replace("_", " ").capitalize())


def _anchor(i: int) -> str:
    return f"constat-{i}"


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
            head = "".join(f"<th>{_e(c)}</th>" for c in cols)
            rows = "".join(f"<tr{cls(n)}>" + "".join(f"<td>{_e(item.get(c, ''))}</td>" for c in cols) + "</tr>"
                           for n, item in enumerate(items))
            table = f'<div class="defile"><table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>'
        else:
            table = "<ul>" + "".join(f"<li{cls(n)}>{_e(x)}</li>" for n, x in enumerate(items)) + "</ul>"
        return f"<h5>{_e(title)} ({len(value)})</h5>{table}{more}"
    return f"<h5>{_e(title)}</h5><p>{_e(value)}</p>"


def _note(kind: str, inner: str) -> str:
    return f'<div class="note {kind}">{inner}</div>'



def _synthese(report: ReportModel, alerts) -> str:
    techniques = sorted({t for f in report.findings for t in (f.extra or {}).get("mitre", []) if isinstance(t, str)})
    corr = next((f for f in report.findings if f.type == "correlation"), None)
    if corr:
        techniques = sorted(set(techniques) | {t for t in corr.extra.get("techniques", []) if isinstance(t, str)})
    if alerts:
        items = "".join(
            f'<li><a href="#{_anchor(i)}">{_e(_label(f))}</a> — <code>{_e(os.path.basename(f.file))}</code> : '
            f'<strong>{_e(str(k).replace("[ALERTE]", "").strip())}</strong> : {_e(v)}</li>'
            for i, f, k, v in alerts)
        block = _note("warning", f"<p><strong>{len(alerts)} alerte(s)</strong> relevée(s) par l'analyse.</p><ul>{items}</ul>")
    else:
        block = _note("tip", "<p>Aucune alerte relevée par les modules exécutés.</p>")
    mitre_block = ""
    if techniques:
        rows = "".join(f"<tr><td><code>{_e(t['id'])}</code></td><td>{_e(t['name'])}</td><td>{_e(t.get('tactic', ''))}</td></tr>"
                       for t in mitre.describe(techniques))
        mitre_block = ("<h3>Techniques MITRE ATT&amp;CK</h3>"
                       f"<table><thead><tr><th>Identifiant</th><th>Technique</th><th>Tactique</th></tr></thead>"
                       f"<tbody>{rows}</tbody></table>")
    return f'<h2 id="synthese">Synthèse</h2>{block}{mitre_block}'


def _perimetre(report: ReportModel) -> str:
    evidence = [f for f in report.findings if f.type not in _TRANSVERSE and os.path.isabs(f.file or "")]
    modules = sorted({_label(f) for f in evidence})
    rows = "".join(
        f"<tr><td><code>{_e(os.path.basename(f.file))}</code><br><small>{_e(f.file)}</small></td>"
        f"<td>{_e(_label(f))}</td><td><code>{_e(f.metadata.get('SHA-256', '—'))}</code></td>"
        f"<td><code>{_e(f.metadata.get('MD5', '—'))}</code></td></tr>"
        for f in evidence)
    table = (f'<div class="defile"><table><thead><tr><th>Preuve</th><th>Module</th><th>SHA-256</th><th>MD5</th></tr></thead>'
             f"<tbody>{rows}</tbody></table></div>") if rows else "<p>Aucune preuve fichier.</p>"
    integrity = "".join(
        _note("warning" if "[ALERTE]" in str(f.metadata.get("Verdict", "")) else "tip",
              f"<p><strong>{_e(f.metadata.get('Phase', 'Vérification'))}</strong> : {_e(f.metadata.get('Verdict', ''))}</p>")
        for f in report.findings if f.type == "evidence_integrity")
    return (f'<h2 id="perimetre">Périmètre et méthode</h2>'
            f"<ul><li><strong>Rapport généré</strong> : {_e(report.timestamp[:19].replace('T', ' '))}</li>"
            f"<li><strong>Outil</strong> : {_e(report.tool)}</li>"
            f"<li><strong>Services en ligne</strong> : {'activés (--online)' if online_enabled() else 'désactivés : aucune donnée envoyée à un tiers'}</li>"
            f"<li><strong>Modules exécutés</strong> : {_e(', '.join(modules) or 'aucun')}</li>"
            f"<li><strong>Dossier de sortie</strong> : <code>{_e(export_root())}</code></li></ul>"
            f"<h3>Preuves analysées ({len(evidence)})</h3>{table}"
            + (f"<h3>Intégrité des preuves</h3>{integrity}" if integrity else ""))


def _chronologie(report: ReportModel) -> str:
    tl = next((f for f in report.findings if f.type == "timeline"), None)
    if not tl:
        return '<h2 id="chronologie">Chronologie consolidée</h2><p>Aucun événement daté.</p>'
    clock = ""
    skew = tl.metadata.get("[ATTENTION] Décalage d'horloge")
    if skew:
        realign = tl.metadata.get("Recalage PCAP")
        clock = _note("info", f"<p><strong>Décalage d'horloge</strong> : {_e(skew)}</p>"
                              + (f"<p>{_e(realign)}</p>" if realign else ""))
    facts = tl.extra.get("facts") or []
    rows = "".join(
        f'<tr class="confiance-{_e(fact.get("confidence", ""))}"><td class="fixe">{_e(str(fact.get("timestamp", ""))[:19].replace("T", " "))}</td>'
        f'<td class="fixe">{_e(fact.get("confidence", ""))}</td><td>{_e(" + ".join(fact.get("sources", [])))}</td>'
        f'<td>{_e(fact.get("description", ""))}</td></tr>'
        for fact in facts)
    return (f'<h2 id="chronologie">Chronologie consolidée</h2>{clock}'
            f"<p>{_e(tl.metadata.get('Total événements', 0))} événement(s), {len(facts)} fait(s) consolidé(s). "
            "Confiance <em>élevée</em> : au moins deux sources concordantes.</p>"
            f"{_kv_table(tl.metadata)}"
            f'<div class="defile"><table><thead><tr><th>Date (UTC)</th><th>Confiance</th><th>Sources</th>'
            f"<th>Fait</th></tr></thead><tbody>{rows}</tbody></table></div>")


def _indicateurs(report: ReportModel) -> str:
    found = sorted(ioc_mod.collect([f for f in report.findings if f.type not in ("timeline",)]),
                   key=lambda i: (-len(i.sources), i.kind, i.value))
    if not found:
        return '<h2 id="indicateurs">Indicateurs de compromission</h2><p>Aucun indicateur extrait.</p>'
    rows = "".join(
        f"<tr><td>{_e(i.kind)}</td><td><code>{_e(i.value)}</code></td>"
        f"<td>{_e(', '.join(sorted(MODULE_NAMES.get(s, s) for s in i.sources)))}</td>"
        f"<td>{_e(' ; '.join(sorted({o.context for o in i.observations if o.context}))[:400])}</td></tr>"
        for i in found)
    shared = sum(len(i.sources) > 1 for i in found)
    return (f'<h2 id="indicateurs">Indicateurs de compromission</h2>'
            f"<p>{len(found)} indicateur(s), dont <strong>{shared}</strong> vu(s) par plusieurs sources (en tête).</p>"
            f'<div class="defile"><table><thead><tr><th>Type</th><th>Valeur</th><th>Sources</th><th>Contexte</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>")


def _constats(report: ReportModel, toc: list[tuple[str, str, int]]) -> str:
    grouped: dict[str, list[int]] = defaultdict(list)
    for i, f in enumerate(report.findings):
        if f.type != "timeline":
            grouped["transverse" if f.type in _TRANSVERSE else get_category(f.type)].append(i)
    titles = [(cat, title) for cat, title, _ in _CATEGORIES] + [("other", "Autres"), ("transverse", "Corrélation et intégrité")]
    out = ['<h2 id="constats">Constats détaillés</h2>']
    for cat, title in titles:
        if not grouped.get(cat):
            continue
        out.append(f"<h3>{_e(title)}</h3>")
        for i in grouped[cat]:
            f = report.findings[i]
            name = f"{_label(f)} — {os.path.basename(f.file) or f.file}"
            toc.append((_anchor(i), name, 2))
            details = "".join(_data_block(k, v) for k, v in (f.extra or {}).items())
            out.append(
                f'<h4 id="{_anchor(i)}">{_e(name)}</h4>'
                f'<p class="chemin"><code>{_e(f.file)}</code></p>'
                f"{_kv_table(f.metadata)}"
                + (f'<details><summary>Données détaillées</summary>{details}</details>' if details else ""))
    return "".join(out)


def _limites(report: ReportModel) -> str:
    items = []
    if report.skipped_files:
        files = "".join(f"<li><code>{_e(p)}</code></li>" for p in report.skipped_files)
        items.append(_note("warning", f"<p><strong>{len(report.skipped_files)} fichier(s) non analysé(s)</strong> "
                                      f"(aucun module adapté) :</p><ul>{files}</ul>"))
    warnings = [(f, k, v) for f in report.findings for k, v in f.metadata.items()
                if k in ("Avertissement", "Enregistrements illisibles") or "illisible" in str(k).lower()]
    if warnings:
        lis = "".join(f"<li><code>{_e(os.path.basename(f.file))}</code> — {_e(k)} : {_e(v)}</li>" for f, k, v in warnings)
        items.append(_note("important", f"<p><strong>Lectures partielles</strong> :</p><ul>{lis}</ul>"))
    if not online_enabled():
        items.append(_note("info", "<p>Analyse <strong>hors ligne</strong> : aucune réputation externe (VirusTotal, "
                                   "MalwareBazaar) ni géocodage n'a été consulté.</p>"))
    items.append(_note("help", "<p>Les constats reflètent les modules exécutés et les preuves fournies ; un artefact "
                               "absent du périmètre n'est pas couvert. L'export JSON contient l'intégralité des données.</p>"))
    return '<h2 id="limites">Limites de l\'analyse</h2>' + "".join(items)



_CSS = """
:root {
  --noir:#0B0B0C; --gris-tres-sombre:#161618; --gris-sombre:#232326; --gris-anthracite:#34343A;
  --gris:#55555C; --gris-moyen:#8B8B93; --gris-clair:#C9C9CF; --gris-tres-clair:#E6E6EA;
  --gris-cellule:#F4F4F6; --texte:#111111; --titres:#232326; --lien:#1B6B62;
  --sarcelle:#1B6B62; --sarcelle-claire:#4FC1B1; --sarcelle-profonde:#1F4E49;
  --acier:#3F6C96; --ambre:#E0A100; --rose:#A3424C;
  --tip:#A8D5C2; --info:#B4BAE3; --warning:#E6B0B5; --important:#CFCFD4; --help:#D3E2D0;
  --note-texte:#222222; --note-lien:#7A2E36; --pied:#8B8B93; --pied-texte:#111111;
  --etiquette:#C9C9CF; --etiquette-texte:#232326; --citation:#C9C9CF;
  font-size: min(18px, calc(13px + .5vw));
}
html { background:#232326; background:linear-gradient(150deg, var(--gris-tres-sombre) -100%, var(--gris-anthracite) 60%, var(--sarcelle-profonde) 150%) fixed;
       font-family: ubuntu, "Trebuchet MS", "Open Sans", sans-serif; color: var(--texte); min-height:100%; }
html.dark { --texte:#DDDDDD; --titres:#E6E6EA; --lien:#4FC1B1; --gris-tres-clair:#1A1A1C; --gris-cellule:#222224;
  --tip:#2A5046; --info:#3E4470; --warning:#5E3036; --important:#34343A; --help:#3E463C;
  --note-texte:#F2F2F2; --note-lien:#8FE0D4; --pied:#2B2B2E; --pied-texte:#C9C9CF;
  --etiquette:#34343A; --etiquette-texte:rgba(255,255,255,.7); --citation:#34343A;
  background: linear-gradient(150deg, var(--noir) 0%, var(--gris-sombre) 60%, var(--noir) 120%) fixed; }
* { box-sizing: border-box; }
body { width:100%; margin:0; }  /* pleine largeur : tout l'espace va au contenu */
body, p, pre, td, th, li { font-size:.9rem; line-height:1.6em; }
header.page { position:sticky; top:0; z-index:5; box-shadow:0 0 8px 2px rgba(0,0,0,.8); }
.topbar { background:var(--noir); height:4.5rem; display:flex; align-items:center; justify-content:space-between; padding:0 1.6rem; }
.logo { color:#fff; font-weight:bold; font-size:1.3rem; letter-spacing:.02em; }
.logo span { color:var(--sarcelle-claire); }
.outils button { background:var(--gris-anthracite); color:rgba(255,255,255,.85); border:0; padding:.4rem .8rem; font:inherit; font-size:.8rem; cursor:pointer; margin-left:.4rem; }
.outils button:hover { background:var(--sarcelle); color:#fff; }
.navbar { background:linear-gradient(150deg, var(--noir) -150%, var(--gris-anthracite) 200%); display:flex; flex-wrap:wrap; }
.navbar a { color:rgba(220,220,220,.85); font-size:1.1rem; height:3rem; line-height:3rem; padding:0 1rem; }
.navbar a:hover { color:#fff; background:var(--gris-anthracite); }
.navbar a.active { color:#fff; background:linear-gradient(170deg, var(--sarcelle), var(--acier)); }
main { background:var(--gris-tres-clair); display:grid; grid-template-areas:'content sidebar'; grid-template-columns:auto 14rem; }
article { grid-area:content; padding:1.2rem 1.6rem; min-width:0; }
#controls { grid-area:sidebar; width:14rem; background:linear-gradient(150deg, var(--gris-sombre), var(--sarcelle) 200%);
            color:rgba(255,255,255,.85); padding:1.6rem 1rem; position:sticky; top:7.5rem; align-self:start; max-height:calc(100vh - 7.5rem); overflow:auto; }
html.dark #controls { background:linear-gradient(150deg, var(--gris-tres-sombre), var(--sarcelle) 300%); }
#controls h2 { color:rgba(255,255,255,.85); font-size:1rem; margin:0 0 .6rem; }
#controls a { color:rgba(255,255,255,.85); display:block; font-size:.8rem; line-height:1.4em; padding:.15em 0; }
#controls a.n2 { padding-left:1.2em; font-size:.75rem; }
#controls a:hover { color:#fff; background:var(--sarcelle); }
h1, h2, h3, h4, h5, h6 { color:var(--titres); font-weight:bold; line-height:1.4em; }
h1 { font-size:2rem; margin:.4em 0 1.2em; }  h2 { font-size:1.55rem; margin:2em 0 1.3em; }
h3 { font-size:1.2rem; margin:1.8em 0 1.3em; }  h4 { font-size:1rem; margin:1.2em 0 .6em; }
h5, h6 { font-size:1rem; margin:.9em 0 .5em; }
a { color:var(--lien); text-decoration:none; }
a:hover { color:#fff; background:var(--sarcelle); }
html.dark a:hover { color:var(--noir); background:var(--sarcelle-claire); }
article ul { list-style:none; padding-left:1.2em; }
article ul > li { margin:.4em 0; }
article ul > li::before { content:'•'; color:var(--sarcelle); opacity:.8; position:absolute; margin-left:-1em; }
code, pre { background:var(--gris-sombre); color:#EDEDED; font-family:ubuntu-mono, Consolas, Monaco, "Courier New", monospace; }
html.dark code, html.dark pre { background:var(--noir); }
code { padding:0 .2rem; border-top:.25em solid var(--gris-sombre); border-bottom:.25em solid var(--gris-sombre); overflow-wrap:anywhere; }
html.dark code { border-color:var(--noir); }
pre { border-left:.5rem solid var(--gris); padding:.8rem; overflow-x:auto; }
table { border-collapse:collapse; margin:.6em 0 1em; width:100%; }
th { background:var(--gris-sombre); color:rgba(255,255,255,.85); font-weight:normal; padding:5px 10px; text-align:left; vertical-align:top; }
td { background:var(--gris-cellule); padding:5px 10px; padding-right:30px; vertical-align:top; text-align:left; overflow-wrap:anywhere; }
table.kv th { width:32%; }
tr.alerte th { background:var(--rose); color:#fff; }
tr.alerte td { font-weight:bold; }
tr.confiance-élevée td:nth-child(2) { color:var(--lien); font-weight:bold; }
.defile { overflow-x:auto; }
td.fixe { white-space:nowrap; padding-right:12px; font-family:ubuntu-mono, Consolas, Monaco, "Courier New", monospace; }
hr { border:0; border-top:1px solid rgba(85,85,92,.35); }
.note { padding:1rem 1rem 1rem 3.2rem; margin-bottom:1rem; color:var(--note-texte); position:relative; }
.note a { color:var(--note-lien); }
.note::before { position:absolute; left:.8rem; top:.4rem; font-size:2rem; font-weight:bold; color:#fff; opacity:.6; }
.note.tip { background:var(--tip); } .note.tip::before { content:'✓'; }
.note.info { background:var(--info); } .note.info::before { content:'i'; font-family:Georgia, serif; }
.note.warning { background:var(--warning); } .note.warning::before { content:'!'; }
.note.important { background:var(--important); } .note.important::before { content:'‼'; }
.note.help { background:var(--help); } .note.help::before { content:'?'; }
.note ul { margin:.4em 0 0; }
details > summary { cursor:pointer; color:var(--lien); font-weight:bold; margin:.6em 0; }
.chemin { margin:.2em 0 .6em; }
.reste { font-style:italic; color:var(--gris); }
.impression { display:none; }
.tags { background:var(--pied); padding:.6rem 1.6rem; }
.tags span { display:inline-block; background:var(--etiquette); color:var(--etiquette-texte); font-size:.6rem; text-transform:uppercase;
             border-radius:.6rem; padding:.1rem .6rem; margin:.15rem .2rem; }
footer.page { background:var(--pied); color:var(--pied-texte); padding:.8rem 1.6rem; font-size:.8rem; }
@media (max-width:1000px) { main { grid-template-areas:'content'; grid-template-columns:auto; } #controls { display:none; }
  #controls.ouvert { display:block; position:fixed; right:0; top:7.5rem; z-index:6; } #menu { display:inline-block; } }
@media (min-width:1001px) { #menu { display:none; } }
@media (max-width:607px) { .navbar { background:linear-gradient(150deg, var(--sarcelle) -100%, var(--gris-sombre) 150%); } .navbar a { font-size:1.2rem; }
  .topbar { height:auto; flex-wrap:wrap; gap:.4rem; padding:.6rem 1rem; } .outils button { font-size:.7rem; padding:.3rem .5rem; margin:0 .3rem 0 0; }
  article { padding:1rem; } }
@media (min-width:608px) and (max-height:800px) { header.page { top:-4.5rem; } }
@page { size:A4; margin:6mm 6mm 10mm;
  @bottom-left { content:"Forensic Analyzer — rapport d'investigation"; font-size:8pt; color:#55555C; }
  @bottom-right { content:"page " counter(page) " / " counter(pages); font-size:8pt; color:#55555C; } }
@media print {
  html, html.dark { background:#fff; font-size:10pt; }
  body { width:auto; margin:0; box-shadow:none; }
  header.page { position:static; box-shadow:none; }
  .navbar, .outils, #controls, #menu { display:none !important; }
  main { display:block; background:#fff; }
  article { padding:0; }
  h2 { break-before:page; } h2#synthese { break-before:auto; }
  h4, tr { break-inside:avoid; }
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


def build_interactive_html(report: ReportModel) -> str:
    alerts = _alerts(report)
    toc: list[tuple[str, str, int]] = []
    constats = _constats(report, toc)
    sections = [("synthese", "Synthèse"), ("perimetre", "Périmètre"), ("chronologie", "Chronologie"),
                ("indicateurs", "Indicateurs"), ("constats", "Constats"), ("limites", "Limites")]
    nav = "".join(f'<a href="#{sid}"' + (' class="active"' if n == 0 else "") + f">{label}</a>"
                  for n, (sid, label) in enumerate(sections))
    side = "".join(f'<a href="#{sid}">{label}</a>' + (
        "".join(f'<a class="n2" href="#{a}">{_e(name)}</a>' for a, name, _ in toc) if sid == "constats" else "")
        for sid, label in sections)
    case = os.path.basename(os.path.normpath(export_root())) or "analyse"
    tags = "".join(f"<span>{_e(t)}</span>" for t in sorted({_label(f) for f in report.findings}))
    evidence_count = sum(1 for f in report.findings if f.type not in _TRANSVERSE)
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport d'investigation — {_e(case)}</title>
<style>{_CSS}</style>
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
    <h1>Rapport d'investigation numérique</h1>
    <p><strong>Affaire</strong> : <code>{_e(case)}</code> · <strong>{evidence_count}</strong> constat(s) ·
       <strong>{len(alerts)}</strong> alerte(s) · généré le {_e(report.timestamp[:19].replace('T', ' '))}</p>
    {_synthese(report, alerts)}
    {_perimetre(report)}
    {_chronologie(report)}
    {_indicateurs(report)}
    {constats}
    {_limites(report)}
  </article>
  <aside id="controls"><h2>Table des matières</h2>{side}</aside>
</main>
<div class="tags">{tags}</div>
<footer class="page">{_e(report.tool)} · rapport généré le {_e(report.timestamp[:19].replace('T', ' '))} · © 2026 Félix TOVIGNAN · VISCHENZISCH</footer>
<script>{_JS}</script>
</body>
</html>"""


class HTMLExporter:
    """Rapport HTML hors ligne au design « documentation » (aussi utilisé pour le PDF)."""

    def export(self, report: ReportModel, output_path: str) -> None:
        os.makedirs(export_root(), exist_ok=True)
        target_path = os.path.join(export_root(), os.path.basename(output_path))
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(build_interactive_html(report))
        log.info("Rapport HTML exporté -> %s", target_path)
