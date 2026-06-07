"""Exporteur HTML interactif premium avec Chart.js et sections DFIR."""
from __future__ import annotations
import html
import json
import os
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.analyzers.timeline_analyzer import build_timeline
from forensic_analyzer.utils.logger import get_logger

log = get_logger("html_exporter")

_TYPE_LABELS = {
    "pdf": "[PDF]", "image": "[IMG]", "gps": "[GPS]",
    "strings": "[STR]", "firefox_history": "[NAV]", "firefox_cookies": "[CKY]",
    "stego": "[STEG]", "carving": "[CARV]", "pcap": "[NET]",
    "memory": "[MEM]", "disk": "[DISK]", "evtx": "[EVTX]",
    "registry": "[REG]", "linux_artifacts": "[LNX]",
    "yara": "[YARA]", "ioc": "[IOC]", "timeline": "[TIME]",
}

_TYPE_COLORS = {
    "pdf": "#f25f5c", "image": "#3ecf8e", "gps": "#f5c542",
    "strings": "#a78bfa", "firefox_history": "#4f8ef7", "firefox_cookies": "#fb923c",
    "stego": "#ec4899", "carving": "#06b6d4", "pcap": "#6366f1",
    "memory": "#ef4444", "disk": "#84cc16", "evtx": "#f59e0b",
    "registry": "#8b5cf6", "linux_artifacts": "#10b981",
    "yara": "#e11d48", "ioc": "#d946ef", "timeline": "#0ea5e9",
}


def _finding_card(f: FindingModel) -> str:
    label = _TYPE_LABELS.get(f.type, "[?]")
    fname = html.escape(os.path.basename(f.file))
    color = _TYPE_COLORS.get(f.type, "#4f8ef7")

    rows = "".join(
        f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v)[:300])}</td></tr>"
        for k, v in f.metadata.items()
    )
    extra_rows = ""
    if f.type == "strings" and "strings" in f.extra:
        extra_rows = "".join(
            f"<tr><td>{i}</td><td class='mono'>{html.escape(s)}</td></tr>"
            for i, s in enumerate(f.extra["strings"][:100], 1)
        )
    elif f.type == "firefox_history" and "entries" in f.extra:
        extra_rows = "".join(
            f"<tr><td>{html.escape(e.get('date') or '-')}</td>"
            f"<td><a href='{html.escape(e.get('url',''))}' target='_blank' class='link'>"
            f"{html.escape(e.get('url','')[:80])}</a></td></tr>"
            for e in f.extra["entries"][:50]
        )
    elif f.type == "ioc" and "iocs" in f.extra:
        iocs = f.extra["iocs"]
        for ioc_type, items in iocs.items():
            for item in items[:10]:
                extra_rows += f"<tr><td>{ioc_type}</td><td class='mono'>{html.escape(str(item))}</td></tr>"

    return f"""
    <section class="card" style="border-left: 3px solid {color}">
      <h3 class="card-title">
        <span class="label" style="background:{color}">{f.type.upper()}</span>
        {label} {fname}
      </h3>
      <p class="filepath">{html.escape(f.file)}</p>
      <table><tbody>{rows}{extra_rows}</tbody></table>
    </section>"""


def _build_charts_data(report: ReportModel) -> str:
    """Genere les donnees JSON pour Chart.js."""
    # Comptage par type
    type_counts: dict[str, int] = {}
    for f in report.findings:
        type_counts[f.type] = type_counts.get(f.type, 0) + 1

    # Timeline pour graphe temporel
    events = build_timeline(report)
    source_counts: dict[str, int] = {}
    for e in events:
        src = e.get("source", "other")
        source_counts[src] = source_counts.get(src, 0) + 1

    return json.dumps({
        "type_labels": list(type_counts.keys()),
        "type_values": list(type_counts.values()),
        "type_colors": [_TYPE_COLORS.get(t, "#4f8ef7") for t in type_counts],
        "source_labels": list(source_counts.keys()),
        "source_values": list(source_counts.values()),
        "timeline_count": len(events),
    })


def _build_executive_summary(report: ReportModel) -> str:
    """Genere le resume executif."""
    alerts = []
    for f in report.findings:
        if f.type == "stego" and f.extra.get("verdict") in ("STEGO PROBABLE", "SUSPECT"):
            alerts.append(f"Steganographie detectee dans {os.path.basename(f.file)}")
        if f.type == "pcap":
            creds = f.extra.get("credentials", [])
            if creds:
                alerts.append(f"{len(creds)} credential(s) trouvee(s) dans le trafic reseau")
            if f.extra.get("dns_exfiltration", {}).get("detected"):
                alerts.append("Exfiltration DNS detectee")
            if f.extra.get("c2_beacons", {}).get("detected"):
                alerts.append("Pattern C2/beacon detecte")
        if f.type == "evtx":
            evtx_alerts = f.extra.get("alerts", {})
            if evtx_alerts.get("audit_cleared"):
                alerts.append("Audit log Windows efface")
            if evtx_alerts.get("failed_logons", 0) > 50:
                alerts.append(f"{evtx_alerts['failed_logons']} tentatives de connexion echouees")
        if f.type == "linux_artifacts":
            auth = f.extra.get("auth_log", {})
            bf = auth.get("brute_force_ips", {})
            if bf:
                alerts.append(f"Brute-force SSH detecte depuis {len(bf)} IP(s)")
        if f.type == "yara":
            matches = f.extra.get("matches", [])
            if matches:
                rules = set(m["rule"] for m in matches)
                alerts.append(f"YARA : {len(rules)} regle(s) declenchee(s)")
        if f.type == "carving":
            polyglots = f.extra.get("polyglots", [])
            if polyglots:
                alerts.append(f"Polyglot detecte : {', '.join(polyglots)}")

    alert_html = ""
    if alerts:
        items = "".join(f"<li>{html.escape(a)}</li>" for a in alerts)
        alert_html = f'<div class="alert-box"><h4>Alertes</h4><ul>{items}</ul></div>'
    else:
        alert_html = '<div class="ok-box"><h4>Aucune alerte critique</h4></div>'

    return alert_html


def _build_ioc_table(report: ReportModel) -> str:
    """Genere la table IOC consolidee."""
    all_iocs: dict = {}
    for f in report.findings:
        if f.type == "ioc" and "iocs" in f.extra:
            for ioc_type, items in f.extra["iocs"].items():
                if items:
                    if ioc_type not in all_iocs:
                        all_iocs[ioc_type] = []
                    all_iocs[ioc_type].extend(items)

    if not all_iocs:
        return ""

    rows = ""
    for ioc_type, items in all_iocs.items():
        unique = list(set(items))[:50]
        for item in unique:
            rows += f"<tr><td><span class='ioc-type'>{ioc_type}</span></td><td class='mono'>{html.escape(str(item))}</td></tr>"

    return f"""
    <section class="card" style="border-left: 3px solid #d946ef">
      <h3 class="card-title"><span class="label" style="background:#d946ef">IOC</span> Table des indicateurs de compromission</h3>
      <table><thead><tr><th>Type</th><th>Valeur</th></tr></thead><tbody>{rows}</tbody></table>
    </section>"""


def build_interactive_html(report: ReportModel) -> str:
    """Construit le rapport HTML interactif complet."""
    cards = "\n".join(_finding_card(f) for f in report.findings)
    ts = html.escape(report.timestamp)
    charts_data = _build_charts_data(report)
    exec_summary = _build_executive_summary(report)
    ioc_table = _build_ioc_table(report)

    counts = {"pdf": 0, "image": 0, "network": 0, "disk": 0, "other": 0}
    for f in report.findings:
        if f.type == "pdf":
            counts["pdf"] += 1
        elif f.type in ("image", "stego"):
            counts["image"] += 1
        elif f.type in ("pcap",):
            counts["network"] += 1
        elif f.type in ("disk", "evtx", "registry", "linux_artifacts"):
            counts["disk"] += 1
        else:
            counts["other"] += 1

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Analyzer - Rapport Interactif</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
:root {{
  --bg: #0a0e17; --surface: #111827; --surface2: #1f2937;
  --border: #374151; --accent: #3b82f6; --text: #f1f5f9;
  --muted: #94a3b8; --red: #ef4444; --green: #22c55e;
  --yellow: #eab308; --radius: 12px;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; background: var(--bg);
        color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
header {{ text-align: center; padding: 3rem 0 2rem; }}
header h1 {{ font-size: 2.2rem; color: var(--accent); letter-spacing: .03em; margin-bottom: .5rem; }}
header p {{ color: var(--muted); font-size: .9rem; }}
.nav {{ display: flex; gap: .5rem; justify-content: center; margin: 2rem 0;
        flex-wrap: wrap; }}
.nav button {{ background: var(--surface); border: 1px solid var(--border); color: var(--text);
               padding: .5rem 1rem; border-radius: 8px; cursor: pointer; font-size: .85rem;
               transition: all .2s; }}
.nav button:hover, .nav button.active {{ background: var(--accent); border-color: var(--accent); }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
          gap: 1rem; margin: 2rem 0; }}
.stat {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: var(--radius); padding: 1.2rem; text-align: center;
         transition: transform .2s; }}
.stat:hover {{ transform: translateY(-2px); }}
.stat strong {{ display: block; font-size: 1.8rem; color: var(--accent); }}
.stat span {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin: 2rem 0; }}
.chart-box {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: var(--radius); padding: 1.5rem; }}
.chart-box h3 {{ font-size: .9rem; color: var(--muted); margin-bottom: 1rem; }}
.alert-box {{ background: rgba(239,68,68,0.1); border: 1px solid var(--red);
              border-radius: var(--radius); padding: 1.5rem; margin: 1.5rem 0; }}
.alert-box h4 {{ color: var(--red); margin-bottom: .5rem; }}
.alert-box ul {{ padding-left: 1.2rem; }}
.alert-box li {{ color: var(--text); margin-bottom: .3rem; }}
.ok-box {{ background: rgba(34,197,94,0.1); border: 1px solid var(--green);
           border-radius: var(--radius); padding: 1.5rem; margin: 1.5rem 0; }}
.ok-box h4 {{ color: var(--green); }}
.card {{ background: var(--surface); border: 1px solid var(--border);
         border-radius: var(--radius); padding: 1.5rem; margin-bottom: 1.2rem;
         transition: border-color .2s; }}
.card:hover {{ border-color: var(--accent); }}
.card-title {{ font-size: 1rem; display: flex; align-items: center; gap: .5rem;
               margin-bottom: .5rem; }}
.label {{ font-size: .65rem; color: #fff; padding: .15rem .5rem;
          border-radius: 999px; text-transform: uppercase; font-weight: 600; }}
.filepath {{ font-size: .7rem; color: var(--muted); margin-bottom: .8rem; word-break: break-all; }}
.ioc-type {{ font-size: .7rem; background: var(--surface2); color: var(--accent);
             padding: .1rem .4rem; border-radius: 4px; }}
table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
th {{ text-align: left; padding: .5rem .6rem; border-bottom: 2px solid var(--border);
     color: var(--muted); font-weight: 500; }}
td {{ padding: .4rem .6rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
td:first-child {{ color: var(--muted); width: 30%; font-weight: 500; }}
.mono {{ font-family: 'Fira Code', 'Cascadia Code', monospace; font-size: .8rem; }}
.link {{ color: var(--accent); word-break: break-all; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.section-title {{ font-size: 1.3rem; color: var(--text); margin: 2.5rem 0 1rem;
                  padding-bottom: .5rem; border-bottom: 2px solid var(--border); }}
.hidden {{ display: none; }}
@media (max-width: 768px) {{
  .charts {{ grid-template-columns: 1fr; }}
  .stats {{ grid-template-columns: repeat(3, 1fr); }}
}}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Forensic Analyzer</h1>
    <p>Rapport genere le {ts} -- {report.total} resultat(s)</p>
  </header>

  <div class="stats">
    <div class="stat"><strong>{report.total}</strong><span>Analyses</span></div>
    <div class="stat"><strong>{counts['pdf']}</strong><span>PDFs</span></div>
    <div class="stat"><strong>{counts['image']}</strong><span>Images</span></div>
    <div class="stat"><strong>{counts['network']}</strong><span>Reseau</span></div>
    <div class="stat"><strong>{counts['disk']}</strong><span>Systeme</span></div>
    <div class="stat"><strong>{counts['other']}</strong><span>Autres</span></div>
  </div>

  <h2 class="section-title">Resume Executif</h2>
  {exec_summary}

  <h2 class="section-title">Statistiques</h2>
  <div class="charts">
    <div class="chart-box">
      <h3>Distribution par type</h3>
      <canvas id="typeChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>Sources timeline</h3>
      <canvas id="sourceChart"></canvas>
    </div>
  </div>

  {ioc_table}

  <h2 class="section-title">Resultats Detailles</h2>
  <div class="nav" id="filters">
    <button class="active" onclick="filterCards('all')">Tous</button>
  </div>
  <div id="findings">
    {cards}
  </div>
</div>

<script>
const chartData = {charts_data};

// Type distribution chart
if (chartData.type_labels.length > 0) {{
  new Chart(document.getElementById('typeChart'), {{
    type: 'doughnut',
    data: {{
      labels: chartData.type_labels,
      datasets: [{{ data: chartData.type_values, backgroundColor: chartData.type_colors, borderWidth: 0 }}]
    }},
    options: {{
      responsive: true,
      plugins: {{ legend: {{ position: 'right', labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }}
    }}
  }});
}}

// Source chart
if (chartData.source_labels.length > 0) {{
  new Chart(document.getElementById('sourceChart'), {{
    type: 'bar',
    data: {{
      labels: chartData.source_labels,
      datasets: [{{ label: 'Evenements', data: chartData.source_values, backgroundColor: '#3b82f6', borderRadius: 6 }}]
    }},
    options: {{
      responsive: true,
      scales: {{
        x: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ display: false }} }},
        y: {{ ticks: {{ color: '#94a3b8' }}, grid: {{ color: '#1f2937' }} }}
      }},
      plugins: {{ legend: {{ display: false }} }}
    }}
  }});
}}

// Dynamic filter buttons
const types = new Set();
document.querySelectorAll('.card').forEach(c => {{
  const label = c.querySelector('.label');
  if (label) types.add(label.textContent.toLowerCase());
}});
const nav = document.getElementById('filters');
types.forEach(t => {{
  const btn = document.createElement('button');
  btn.textContent = t;
  btn.onclick = () => filterCards(t);
  nav.appendChild(btn);
}});

function filterCards(type) {{
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings .card').forEach(c => {{
    if (type === 'all') {{ c.classList.remove('hidden'); return; }}
    const label = c.querySelector('.label');
    if (label && label.textContent.toLowerCase() === type) c.classList.remove('hidden');
    else c.classList.add('hidden');
  }});
}}
</script>
</body>
</html>"""


class HTMLExporter:
    """Genere un rapport HTML interactif premium avec Chart.js."""

    def export(self, report: ReportModel, output_path: str) -> None:
        content = build_interactive_html(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("Rapport HTML exporté -> %s", output_path)
