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
                extra_rows += f"<tr><td><span class='ioc-type'>{ioc_type}</span></td><td class='mono'>{html.escape(str(item))}</td></tr>"

    return f"""
    <section class="card">
      <h3 class="card-title">
        <span class="badge" style="background:{color}">{f.type.upper()}</span>
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
    <section class="card">
      <h3 class="card-title"><span class="badge" style="background:#d946ef">IOC</span> Table des indicateurs de compromission</h3>
      <table><thead><tr><th style="width: 30%">Type</th><th>Valeur</th></tr></thead><tbody>{rows}</tbody></table>
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
    --page: #f1f5f9;
    --ink: #0f172a;
    --muted: #475569;
    --surface: #ffffff;
    --line: #e2e8f0;
    --navy: #0f172a;
    --accent: #2563eb;
    --link: #0284c7;
    --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
}}
* {{
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}}
body {{
    font-family: var(--font-sans);
    background: var(--page);
    color: var(--ink);
    min-height: 100vh;
    padding: 0;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
}}
.container {{
    max-width: 1600px;
    margin: 0 auto;
    padding: 32px 24px;
}}
.header {{
    background: var(--navy);
    color: #ffffff;
    border-radius: 8px;
    padding: 24px 32px;
    margin-bottom: 32px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 16px;
    align-items: center;
    box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
}}
.header h1 {{
    color: #ffffff;
    font-size: 2.1em;
    font-weight: 800;
    letter-spacing: -0.5px;
}}
.header .meta {{
    color: #94a3b8;
    font-size: 1.05em;
    margin-top: 4px;
}}
.total-badge {{
    background: #ffffff;
    color: #0f172a;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 1.05em;
    font-weight: 800;
    white-space: nowrap;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.1);
}}
.stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 20px;
    margin-bottom: 32px;
}}
.stat {{
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 24px 20px;
    text-align: center;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
    transition: transform 0.2s;
}}
.stat:hover {{
    transform: translateY(-2px);
}}
.stat strong {{
    display: block;
    font-size: 2.2em;
    color: var(--navy);
    font-weight: 800;
}}
.stat span {{
    font-size: 0.85em;
    color: var(--muted);
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.section-title {{
    font-size: 1.25em;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--navy);
    margin: 40px 0 24px;
    padding-bottom: 8px;
    border-bottom: 3px solid var(--navy);
}}
.alert-box {{
    background: #fef2f2;
    border: 1px solid #fca5a5;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 32px;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
}}
.alert-box h4 {{
    color: #991b1b;
    font-weight: 800;
    margin-bottom: 8px;
    font-size: 1.1em;
}}
.alert-box ul {{
    padding-left: 20px;
}}
.alert-box li {{
    color: #7f1d1d;
    font-size: 0.95em;
    margin-bottom: 4px;
}}
.ok-box {{
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 32px;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
}}
.ok-box h4 {{
    color: #166534;
    font-weight: 800;
    font-size: 1.1em;
}}
.charts {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
    margin-bottom: 32px;
}}
.chart-box {{
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 24px;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
}}
.chart-box h3 {{
    font-size: 0.95em;
    color: var(--muted);
    margin-bottom: 16px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 800;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgb(0 0 0 / 0.05);
    transition: transform 0.15s, border-color 0.15s;
}}
.card:hover {{
    transform: translateY(-1px);
    border-color: var(--navy) !important;
}}
.card-title {{
    background: #ffffff;
    border-bottom: 1px solid var(--line);
    color: var(--ink);
    padding: 14px 18px;
    font-size: 1.15em;
    font-weight: 800;
    display: flex;
    align-items: center;
    gap: 10px;
}}
.filepath {{
    font-size: 0.8em;
    color: var(--muted);
    padding: 8px 18px 12px;
    font-family: var(--font-mono);
    word-break: break-all;
    border-bottom: 1px solid var(--line);
    background: #fafafa;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: #ffffff;
    table-layout: fixed;
}}
th {{
    background: #f8fafc;
    color: #475569;
    border-bottom: 2px solid var(--line);
    font-size: 0.9em;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    text-align: left;
    padding: 12px 18px;
    font-weight: 800;
}}
td {{
    color: var(--ink);
    vertical-align: middle;
    border-bottom: 1px solid #e2e8f0;
    padding: 12px 18px;
    word-break: break-all;
}}
td:first-child {{
    color: var(--muted);
    width: 30%;
    font-weight: 700;
}}
tr {{
    transition: background 0.15s;
}}
tr:hover {{
    background: #f8fafc !important;
}}
.badge {{
    display: inline-block;
    padding: 4px 10px;
    font-size: 0.8em;
    font-weight: 800;
    letter-spacing: 0.5px;
    border-radius: 4px;
    text-transform: uppercase;
    text-align: center;
    color: #ffffff;
}}
.nav {{
    display: flex;
    gap: 8px;
    margin: 16px 0 24px;
    flex-wrap: wrap;
}}
.nav button {{
    background: var(--surface);
    border: 1px solid var(--line);
    color: var(--ink);
    padding: 8px 16px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85em;
    font-weight: 700;
    transition: all 0.15s;
    box-shadow: 0 1px 2px rgb(0 0 0 / 0.05);
}}
.nav button:hover, .nav button.active {{
    background: var(--navy);
    border-color: var(--navy);
    color: #ffffff;
}}
.mono {{
    font-family: var(--font-mono);
    font-size: 0.85em;
}}
.ioc-type {{
    font-size: 0.8em;
    background: var(--page);
    color: #d946ef;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
}}
.link {{
    color: var(--link);
    font-weight: 700;
}}
.link:hover {{
    text-decoration: underline;
}}
.footer {{
    text-align: left;
    color: var(--muted);
    font-size: 0.95em;
    margin-top: 32px;
    padding: 16px 0;
    border-top: 1px solid var(--line);
}}
.hidden {{
    display: none;
}}
@media (max-width: 768px) {{
    .container {{
        padding: 12px;
    }}
    .header {{
        grid-template-columns: 1fr;
        padding: 16px;
    }}
    .header h1 {{
        font-size: 1.7em;
    }}
    .charts {{
        grid-template-columns: 1fr;
    }}
    .stats {{
        grid-template-columns: repeat(3, 1fr);
    }}
    table {{
        min-width: auto;
    }}
}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1>Forensic Analyzer</h1>
      <div class="meta">Rapport généré le {ts}</div>
    </div>
    <div class="total-badge">
      {report.total} résultat(s)
    </div>
  </div>

  <div class="stats">
    <div class="stat"><strong>{report.total}</strong><span>Analyses</span></div>
    <div class="stat"><strong>{counts['pdf']}</strong><span>PDFs</span></div>
    <div class="stat"><strong>{counts['image']}</strong><span>Images</span></div>
    <div class="stat"><strong>{counts['network']}</strong><span>Réseau</span></div>
    <div class="stat"><strong>{counts['disk']}</strong><span>Système</span></div>
    <div class="stat"><strong>{counts['other']}</strong><span>Autres</span></div>
  </div>

  <h2 class="section-title">Résumé Exécutif</h2>
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

  <h2 class="section-title">Résultats Détaillés</h2>
  <div class="nav" id="filters">
    <button class="active" onclick="filterCards('all')">Tous</button>
  </div>
  <div id="findings">
    {cards}
  </div>

  <div class="footer">
    © 2026 Félix TOVIGNAN &nbsp;|&nbsp; 
    <a href="https://github.com/VISCHENZISCH/ForensicTool.git" target="_blank" class="link">
      https://github.com/VISCHENZISCH/ForensicTool.git
    </a>
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
      plugins: {{ legend: {{ position: 'right', labels: {{ color: '#475569', font: {{ size: 11 }} }} }} }}
    }}
  }});
}}

// Source chart
if (chartData.source_labels.length > 0) {{
  new Chart(document.getElementById('sourceChart'), {{
    type: 'bar',
    data: {{
      labels: chartData.source_labels,
      datasets: [{{ label: 'Événements', data: chartData.source_values, backgroundColor: '#2563eb', borderRadius: 6 }}]
    }},
    options: {{
      responsive: true,
      scales: {{
        x: {{ ticks: {{ color: '#475569' }}, grid: {{ display: false }} }},
        y: {{ ticks: {{ color: '#475569' }}, grid: {{ color: '#e2e8f0' }} }}
      }},
      plugins: {{ legend: {{ display: false }} }}
    }}
  }});
}}

// Dynamic filter buttons
const types = new Set();
document.querySelectorAll('.card').forEach(c => {{
  const label = c.querySelector('.badge');
  if (label) types.add(label.textContent.toLowerCase());
}});
const nav = document.getElementById('filters');
types.forEach(t => {{
  const btn = document.createElement('button');
  btn.textContent = t;
  btn.onclick = (event) => filterCards(t, event);
  nav.appendChild(btn);
}});

function filterCards(type, event) {{
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  if (event) {{
    event.target.classList.add('active');
  }} else {{
    document.querySelector('.nav button').classList.add('active');
  }}
  document.querySelectorAll('#findings .card').forEach(c => {{
    if (type === 'all') {{ c.classList.remove('hidden'); return; }}
    const label = c.querySelector('.badge');
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
        filename = os.path.basename(output_path)
        os.makedirs("export", exist_ok=True)
        target_path = os.path.join("export", filename)
        content = build_interactive_html(report)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("Rapport HTML exporté -> %s", target_path)
