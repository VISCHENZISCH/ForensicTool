"""Exporteur HTML/PDF - Design System Figma (Monochrome + Color Blocks)."""
from __future__ import annotations

import html
import json
import os
from collections import defaultdict

from forensic_analyzer.analyzers.timeline_analyzer import build_timeline
from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.utils.logger import get_logger

log = get_logger("html_exporter")

_TYPE_LABELS = {
    "pdf": "PDF Document", "image": "Image / EXIF", "gps": "GPS Data",
    "strings": "Extracted Strings", "firefox_history": "Firefox History", "firefox_cookies": "Firefox Cookies",
    "stego": "Steganography", "carving": "File Carving", "pcap": "Network Traffic (PCAP)",
    "memory": "Memory Dump", "disk": "Disk Forensic", "evtx": "Windows EVTX",
    "registry": "Windows Registry", "linux_artifacts": "Linux Artifacts",
    "yara": "YARA Matches", "ioc": "IOCs", "timeline": "DFIR Timeline",
    "pe_analysis": "PE Malware Triage", "chromium_artifacts": "Chromium Artifacts",
    "prefetch": "WinExec Prefetch", "lnk_shortcut": "WinExec LNK",
}

def get_category(f_type: str) -> str:
    if f_type in ("disk", "evtx", "registry", "prefetch", "lnk_shortcut"):
        return "system"
    elif f_type in ("pcap", "firefox_history", "firefox_cookies", "chromium_artifacts"):
        return "network"
    elif f_type in ("pe_analysis", "yara", "ioc", "stego", "carving", "strings"):
        return "malware"
    elif f_type in ("pdf", "image", "gps"):
        return "files"
    elif f_type in ("memory", "linux_artifacts"):
        return "memory_linux"
    elif f_type == "timeline":
        return "timeline"
    return "other"

_CATEGORIES = {
    "system": {"title": "Système & Disque", "class": "block-lime"},
    "network": {"title": "Réseau & Web", "class": "block-coral"},
    "malware": {"title": "Malware & Avancé", "class": "block-navy"},
    "files": {"title": "Métadonnées Fichiers", "class": "block-lilac"},
    "memory_linux": {"title": "Mémoire & OS", "class": "block-mint"},
    "timeline": {"title": "Chronologie", "class": "block-cream"},
    "other": {"title": "Autres", "class": "block-pink"},
}


def _finding_card(f: FindingModel, is_inverse: bool = False) -> str:
    label = _TYPE_LABELS.get(f.type, f.type.upper())
    fname = html.escape(os.path.basename(f.file))
    
    card_cls = "card card-inverse" if is_inverse else "card"
    row_cls = "table-row table-row-inverse" if is_inverse else "table-row"
    text_cls = "text-inverse" if is_inverse else "text-ink"
    muted_cls = "text-inverse-muted" if is_inverse else "text-muted"

    rows = "".join(
        f"<div class='{row_cls}'><div class='eyebrow {muted_cls} cell-key'>{html.escape(str(k))}</div><div class='body-sm {text_cls} cell-val'>{html.escape(str(v)[:300])}</div></div>"
        for k, v in f.metadata.items()
    )

    extra_rows = ""
    ext = f.extra or {}
    
    def section_header(title):
        return f"<div class='{row_cls} section-header'><div class='eyebrow {text_cls}'>{title}</div></div>"
    
    def render_row(k, v, is_danger=False):
        danger_style = "color: var(--accent-magenta); font-weight: 540;" if is_danger else ""
        return f"<div class='{row_cls}'><div class='eyebrow {muted_cls} cell-key'>{html.escape(str(k))}</div><div class='body-sm {text_cls} cell-val mono' style='{danger_style}'>{html.escape(str(v))}</div></div>"

    if f.type == "strings" and "strings" in ext:
        extra_rows += section_header("Chaines (Top 100)")
        for i, s in enumerate(ext["strings"][:100], 1):
            extra_rows += render_row(f"#{i}", s)
    elif f.type == "firefox_history" and "entries" in ext:
        extra_rows += section_header("Historique")
        for e in ext["entries"][:50]:
            extra_rows += render_row(e.get('date') or '-', e.get('url','')[:80])
    elif f.type == "firefox_cookies" and "entries" in ext:
        extra_rows += section_header("Cookies")
        for e in ext["entries"][:50]:
            extra_rows += render_row(e.get('host') or '-', f"{e.get('name','')} = {e.get('value','')[:60]}")
    elif f.type == "chromium_artifacts":
        if ext.get("chromium_urls"):
            extra_rows += section_header("URLs (Top 10)")
            for u in ext["chromium_urls"][:10]:
                extra_rows += render_row(f"VISITES: {u.get('visites', 0)}", u.get('url','')[:80])
        if ext.get("chromium_downloads"):
            extra_rows += section_header("Téléchargements")
            for d in ext["chromium_downloads"][:10]:
                extra_rows += render_row(f"TAILLE: {d.get('taille_octets', 0)}", str(d.get('fichier', ''))[:80], is_danger=bool(d.get('danger_type')))
    elif f.type == "pe_analysis":
        if ext.get("sections_pe"):
            extra_rows += section_header("Sections PE")
            for sec in ext["sections_pe"]:
                ent = sec.get("Entropie", "")
                extra_rows += render_row(sec.get('Nom', ''), f"Entropie: {ent} | Taille: {sec.get('Taille Virtuelle', 0)}", is_danger="CRITIQUE" in ent)
        if ext.get("dll_imports"):
            extra_rows += section_header("Imports DLL")
            for dll in ext["dll_imports"][:15]:
                extra_rows += render_row("DLL", dll)
    elif f.type == "pcap" and ext.get("credentials"):
        extra_rows += section_header("Credentials Réseau")
        for c in ext["credentials"][:20]:
            extra_rows += render_row(c.get('protocol', '?'), c.get('data', c.get('user', str(c))), is_danger=True)
    elif f.type == "ioc" and ext.get("iocs"):
        for ioc_type, items in ext["iocs"].items():
            for item in items[:10]:
                extra_rows += render_row(ioc_type, item)
    elif f.type == "timeline" and ext.get("events"):
        extra_rows += section_header("Chronologie")
        for e in ext["events"][:50]:
            extra_rows += render_row(e.get('timestamp', '?') or "N/A", f"[{e.get('source', '')}] {e.get('detail', '')[:80]}")
    elif f.type in ("carving", "stego"):
        for extra_key in ("embedded_files", "polyglots", "lsb_data", "matches"):
            items = ext.get(extra_key)
            if items and isinstance(items, list):
                extra_rows += section_header(extra_key.replace('_', ' '))
                for item in items[:20]:
                    if isinstance(item, dict):
                        for ik, iv in item.items():
                            extra_rows += render_row(ik, str(iv)[:80])
                    else:
                        extra_rows += render_row("MATCH", str(item))
    elif f.type == "yara" and ext.get("matches"):
        extra_rows += section_header("Règles YARA")
        for rule in ext["matches"]:
            extra_rows += render_row("ALERT", rule, is_danger=True)

    tag_cls = "pill-inverse" if is_inverse else "pill-secondary"
    return f"""
    <div class="{card_cls}">
      <div class="card-header">
        <span class="caption {tag_cls}">{f.type.upper()}</span>
        <h3 class="card-title {text_cls}" style="margin-top: 16px; margin-bottom: 4px;">{label}</h3>
        <div class="caption {muted_cls} mono" style="word-break: break-all;">{html.escape(f.file)}</div>
      </div>
      <div class="table-wrapper" style="margin-top: 24px;">
        {rows}{extra_rows}
      </div>
    </div>"""


def _build_executive_summary(report: ReportModel) -> str:
    alerts = []
    for f in report.findings:
        ext = f.extra or {}
        if f.type == "stego" and ext.get("verdict") in ("STEGO PROBABLE", "SUSPECT"):
            alerts.append(f"Steganography detected in {os.path.basename(f.file)}")
        if f.type == "pcap" and ext.get("credentials"):
            alerts.append(f"{len(ext['credentials'])} credential(s) intercepted in network traffic")
        if f.type == "pe_analysis":
            for sec in ext.get("sections_pe", []):
                if "CRITIQUE" in sec.get("Entropie", ""):
                    alerts.append(f"Critical entropy in PE section {sec.get('Nom', '')} of {os.path.basename(f.file)}")
        if f.type == "evtx" and ext.get("alerts", {}).get("audit_cleared"):
            alerts.append("Windows Audit Log clearing detected")
        if f.type == "linux_artifacts" and ext.get("auth_log", {}).get("brute_force_ips"):
            alerts.append("SSH Brute-force activity detected")
        if f.type == "yara" and ext.get("matches"):
            alerts.append(f"YARA rules triggered on {os.path.basename(f.file)}")
        if f.type == "chromium_artifacts":
            for d in ext.get("chromium_downloads", []):
                if d.get("danger_type"):
                    alerts.append(f"Dangerous download detected via Chromium: {d.get('fichier')}")

    if not alerts:
        return ""

    items = "".join(f"<li class='body-sm' style='margin-bottom: 12px; display: flex; gap: 12px;'><span class='eyebrow' style='color: var(--accent-magenta);'>ALERT</span> {html.escape(a)}</li>" for a in alerts)
    return f"""
    <div class="color-block block-pink">
      <h2 class="display-lg" style="margin-bottom: 48px;">Critical Alerts</h2>
      <ul style="list-style: none; padding: 0; margin: 0;">{items}</ul>
    </div>
    """


def build_interactive_html(report: ReportModel) -> str:
    ts = html.escape(report.timestamp)
    exec_summary = _build_executive_summary(report)

    # Group findings by category
    grouped: dict[str, list[FindingModel]] = defaultdict(list)
    for f in report.findings:
        grouped[get_category(f.type)].append(f)

    sections_html = ""
    for cat_id, cat_info in _CATEGORIES.items():
        if cat_id not in grouped:
            continue
        
        is_inverse = cat_id in ("malware",)  # Navy block is inverse
        title_cls = "display-lg text-inverse" if is_inverse else "display-lg"
        
        cards_html = "".join(_finding_card(f, is_inverse) for f in grouped[cat_id])
        
        sections_html += f"""
        <div class="color-block {cat_info['class']}">
          <h2 class="{title_cls}" style="margin-bottom: 48px;">{cat_info['title']}</h2>
          <div class="grid-2up">
            {cards_html}
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Analyzer Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
:root {{
  --primary: #000000;
  --on-primary: #ffffff;
  --ink: #000000;
  --canvas: #ffffff;
  --inverse-canvas: #000000;
  --inverse-ink: #ffffff;
  --hairline: #e6e6e6;
  --hairline-soft: #f1f1f1;
  --surface-soft: #f7f7f5;
  --block-lime: #dceeb1;
  --block-lilac: #c5b0f4;
  --block-cream: #f4ecd6;
  --block-pink: #efd4d4;
  --block-mint: #c8e6cd;
  --block-coral: #f3c9b6;
  --block-navy: #1f1d3d;
  --accent-magenta: #ff3d8b;
  
  --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', monospace;
}}

* {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  background: var(--canvas);
  color: var(--ink);
  font-family: var(--font-sans);
  -webkit-font-smoothing: antialiased;
  line-height: 1.45;
}}

/* Typography */
.display-xl {{ font-family: var(--font-sans); font-size: 86px; font-weight: 300; line-height: 1.0; letter-spacing: -1.72px; }}
.display-lg {{ font-family: var(--font-sans); font-size: 64px; font-weight: 300; line-height: 1.1; letter-spacing: -0.96px; }}
.headline {{ font-family: var(--font-sans); font-size: 26px; font-weight: 500; line-height: 1.35; letter-spacing: -0.26px; }}
.subhead {{ font-family: var(--font-sans); font-size: 26px; font-weight: 300; line-height: 1.35; letter-spacing: -0.26px; }}
.card-title {{ font-family: var(--font-sans); font-size: 24px; font-weight: 700; line-height: 1.45; }}
.body-lg {{ font-family: var(--font-sans); font-size: 20px; font-weight: 300; line-height: 1.4; letter-spacing: -0.14px; }}
.body {{ font-family: var(--font-sans); font-size: 18px; font-weight: 300; line-height: 1.45; letter-spacing: -0.26px; }}
.body-sm {{ font-family: var(--font-sans); font-size: 16px; font-weight: 300; line-height: 1.45; letter-spacing: -0.14px; }}
.button {{ font-family: var(--font-sans); font-size: 20px; font-weight: 500; line-height: 1.4; letter-spacing: -0.1px; }}
.eyebrow {{ font-family: var(--font-mono); font-size: 18px; font-weight: 400; line-height: 1.3; letter-spacing: 0.54px; text-transform: uppercase; }}
.caption {{ font-family: var(--font-mono); font-size: 12px; font-weight: 400; line-height: 1.0; letter-spacing: 0.6px; text-transform: uppercase; }}
.mono {{ font-family: var(--font-mono); }}

.text-ink {{ color: var(--ink); }}
.text-inverse {{ color: var(--inverse-ink); }}
.text-muted {{ color: rgba(0,0,0,0.5); }}
.text-inverse-muted {{ color: rgba(255,255,255,0.5); }}

/* Layout */
.nav-bar {{ padding: 24px 48px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--hairline); }}
.page-container {{ max-width: 1400px; margin: 0 auto; padding: 48px; }}
.hero-section {{ padding: 96px 0; max-width: 900px; }}
.marquee-strip {{ background: var(--inverse-canvas); color: var(--inverse-ink); padding: 12px 48px; display: flex; gap: 48px; }}

/* Color Blocks */
.color-block {{ border-radius: 24px; padding: 48px; margin-bottom: 96px; }}
.block-lime {{ background: var(--block-lime); color: var(--ink); }}
.block-lilac {{ background: var(--block-lilac); color: var(--ink); }}
.block-cream {{ background: var(--block-cream); color: var(--ink); }}
.block-navy {{ background: var(--block-navy); color: var(--inverse-ink); }}
.block-coral {{ background: var(--block-coral); color: var(--ink); }}
.block-pink {{ background: var(--block-pink); color: var(--ink); }}
.block-mint {{ background: var(--block-mint); color: var(--ink); }}

/* Cards & Components */
.grid-2up {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
.card {{ background: var(--surface-soft); border-radius: 8px; padding: 24px; }}
.card-inverse {{ background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); }}

.pill-primary {{ background: var(--primary); color: var(--on-primary); border-radius: 50px; padding: 10px 20px; display: inline-flex; align-items: center; }}
.pill-secondary {{ background: var(--canvas); color: var(--ink); border-radius: 50px; padding: 8px 18px 10px; border: 1px solid var(--primary); display: inline-flex; align-items: center; }}
.pill-inverse {{ background: rgba(255,255,255,0.1); color: var(--inverse-ink); border-radius: 50px; padding: 8px 18px 10px; border: 1px solid rgba(255,255,255,0.3); display: inline-flex; align-items: center; }}

/* Tables */
.table-row {{ display: flex; padding: 12px 0; border-bottom: 1px solid var(--hairline); align-items: baseline; }}
.table-row-inverse {{ border-bottom: 1px solid rgba(255,255,255,0.1); }}
.table-row:last-child {{ border-bottom: none; }}
.cell-key {{ width: 35%; flex-shrink: 0; padding-right: 16px; word-break: break-word; }}
.cell-val {{ width: 65%; word-break: break-word; }}
.section-header {{ padding-top: 24px; padding-bottom: 8px; border-bottom: 2px solid var(--primary); }}
.table-row-inverse.section-header {{ border-bottom: 2px solid var(--inverse-ink); }}

/* Responsive */
@media (max-width: 960px) {{
  .grid-2up {{ grid-template-columns: 1fr; }}
  .display-xl {{ font-size: 56px; letter-spacing: -1px; }}
  .display-lg {{ font-size: 44px; letter-spacing: -0.5px; }}
  .color-block {{ padding: 32px; border-radius: 0; margin-left: -24px; margin-right: -24px; }}
  .page-container {{ padding: 24px; }}
}}
</style>
</head>
<body>

<div class="page-container">

  <div class="color-block" style="background: var(--inverse-canvas); color: var(--inverse-ink); margin-bottom: 96px;">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 48px;">
      <div>
        <h1 class="display-xl" style="margin-bottom: 24px;">Investigation<br>Report</h1>
        <p class="subhead" style="color: rgba(255,255,255,0.7); max-width: 500px;">A comprehensive digital forensics and incident response summary.</p>
      </div>
      
      <div class="card card-inverse" style="min-width: 350px; flex-shrink: 0;">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; gap: 24px;">
          <a href="https://github.com/VISCHENZISCH/ForensicTool" target="_blank" style="text-decoration: none; display: flex; align-items: center; gap: 8px;">
            <h3 class="button text-inverse" style="margin: 0; font-weight: 700; letter-spacing: -0.5px;">Forensic Analyzer</h3>
            <span style="color: rgba(255,255,255,0.5); font-size: 16px;">↗</span>
          </a>
          <span class="caption pill-inverse" style="white-space: nowrap;">Report {ts[:10]}</span>
        </div>
        <div>
          <div class="table-row table-row-inverse">
            <div class="eyebrow text-inverse-muted cell-key" style="width: 40%;">Generated</div>
            <div class="body-sm text-inverse cell-val mono" style="width: 60%;">{ts[:19].replace('T', ' ')}</div>
          </div>
          <div class="table-row table-row-inverse" style="border-bottom: none;">
            <div class="eyebrow text-inverse-muted cell-key" style="width: 40%;">Artifacts</div>
            <div class="body-lg text-inverse cell-val mono" style="width: 60%; font-weight: 700; color: var(--block-lime);">{report.total}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  {exec_summary}

  {sections_html}

  <div style="margin-top: 96px; padding-top: 48px; border-top: 1px solid var(--hairline); text-align: center;">
    <div class="caption text-muted">© 2026 Félix TOVIGNAN • VISCHENZISCH</div>
  </div>
</div>

</body>
</html>"""


class HTMLExporter:
    """Genere un rapport HTML/PDF premium utilisant le design system Figma."""

    def export(self, report: ReportModel, output_path: str) -> None:
        filename = os.path.basename(output_path)
        os.makedirs("export", exist_ok=True)
        target_path = os.path.join("export", filename)
        content = build_interactive_html(report)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("Rapport HTML/PDF (Figma Design) exporté -> %s", target_path)
