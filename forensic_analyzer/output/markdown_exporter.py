"""Exportateur de rapports DFIR interactifs au format Markdown."""
from __future__ import annotations

import datetime
import os

from forensic_analyzer.models.finding import ReportModel


# SVG Icons for report status and markers
SVG_RED = '<svg width="12" height="12" viewBox="0 0 100 100" style="display:inline-block;vertical-align:middle;margin-right:4px;"><circle cx="50" cy="50" r="40" fill="#ff4d4d"/></svg>'
SVG_YELLOW = '<svg width="12" height="12" viewBox="0 0 100 100" style="display:inline-block;vertical-align:middle;margin-right:4px;"><circle cx="50" cy="50" r="40" fill="#ffcc00"/></svg>'
SVG_GREEN = '<svg width="12" height="12" viewBox="0 0 100 100" style="display:inline-block;vertical-align:middle;margin-right:4px;"><circle cx="50" cy="50" r="40" fill="#2eb82e"/></svg>'
SVG_SEARCH = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;margin-right:6px;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>'
SVG_WARNING = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ffcc00" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;margin-right:4px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'


def _get_threat_status(finding: ReportModel.FindingModel) -> tuple[str, str]:
    """Détermine le statut de menace (couleur + texte) pour une preuve."""
    # Par défaut, on lit le statut s'il est déjà défini
    status = finding.metadata.get("Menaces detectees", 
             finding.metadata.get("Statut de Securite", 
             finding.metadata.get("Mecanismes de persistance", "")))
             
    extra = finding.extra or {}
    
    # 1. Si YARA a matché
    if finding.type == "yara" and extra.get("matches"):
        return SVG_RED, f"CRITIQUE / YARA ({len(extra['matches'])} règle(s))"
        
    # 2. Si le module de deobfuscation JS a trouvé des anomalies suspectes
    if finding.type == "javascript":
        sec_status = finding.metadata.get("Statut de Securite", "")
        if "SUSPECT" in str(sec_status) or "OBFUSQUÉ" in str(sec_status):
            return SVG_RED, sec_status
            
    # 3. Si du malware/PE a de l'entropie critique ou des imports suspects
    if finding.type in ["pe_analysis", "malware_analysis"]:
        entropy_str = finding.metadata.get("Entropie globale", "")
        if "Suspicion packé: OUI" in entropy_str:
            return SVG_RED, "SUSPECT / Entropie élevée (Packé)"
        iocs_str = finding.metadata.get("IOCs Internes", "")
        if iocs_str and iocs_str != "0" and "0 IPs, 0 URLs" not in iocs_str:
            return SVG_RED, f"SUSPECT / {iocs_str}"
            
    # 4. Si PCAP contient des credentials ou des malwares
    if finding.type == "pcap":
        creds = extra.get("credentials", [])
        if creds:
            return SVG_RED, f"CRITIQUE / {len(creds)} Credentials interceptés"
        
        malwares = finding.metadata.get("Malwares extraits", "0")
        if malwares != "0" and malwares != "Aucun" and malwares != "0 analysés":
            return SVG_RED, f"CRITIQUE / Malware extrait ({malwares})"
            
        beacons = finding.metadata.get("C2 Beacons detectes", "0")
        if beacons != "0" and beacons != "Aucun":
            return SVG_RED, f"CRITIQUE / C2 Beacons détectés ({beacons})"
            
        dns_exfil = finding.metadata.get("DNS Exfiltration", "NON")
        if dns_exfil != "NON":
            return SVG_RED, "CRITIQUE / Exfiltration DNS suspectée"

    # 5. Si des IOCs ont été extraits
    if finding.type == "ioc":
        total_iocs = sum(int(v) for k, v in finding.metadata.items() if "IOC" in k and str(v).isdigit())
        if total_iocs > 0:
            return SVG_RED, f"CRITIQUE / {total_iocs} IOCs extraits"

    # 6. Si des URLs/IPs ont été extraites
    urls = extra.get("pdf_urls", extra.get("urls", []))
    if urls:
        return SVG_YELLOW, f"ALERTE / {len(urls)} URL(s) extraite(s)"

    # 7. Si des anomalies de structure existent (ex: PDF ou JS)
    if extra.get("anomalies"):
        return SVG_YELLOW, f"ALERTE / {len(extra['anomalies'])} anomalie(s) de structure"
        
    # 8. Si de la persistance est détectée
    if finding.type == "registry" and extra.get("persistence"):
        return SVG_RED, f"SUSPECT / {len(extra['persistence'])} mécanisme(s) de persistance"

    # 9. Tri textuel par défaut
    if status:
        status_str_val = str(status)
        if "Critique" in status_str_val or "DÉTECTÉES" in status_str_val or "SUSPECT" in status_str_val:
            return SVG_RED, status_str_val
        elif "Alerte" in status_str_val or "suspect" in status_str_val.lower() or "warning" in status_str_val.lower():
            return SVG_YELLOW, status_str_val
        elif status_str_val == "0":
            return SVG_GREEN, "Aucun mécanisme suspect"
        return SVG_GREEN, status_str_val

    return SVG_GREEN, "Aucune menace détectée"


class MarkdownExporter:
    """Générateur de rapport Markdown (DFIR Incident Report)."""

    def export(self, report: ReportModel, output_path: str) -> bool:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                # En-tête du rapport
                f.write("# RAPPORT D'INCIDENT DFIR AUTOMATIQUE\n")
                f.write(f"*Généré le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
                
                f.write("## 1. Résumé Exécutif\n")
                f.write("Ce rapport présente les résultats de l'analyse automatisée effectuée par la suite Forensic Analyzer. ")
                f.write(f"Au total, **{len(report.findings)}** preuve(s) ont été analysée(s).\n\n")
                
                # Tableau synthétique des preuves
                f.write("## 2. Tableau Synthétique des Preuves\n")
                f.write("| Fichier | Module | Menaces / Statut | MD5 |\n")
                f.write("| --- | --- | --- | --- |\n")
                
                for finding in report.findings:
                    fname = os.path.basename(finding.file)
                    ftype = finding.type.upper()
                    
                    svg_icon, status_desc = _get_threat_status(finding)
                    status_str = f"{svg_icon} {status_desc}"
                        
                    md5 = finding.metadata.get("MD5", "N/A")
                    f.write(f"| `{fname}` | {ftype} | {status_str} | `{md5}` |\n")
                f.write("\n")
                
                # Analyse détaillée de chaque preuve
                f.write("## 3. Analyse Détaillée des Preuves\n\n")
                for finding in report.findings:
                    fname = os.path.basename(finding.file)
                    f.write(f"### {SVG_SEARCH} Preuve : `{fname}` (Module: {finding.type.upper()})\n")
                    f.write(f"- **Chemin absolu :** `{finding.file}`\n")
                    
                    # Métadonnées basiques
                    f.write("#### Métadonnées\n")
                    for k, v in finding.metadata.items():
                        if k not in ["MD5", "SHA-256", "Fichier"]:
                            f.write(f"- **{k} :** {v}\n")
                            
                    # Hashes
                    md5 = finding.metadata.get("MD5")
                    sha256 = finding.metadata.get("SHA-256")
                    if md5 or sha256:
                        f.write("\n#### Empreintes Cryptographiques\n")
                        if md5:
                            f.write(f"- **MD5 :** `{md5}`\n")
                        if sha256:
                            f.write(f"- **SHA-256 :** `{sha256}`\n")
                            
                    # Extras (URLs extraites, VBA macros, persistence)
                    extra = finding.extra or {}
                    
                    # Si c'est du pcap
                    if finding.type == "pcap":
                        if "host_identities" in extra:
                            f.write("\n#### Hôtes & Identités Découvertes\n")
                            for ip, info in extra["host_identities"].items():
                                host = ", ".join(info["hostnames"]) if info["hostnames"] else "Inconnu"
                                user = ", ".join(info["users"]) if info["users"] else "Inconnu"
                                f.write(f"- `{ip}` -> Hôte: **{host}** | Utilisateur: **{user}**\n")
                                
                        if "pdf_urls" in extra or "urls" in extra:
                            urls = extra.get("pdf_urls", extra.get("urls", []))
                            if urls:
                                f.write("\n#### URLs Extraites\n")
                                for u in urls:
                                    f.write(f"- `{u}`\n")
                                    
                    # Si c'est du PDF ou JS
                    if finding.type in ["pdf", "javascript"]:
                        if "pdf_urls" in extra or "urls" in extra:
                            urls = extra.get("pdf_urls", extra.get("urls", []))
                            if urls:
                                f.write("\n#### URLs/IOCs Extraits\n")
                                for u in urls:
                                    f.write(f"- `{u}`\n")
                        if "anomalies" in extra and extra["anomalies"]:
                            f.write("\n#### Anomalies de Structure\n")
                            for a in extra["anomalies"]:
                                f.write(f"- {SVG_WARNING} {a}\n")

                    # Si c'est de la persistance registre
                    if finding.type == "registry":
                        if "persistence" in extra and extra["persistence"]:
                            f.write("\n#### Clés de Persistance Détectées\n")
                            f.write("| Type | Clé / Emplacement | Nom | Valeur |\n")
                            f.write("| --- | --- | --- | --- |\n")
                            for p in extra["persistence"]:
                                f.write(f"| {p['type']} | `{p['key']}` | `{p['name']}` | `{p['value']}` |\n")
                                
                    f.write("\n---\n\n")
                    
                # Recommandations SOC
                f.write("## 4. Recommandations et Mitigations SOC\n")
                f.write("1. **Isolation réseau** immédiate des machines identifiées comme infectées ou ayant communiqué avec des domaines suspects.\n")
                f.write("2. **Blocage des IOCs** (domaines, IPs, hashes) sur les pare-feux, proxies d'entreprise et solutions EDR.\n")
                f.write("3. **Changement des identifiants** pour tous les comptes d'utilisateurs suspectés d'être compromis.\n")
                f.write("4. **Analyse de la persistance** pour nettoyer les clés de registre malveillantes créées lors de l'infection.\n")
                
            return True
        except Exception:
            pass  # TODO: log.debug(exc)
            return False
