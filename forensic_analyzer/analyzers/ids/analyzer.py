import os
import json
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger

logger = get_logger("forensic.ids")

class IDSAnalyzer(BaseAnalyzer):
    """Analyse les journaux d'alertes IDS (Suricata eve.json, fast.log)."""
    name = "ids"
    supported_extensions = ('.json', '.log')

    def analyze(self, filepath: str) -> FindingModel | None:
        fname = os.path.basename(filepath).lower()
        if fname not in ("eve.json", "fast.log"):
            return None
            
        logger.info(f"Analyse des alertes IDS sur {fname}...")
        
        metadata = {}
        extra = {}
        alerts = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                if fname == "eve.json":
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            if event.get("event_type") == "alert":
                                alerts.append({
                                    "timestamp": event.get("timestamp"),
                                    "src_ip": event.get("src_ip"),
                                    "dest_ip": event.get("dest_ip"),
                                    "signature": event.get("alert", {}).get("signature", "Unknown"),
                                    "severity": event.get("alert", {}).get("severity", 3)
                                })
                        except:
                            continue
                elif fname == "fast.log":
                    for line in f:
                        if "[**]" in line:
                            parts = line.split("[**]")
                            if len(parts) >= 3:
                                signature = parts[1].split("] ")[-1].strip()
                                alerts.append({
                                    "signature": signature,
                                    "raw": line.strip()
                                })
                                
            if alerts:
                metadata["Total Alertes"] = str(len(alerts))
                # Top signatures
                sigs = {}
                for a in alerts:
                    s = a["signature"]
                    sigs[s] = sigs.get(s, 0) + 1
                    
                top_sigs = sorted(sigs.items(), key=lambda x: -x[1])[:3]
                metadata["Top Signatures"] = " | ".join([f"{k} ({v})" for k, v in top_sigs])
                
                # Critical alerts (severity 1 or 2) in eve.json
                crit_alerts = [a for a in alerts if a.get("severity", 3) <= 2]
                if crit_alerts:
                    metadata["Alertes Critiques"] = str(len(crit_alerts))
                    
                extra["raw_alerts"] = alerts[:100] # Limiter la taille
            else:
                return None
                
        except Exception as e:
            logger.error(f"Erreur de parsing IDS: {e}")
            return None
            
        return FindingModel(
            type="ids_alerts",
            file=filepath,
            metadata=metadata,
            extra=extra
        )
