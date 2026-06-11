from __future__ import annotations
import os
from forensic_analyzer.core.base import BaseAnalyzer
from forensic_analyzer.models.finding import FindingModel
from forensic_analyzer.utils.logger import get_logger
from .deobfuscator import JSDeobfuscator, Ok, Err

log = get_logger("javascript")

class JavaScriptAnalyzer(BaseAnalyzer):
    name = "javascript"
    supported_extensions = ('.js', '.html')

    def analyze(self, path: str) -> FindingModel | None:
        if not self.can_handle(path): return None
        log.info(f"Analyse JavaScript sur {path}...")
        
        parser = JSDeobfuscator(path)
        match parser.deobfuscate():
            case Ok(value=code):
                return FindingModel(
                    type="javascript_analysis",
                    file=os.path.abspath(path),
                    metadata={"Code désobfusqué": "Oui" if code else "Non"},
                    extra={"code_preview": code[:200]}
                )
            case Err(error=msg):
                log.error(f"Erreur JS: {msg}")
                return None
