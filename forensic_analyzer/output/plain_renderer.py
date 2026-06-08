"""Renderer ANSI de secours utilisant le systeme de design pur ANSI style TheFatRat."""
from __future__ import annotations

from forensic_analyzer.models.finding import FindingModel, ReportModel
from forensic_analyzer.output import ui
from forensic_analyzer.output.base_renderer import BaseRenderer


class PlainRenderer(BaseRenderer):
    """Renderer terminal utilisant le design terminal pur ANSI (TheFatRat style)."""

    def render_banner(self) -> None:
        ui.banner()

    def render_finding(self, finding: FindingModel) -> None:
        ui.render_finding(finding)

    def render_report(self, report: ReportModel) -> None:
        self.render_banner()
        for finding in report.findings:
            self.render_finding(finding)
        ui.render_summary(report)
